"""
ZeroDayDetector — unsupervised anomaly layer using IsolationForest.

The GradientBoostingClassifier (catnip_severity_model.pkl) is a supervised
classifier: it can only recognise attack patterns it was trained on.

ZeroDayDetector addresses what the GBC cannot:
  - Behaviour that deviates from the learned baseline but has no label
  - Novel attack techniques with no matching training example
  - Low-and-slow campaigns that stay below static thresholds

How it works:
  1. Train on a large window of events, ideally dominated by normal traffic.
  2. IsolationForest learns the density of the feature space.
  3. At inference time, events that fall in sparse/isolated regions
     (far from the normal cluster) get a negative anomaly_score.
  4. A configurable threshold converts the score to an is_anomaly bool.
  5. Scores are normalised to [0, 1] so they can be blended with the
     GBC confidence to produce a single combined_risk_score.

Usage:
    detector = ZeroDayDetector()
    detector.fit(list_of_normalised_feature_dicts)   # or load from disk
    result = detector.score(event_dict)
    # result["is_zero_day"] == True → flag this event
"""

from __future__ import annotations

import os
import pickle
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


_DEFAULT_ZD_PATH = Path(__file__).resolve().parents[1] / "models" / "zero_day_detector.pkl"

# Feature order must match _build_row()
_NUMERIC_FEATURES = [
    "risk_score",
    "confidence",
    "baseline_deviation",
    "entropy",
    "frequency_anomaly",
    "sequence_anomaly",
]


class ZeroDayDetector:
    """
    Wraps IsolationForest with a StandardScaler and exposes a simple
    score(event) → result dict interface that mirrors CatnipModel.predict().
    """

    # Anomaly score below this threshold → flagged as zero-day.
    # IsolationForest scores: 1 = normal, -1 = anomaly, 0 = boundary.
    DEFAULT_THRESHOLD: float = -0.05

    def __init__(
        self,
        n_estimators: int = 200,
        contamination: float = 0.05,
        threshold: float = DEFAULT_THRESHOLD,
        random_state: int = 42,
    ) -> None:
        self._threshold = threshold
        self._scaler = StandardScaler()
        self._if = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1,
        )
        self._fitted = False
        self._score_min: float = -1.0
        self._score_max: float = 1.0

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def fit(self, events: list[dict[str, Any]]) -> "ZeroDayDetector":
        """Train on a list of normalised event dicts (from any adapter)."""
        if not events:
            raise ValueError("Need at least one event to fit ZeroDayDetector.")

        X = np.vstack([self._build_row(e) for e in events])
        X_scaled = self._scaler.fit_transform(X)
        self._if.fit(X_scaled)

        raw_scores = self._if.score_samples(X_scaled)
        self._score_min = float(raw_scores.min())
        self._score_max = float(raw_scores.max())
        self._fitted = True
        return self

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def score(self, event: dict[str, Any]) -> dict[str, Any]:
        """Score a single normalised event dict."""
        self._assert_fitted()
        X = self._build_row(event).reshape(1, -1)
        X_scaled = self._scaler.transform(X)
        raw = float(self._if.score_samples(X_scaled)[0])
        normalised = self._normalise(raw)
        is_anomaly = raw < self._threshold

        return {
            "zero_day_score":      round(normalised, 4),  # 0 = normal, 1 = max anomaly
            "zero_day_raw":        round(raw, 4),
            "is_zero_day":         is_anomaly,
            "zero_day_threshold":  self._threshold,
        }

    def score_batch(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Score a list of normalised event dicts in one pass."""
        self._assert_fitted()
        if not events:
            return []
        X = np.vstack([self._build_row(e) for e in events])
        X_scaled = self._scaler.transform(X)
        raws = self._if.score_samples(X_scaled).tolist()
        results = []
        for raw in raws:
            normalised = self._normalise(raw)
            results.append({
                "zero_day_score":     round(normalised, 4),
                "zero_day_raw":       round(raw, 4),
                "is_zero_day":        raw < self._threshold,
                "zero_day_threshold": self._threshold,
            })
        return results

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: str | Path | None = None) -> Path:
        out = Path(path) if path else _DEFAULT_ZD_PATH
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "wb") as f:
            pickle.dump({
                "scaler":     self._scaler,
                "model":      self._if,
                "threshold":  self._threshold,
                "score_min":  self._score_min,
                "score_max":  self._score_max,
                "fitted":     self._fitted,
            }, f, protocol=pickle.HIGHEST_PROTOCOL)
        return out

    @classmethod
    def load(cls, path: str | Path | None = None) -> "ZeroDayDetector":
        src = Path(path) if path else _DEFAULT_ZD_PATH
        if not src.exists():
            raise FileNotFoundError(f"ZeroDayDetector model not found: {src}")
        with open(src, "rb") as f:
            data = pickle.load(f)
        detector = cls(threshold=data["threshold"])
        detector._scaler     = data["scaler"]
        detector._if         = data["model"]
        detector._score_min  = data["score_min"]
        detector._score_max  = data["score_max"]
        detector._fitted     = data["fitted"]
        return detector

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _assert_fitted(self) -> None:
        if not self._fitted:
            raise RuntimeError(
                "ZeroDayDetector is not fitted. Call fit() or load() first."
            )

    def _normalise(self, raw: float) -> float:
        """Map raw IF score to [0, 1] where 1 = most anomalous."""
        span = self._score_max - self._score_min
        if span == 0:
            return 0.0
        clipped = max(self._score_min, min(self._score_max, raw))
        return 1.0 - (clipped - self._score_min) / span

    @staticmethod
    def _build_row(event: dict[str, Any]) -> np.ndarray:
        return np.array([
            float(event.get("risk_score",          50.0)),
            float(event.get("confidence",           0.5)),
            float(event.get("baseline_deviation",   0.0)),
            float(event.get("entropy",              0.0)),
            1.0 if event.get("frequency_anomaly") else 0.0,
            1.0 if event.get("sequence_anomaly")  else 0.0,
        ], dtype=np.float32)
