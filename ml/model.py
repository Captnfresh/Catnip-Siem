"""
CatnipModel — portable wrapper around catnip_severity_model.pkl.

Accepts a normalised feature dict (see adapters.py) and returns:
    {
        "ml_severity":    "critical" | "high" | "medium" | "low" | "info",
        "ml_confidence":  0.0 – 1.0,
        "ml_label_index": int,
        "ml_all_proba":   {label: probability, ...},
    }

Works identically whether called from Catnip SIEM or OmniLog.
"""

from __future__ import annotations

import os
import pickle
from pathlib import Path
from typing import Any

import numpy as np


_DEFAULT_MODEL_PATH = Path(__file__).resolve().parents[1] / "models" / "catnip_severity_model.pkl"


class CatnipModel:
    def __init__(self, model_path: str | Path | None = None) -> None:
        path = Path(model_path) if model_path else _DEFAULT_MODEL_PATH
        if not path.exists():
            raise FileNotFoundError(f"Model not found: {path}")

        with open(path, "rb") as f:
            artefact = pickle.load(f)

        self._clf            = artefact["model"]
        self._label_map      = artefact["label_map"]       # str → int
        self._label_map_inv  = artefact["label_map_inv"]   # int → str
        self._event_type_vocab = artefact["event_type_vocab"]
        self._action_vocab     = artefact["action_vocab"]
        self._feature_names    = artefact["feature_names"]
        self._n_features       = artefact["n_features"]

        self.labels: list[str] = [self._label_map_inv[i] for i in range(len(self._label_map))]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def predict(self, event: dict[str, Any]) -> dict[str, Any]:
        """Score a single normalised event dict."""
        X = self._build_row(event).reshape(1, -1)
        idx   = int(self._clf.predict(X)[0])
        proba = self._clf.predict_proba(X)[0]
        return {
            "ml_severity":    self._label_map_inv[idx],
            "ml_confidence":  round(float(proba[idx]), 4),
            "ml_label_index": idx,
            "ml_all_proba":   {
                self._label_map_inv[i]: round(float(p), 4)
                for i, p in enumerate(proba)
            },
        }

    def predict_batch(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Score a list of normalised event dicts in one pass."""
        if not events:
            return []
        X = np.vstack([self._build_row(e) for e in events])
        idxs  = self._clf.predict(X).tolist()
        probas = self._clf.predict_proba(X).tolist()
        results = []
        for idx, proba in zip(idxs, probas):
            results.append({
                "ml_severity":    self._label_map_inv[int(idx)],
                "ml_confidence":  round(float(proba[int(idx)]), 4),
                "ml_label_index": int(idx),
                "ml_all_proba":   {
                    self._label_map_inv[i]: round(float(p), 4)
                    for i, p in enumerate(proba)
                },
            })
        return results

    @property
    def feature_names(self) -> list[str]:
        return list(self._feature_names)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_row(self, event: dict[str, Any]) -> np.ndarray:
        row: list[float] = [
            float(event.get("risk_score",          50.0)),
            float(event.get("confidence",           0.5)),
            float(event.get("baseline_deviation",   0.0)),
            float(event.get("entropy",              0.0)),
            1.0 if event.get("frequency_anomaly") else 0.0,
            1.0 if event.get("sequence_anomaly")  else 0.0,
        ]
        et = str(event.get("event_type", "unknown"))
        for vocab_et in self._event_type_vocab:
            row.append(1.0 if et == vocab_et else 0.0)

        ac = str(event.get("action", "unknown"))
        for vocab_ac in self._action_vocab:
            row.append(1.0 if ac == vocab_ac else 0.0)

        return np.array(row, dtype=np.float32)
