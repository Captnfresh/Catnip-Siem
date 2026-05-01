"""
Catnip SIEM — ML Inference Service
====================================
Flask REST API that exposes the trained GradientBoosting severity classifier
and the IsolationForest zero-day detector to any platform (Catnip SIEM,
OmniLog, or any HTTP client).

Endpoints
---------
GET  /health                       — liveness check
POST /predict                      — score a single event
POST /predict/batch                — score a list of events
POST /train/zero-day               — (re)train IF on provided events
GET  /model/info                   — model metadata

Request bodies
--------------
POST /predict
    {
        "platform": "graylog" | "omnilog" | "generic",   # default: generic
        "event": { ...raw event fields... }
    }

POST /predict/batch
    {
        "platform": "graylog" | "omnilog" | "generic",
        "events": [ {...}, {...}, ... ]
    }

POST /train/zero-day
    {
        "platform": "graylog" | "omnilog" | "generic",
        "events": [ {...}, {...}, ... ],        # training data
        "contamination": 0.05,                 # optional, default 0.05
        "threshold": -0.05                     # optional
    }

Response — /predict and /predict/batch items
    {
        "ml_severity":       "critical",
        "ml_confidence":     0.93,
        "ml_all_proba":      {"critical": 0.93, "high": 0.05, ...},
        "zero_day_score":    0.12,      # 0 = normal, 1 = most anomalous
        "is_zero_day":       false,
        "combined_risk":     0.47,      # blend of ml_confidence + zero_day_score
        "source_platform":   "graylog",
        "event_id":          "...",
        "timestamp":         "..."
    }

Environment variables
---------------------
ML_MODEL_PATH      path to catnip_severity_model.pkl  (optional)
ML_ZD_MODEL_PATH   path to zero_day_detector.pkl      (optional)
ML_SERVICE_PORT    port to bind on                    (default 5001)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Allow running from repo root without installing the package
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from flask import Flask, jsonify, request

from ml.adapters import get_adapter
from ml.model import CatnipModel
from ml.zero_day import ZeroDayDetector

# ---------------------------------------------------------------------------
# Initialise models
# ---------------------------------------------------------------------------

_model_path = os.environ.get("ML_MODEL_PATH")
_zd_path    = os.environ.get("ML_ZD_MODEL_PATH")

severity_model = CatnipModel(model_path=_model_path)

try:
    zd_detector = ZeroDayDetector.load(_zd_path)
    _zd_loaded  = True
except FileNotFoundError:
    zd_detector = ZeroDayDetector()
    _zd_loaded  = False

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__)


def _score_event(event: dict, platform: str) -> dict:
    """Normalise, run both models, blend scores, return result dict."""
    adapter   = get_adapter(platform)
    normed    = adapter.normalize(event)

    sev_result = severity_model.predict(normed)

    if _zd_loaded:
        zd_result = zd_detector.score(normed)
    else:
        zd_result = {
            "zero_day_score": 0.0,
            "zero_day_raw":   0.0,
            "is_zero_day":    False,
            "zero_day_threshold": ZeroDayDetector.DEFAULT_THRESHOLD,
        }

    # combined_risk: 60% severity confidence + 40% zero-day score
    combined = round(
        0.6 * sev_result["ml_confidence"] + 0.4 * zd_result["zero_day_score"], 4
    )

    return {
        **sev_result,
        **zd_result,
        "combined_risk":   combined,
        "source_platform": normed["_source_platform"],
        "event_id":        normed.get("_event_id", ""),
        "timestamp":       normed.get("_timestamp", ""),
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return jsonify({
        "status":           "ok",
        "severity_model":   "loaded",
        "zero_day_model":   "loaded" if _zd_loaded else "not_trained",
        "labels":           severity_model.labels,
        "n_features":       severity_model._n_features,
    })


@app.post("/predict")
def predict():
    body = request.get_json(force=True, silent=True) or {}
    event    = body.get("event")
    platform = body.get("platform", "generic")

    if not event or not isinstance(event, dict):
        return jsonify({"error": "'event' must be a non-empty object"}), 400

    try:
        result = _score_event(event, platform)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    return jsonify(result)


@app.post("/predict/batch")
def predict_batch():
    body = request.get_json(force=True, silent=True) or {}
    events   = body.get("events", [])
    platform = body.get("platform", "generic")

    if not isinstance(events, list) or not events:
        return jsonify({"error": "'events' must be a non-empty list"}), 400

    try:
        results = [_score_event(e, platform) for e in events]
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    return jsonify({"results": results, "count": len(results)})


@app.post("/train/zero-day")
def train_zero_day():
    global zd_detector, _zd_loaded
    body = request.get_json(force=True, silent=True) or {}
    events        = body.get("events", [])
    platform      = body.get("platform", "generic")
    contamination = float(body.get("contamination", 0.05))
    threshold     = float(body.get("threshold", ZeroDayDetector.DEFAULT_THRESHOLD))

    if not isinstance(events, list) or len(events) < 10:
        return jsonify({"error": "Provide at least 10 events to train zero-day model"}), 400

    adapter = get_adapter(platform)
    normed  = [adapter.normalize(e) for e in events]

    try:
        zd_detector = ZeroDayDetector(
            contamination=contamination,
            threshold=threshold,
        ).fit(normed)
        saved_path = zd_detector.save(_zd_path)
        _zd_loaded = True
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    return jsonify({
        "status":        "trained",
        "n_events":      len(normed),
        "contamination": contamination,
        "threshold":     threshold,
        "saved_to":      str(saved_path),
    })


@app.get("/model/info")
def model_info():
    return jsonify({
        "severity_model": {
            "type":         "GradientBoostingClassifier",
            "labels":       severity_model.labels,
            "n_features":   severity_model._n_features,
            "feature_names": severity_model.feature_names,
        },
        "zero_day_model": {
            "type":    "IsolationForest",
            "trained": _zd_loaded,
            "threshold": zd_detector._threshold if _zd_loaded else None,
        },
        "supported_platforms": ["graylog", "omnilog", "generic"],
    })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("ML_SERVICE_PORT", 5001))
    print(f"[ML Service] Severity model:   loaded ({severity_model._n_features} features)")
    print(f"[ML Service] Zero-day model:   {'loaded' if _zd_loaded else 'not trained — POST /train/zero-day first'}")
    print(f"[ML Service] Starting on port: {port}")
    app.run(host="0.0.0.0", port=port, debug=False)
