"""
Source adapters — each normalises platform-specific log fields into the
common feature schema that CatnipModel and ZeroDayDetector expect:

    {
        "risk_score":          float   (0–100)
        "confidence":          float   (0–1)
        "baseline_deviation":  float   (0–∞)
        "entropy":             float   (0–∞)
        "frequency_anomaly":   bool
        "sequence_anomaly":    bool
        "event_type":          str
        "action":              str
        # passthrough metadata (not used in features, forwarded in result)
        "_source_platform":    str
        "_event_id":           str
        "_timestamp":          str
        "_raw":                dict    (original event)
    }

Add a new adapter for any platform by subclassing BaseAdapter and
implementing `normalize()`.
"""

from __future__ import annotations

import math
from abc import ABC, abstractmethod
from typing import Any


class BaseAdapter(ABC):
    platform: str = "unknown"

    @abstractmethod
    def normalize(self, event: dict[str, Any]) -> dict[str, Any]:
        ...

    # shared helper — compute rough entropy of a string
    @staticmethod
    def _string_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        n = len(s)
        return -sum((f / n) * math.log2(f / n) for f in freq.values())


# ---------------------------------------------------------------------------
# Graylog / Catnip SIEM
# ---------------------------------------------------------------------------

class GraylogAdapter(BaseAdapter):
    """
    Handles both GELF messages from log_generator.py and messages retrieved
    via the Graylog search API (/api/search/messages).

    GELF keys from log_generator.py:
        event_type, action, server_id, source_ip, severity,
        risk_score, confidence, baseline_deviation, entropy,
        frequency_anomaly, sequence_anomaly
    """

    platform = "graylog"

    def normalize(self, event: dict[str, Any]) -> dict[str, Any]:
        meta = event.get("advanced_metadata", {})
        ba   = event.get("behavioral_analytics", {})

        risk_score = float(
            event.get("risk_score")
            or meta.get("risk_score")
            or 50.0
        )
        confidence = float(
            event.get("confidence")
            or meta.get("confidence")
            or 0.5
        )
        baseline_deviation = float(
            event.get("baseline_deviation")
            or ba.get("baseline_deviation")
            or 0.0
        )
        entropy = float(
            event.get("entropy")
            or ba.get("entropy")
            or self._string_entropy(str(event.get("raw_log", "")))
        )

        return {
            "risk_score":         risk_score,
            "confidence":         confidence,
            "baseline_deviation": baseline_deviation,
            "entropy":            entropy,
            "frequency_anomaly":  bool(
                event.get("frequency_anomaly") or ba.get("frequency_anomaly")
            ),
            "sequence_anomaly":   bool(
                event.get("sequence_anomaly") or ba.get("sequence_anomaly")
            ),
            "event_type": str(event.get("event_type", "unknown")),
            "action":     str(event.get("action",     "unknown")),
            # passthrough
            "_source_platform": self.platform,
            "_event_id":   str(event.get("event_id", event.get("_id", ""))),
            "_timestamp":  str(event.get("timestamp", "")),
            "_raw": event,
        }


# ---------------------------------------------------------------------------
# OmniLog
# ---------------------------------------------------------------------------

class OmniLogAdapter(BaseAdapter):
    """
    Adapter for OmniLog's event schema.

    OmniLog field mapping (update once OmniLog schema is confirmed):
        omnilog.riskScore         → risk_score
        omnilog.confidenceScore   → confidence
        omnilog.baselineDev       → baseline_deviation
        omnilog.shannonEntropy    → entropy
        omnilog.freqAnomaly       → frequency_anomaly
        omnilog.seqAnomaly        → sequence_anomaly
        omnilog.eventCategory     → event_type
        omnilog.eventAction       → action

    Falls back to Graylog field names if OmniLog fields are absent, so
    the adapter works with raw CEF/LEEF events forwarded from OmniLog
    before they are enriched.
    """

    platform = "omnilog"

    # Map OmniLog camelCase keys → normalised schema keys
    _FIELD_MAP = {
        "riskScore":       "risk_score",
        "confidenceScore": "confidence",
        "baselineDev":     "baseline_deviation",
        "shannonEntropy":  "entropy",
        "freqAnomaly":     "frequency_anomaly",
        "seqAnomaly":      "sequence_anomaly",
        "eventCategory":   "event_type",
        "eventAction":     "action",
    }

    def normalize(self, event: dict[str, Any]) -> dict[str, Any]:
        omni = event.get("omnilog", event)  # nested or flat

        def _get(omnilog_key: str, fallback_key: str, default: Any) -> Any:
            v = omni.get(omnilog_key)
            if v is None:
                v = event.get(fallback_key, default)
            return v

        risk_score         = float(_get("riskScore",       "risk_score",         50.0))
        confidence         = float(_get("confidenceScore", "confidence",          0.5))
        baseline_deviation = float(_get("baselineDev",     "baseline_deviation",  0.0))
        entropy            = float(_get("shannonEntropy",  "entropy",             0.0))

        if entropy == 0.0:
            raw = str(event.get("raw_log", event.get("message", "")))
            entropy = self._string_entropy(raw)

        freq_anomaly = bool(_get("freqAnomaly", "frequency_anomaly", False))
        seq_anomaly  = bool(_get("seqAnomaly",  "sequence_anomaly",  False))

        event_type = str(_get("eventCategory", "event_type", "unknown"))
        action     = str(_get("eventAction",   "action",     "unknown"))

        return {
            "risk_score":         risk_score,
            "confidence":         confidence,
            "baseline_deviation": baseline_deviation,
            "entropy":            entropy,
            "frequency_anomaly":  freq_anomaly,
            "sequence_anomaly":   seq_anomaly,
            "event_type":         event_type,
            "action":             action,
            # passthrough
            "_source_platform": self.platform,
            "_event_id":  str(omni.get("eventId", event.get("event_id", ""))),
            "_timestamp": str(omni.get("eventTime", event.get("timestamp", ""))),
            "_raw": event,
        }


# ---------------------------------------------------------------------------
# Generic / auto-detect
# ---------------------------------------------------------------------------

class GenericAdapter(BaseAdapter):
    """
    Best-effort adapter: tries OmniLog fields first, then Graylog fields,
    then falls back to defaults.  Use when source platform is unknown.
    """

    platform = "generic"

    def __init__(self) -> None:
        self._graylog  = GraylogAdapter()
        self._omnilog  = OmniLogAdapter()

    def normalize(self, event: dict[str, Any]) -> dict[str, Any]:
        if "omnilog" in event or "eventCategory" in event:
            result = self._omnilog.normalize(event)
        else:
            result = self._graylog.normalize(event)
        result["_source_platform"] = self.platform
        return result


# ---------------------------------------------------------------------------
# Registry helper
# ---------------------------------------------------------------------------

_ADAPTERS: dict[str, BaseAdapter] = {
    "graylog": GraylogAdapter(),
    "omnilog": OmniLogAdapter(),
    "generic": GenericAdapter(),
}

def get_adapter(platform: str) -> BaseAdapter:
    """Return the adapter for *platform*, falling back to GenericAdapter."""
    return _ADAPTERS.get(platform.lower(), _ADAPTERS["generic"])
