"""
OmniLog API — Flask backend for the OmniLog conversational UI.
Runs on port 5002. Vite proxies /omnilog-api → http://localhost:5002.

Responsibilities:
  - Accept natural-language queries from the React frontend
  - Use Claude (claude-opus-4-7) with tool use to investigate Graylog logs
  - Fetch matching log messages via the Graylog REST API (tool)
  - Score each event through the ML service (port 5001) (tool)
  - Map detected threat classes to relevant CVEs (tool)
  - Return a ThreatAnalysis JSON response
  - Maintain multi-turn conversation history per session_id
  - Report live connection status for the sidebar gauge

Environment variables (mirrors .env):
  GRAYLOG_HOST          default: localhost
  GRAYLOG_PORT          default: 9000
  GRAYLOG_USER          default: admin
  GRAYLOG_PASSWORD      default: (read from .env)
  ML_SERVICE_URL        default: http://localhost:5001
  OMNILOG_PORT          default: 5002
  ANTHROPIC_API_KEY     required for Claude integration
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from pathlib import Path
from typing import Any

import requests
from flask import Flask, jsonify, request
from flask_cors import CORS

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

_ENV_FILE = Path(__file__).resolve().parents[1] / ".env"

def _read_env_file() -> dict[str, str]:
    env: dict[str, str] = {}
    if not _ENV_FILE.exists():
        return env
    for line in _ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip().rstrip("\r")
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            env[k.strip()] = v.strip().strip('"').strip("'")
    return env

_file_env = _read_env_file()

def _cfg(key: str, default: str = "") -> str:
    return os.environ.get(key) or _file_env.get(key) or default

GRAYLOG_HOST  = _cfg("GRAYLOG_HOST", "localhost")
GRAYLOG_PORT  = _cfg("GRAYLOG_PORT", "9000")
GRAYLOG_USER  = _cfg("GRAYLOG_USER", "admin")
GRAYLOG_PASS  = _cfg("GRAYLOG_ADMIN_PASSWORD", _cfg("GRAYLOG_PASSWORD", "admin"))
ML_URL        = _cfg("ML_SERVICE_URL", "http://localhost:5001")
OMNILOG_PORT  = int(_cfg("OMNILOG_PORT", "5002"))
ANTHROPIC_KEY = _cfg("ANTHROPIC_API_KEY", "")

# On Windows/WSL2 with Docker Desktop, IPv4 localhost can return 405 while IPv6
# works correctly. Bracket IPv6 addresses for use in URLs.
_gl_host_url = f"[{GRAYLOG_HOST}]" if ":" in GRAYLOG_HOST else GRAYLOG_HOST
if GRAYLOG_HOST in ("localhost", "127.0.0.1"):
    _gl_host_url = "[::1]"
GRAYLOG_BASE  = f"http://{_gl_host_url}:{GRAYLOG_PORT}/api"
_GL_HEADERS   = {"Accept": "application/json", "X-Requested-By": "omnilog"}
_GL_AUTH      = (GRAYLOG_USER, GRAYLOG_PASS)
_TIMEOUT      = 8

# ---------------------------------------------------------------------------
# Claude client (lazy — only imported if ANTHROPIC_API_KEY is set)
# ---------------------------------------------------------------------------

_claude = None

def _get_claude():
    global _claude
    if _claude is None and ANTHROPIC_KEY:
        import anthropic
        _claude = anthropic.Anthropic(api_key=ANTHROPIC_KEY)
    return _claude

# ---------------------------------------------------------------------------
# CVE database (attack-type → CVE list)
# ---------------------------------------------------------------------------

_CVE_MAP: dict[str, list[dict]] = {
    "brute_force": [
        {"id": "CVE-2023-23397", "description": "NTLM hash theft via Outlook calendar invites enabling credential relay", "cvss": 9.8},
        {"id": "CVE-2022-30190",  "description": "MSDT remote code execution (Follina) — commonly chained after credential theft", "cvss": 7.8},
    ],
    "credential_stuffing": [
        {"id": "CVE-2021-42013",  "description": "Apache path traversal + RCE enabling credential extraction", "cvss": 9.8},
        {"id": "CVE-2023-44487",  "description": "HTTP/2 Rapid Reset DDoS (used to exhaust auth endpoints)", "cvss": 7.5},
    ],
    "ddos": [
        {"id": "CVE-2023-44487",  "description": "HTTP/2 Rapid Reset — record-breaking DDoS amplification technique", "cvss": 7.5},
        {"id": "CVE-2022-26134",  "description": "Confluence OGNL injection used in amplification and botnet recruitment", "cvss": 9.8},
    ],
    "sql_injection": [
        {"id": "CVE-2023-3024",   "description": "SQL injection via unsanitised input parameters", "cvss": 9.1},
        {"id": "CVE-2021-44228",  "description": "Log4Shell JNDI injection — often delivered via SQL error messages", "cvss": 10.0},
    ],
    "suspicious_login": [
        {"id": "CVE-2023-23397",  "description": "NTLM relay attack via malicious calendar invite", "cvss": 9.8},
        {"id": "CVE-2022-21999",  "description": "Windows Print Spooler privilege escalation (PrintNightmare variant)", "cvss": 7.8},
    ],
    "network_anomaly": [
        {"id": "CVE-2022-26923",  "description": "AD CS domain privilege escalation via certificate template abuse", "cvss": 8.8},
        {"id": "CVE-2021-34527",  "description": "PrintNightmare — lateral movement via print spooler RCE", "cvss": 8.8},
    ],
    "zero_day": [
        {"id": "CVE-UNKNOWN",     "description": "Zero-day anomaly — no CVE assigned. Behaviour deviates from learned baseline.", "cvss": None},
    ],
}

# ---------------------------------------------------------------------------
# Claude tool definitions
# ---------------------------------------------------------------------------

_TOOLS = [
    {
        "name": "search_graylog",
        "description": (
            "Search Graylog for log events matching a query. "
            "Returns up to 50 events from the requested time window. "
            "Use Graylog query syntax: field:value, AND/OR, wildcards (*). "
            "Examples: 'action:failed AND event_type:auth', 'severity:critical', '*'"
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Graylog query string"
                },
                "limit": {
                    "type": "integer",
                    "description": "Max events to return (1–50)",
                    "default": 20
                },
                "range_seconds": {
                    "type": "integer",
                    "description": "Look-back window in seconds (default 3600 = 1 hour)",
                    "default": 3600
                }
            },
            "required": ["query"]
        }
    },
    {
        "name": "score_events_ml",
        "description": (
            "Run a list of log events through the ML anomaly model. "
            "Returns severity, confidence, zero-day score, and combined risk for each event. "
            "Call this after search_graylog to score the retrieved events."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "events": {
                    "type": "array",
                    "description": "Log event objects (the 'message' dicts from Graylog search results)",
                    "items": {"type": "object"}
                }
            },
            "required": ["events"]
        }
    },
    {
        "name": "lookup_cves",
        "description": "Look up CVEs relevant to a detected attack type.",
        "input_schema": {
            "type": "object",
            "properties": {
                "threat_type": {
                    "type": "string",
                    "description": "Detected attack type",
                    "enum": [
                        "brute_force", "credential_stuffing", "ddos",
                        "sql_injection", "suspicious_login", "network_anomaly", "zero_day"
                    ]
                }
            },
            "required": ["threat_type"]
        }
    },
    {
        "name": "produce_analysis",
        "description": (
            "Deliver the final structured threat analysis to the UI. "
            "Call this ONCE as your very last action after you have gathered all evidence. "
            "Do not call any other tool after this."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {
                    "type": "string",
                    "description": "Detailed analyst summary of findings (3–5 sentences)"
                },
                "threatLevel": {
                    "type": "string",
                    "enum": ["Low", "Medium", "High", "Critical"],
                    "description": "Overall threat level based on evidence"
                },
                "affectedSystems": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Hostnames / source IDs seen in the logs"
                },
                "recommendedActions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Concrete, prioritised remediation steps"
                },
                "conversationalReply": {
                    "type": "string",
                    "description": "Short chat message to display above the analysis card (1–2 sentences, analyst tone)"
                }
            },
            "required": ["summary", "threatLevel", "affectedSystems", "recommendedActions", "conversationalReply"]
        }
    }
]

# ---------------------------------------------------------------------------
# System prompt (cached — stable prefix)
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are OmniLog, an expert AI security analyst embedded in the Catnip SIEM platform \
(Graylog 6.1 + OpenSearch 2.15). You have live access to Graylog log data, \
a machine-learning anomaly detector, and a CVE knowledge base.

## Investigation protocol

1. Call search_graylog with a precise Graylog query derived from the user's intent.
2. If events are returned, call score_events_ml on the top 20 events to get ML threat scores.
3. If the ML scores reveal a clear threat class (brute_force, ddos, sql_injection, etc.) or a \
zero-day anomaly (is_zero_day = true), call lookup_cves for that threat type.
4. Synthesise all evidence and call produce_analysis exactly once as your final action.

## Rules

- Always investigate with real tool calls — never answer from assumptions alone.
- If Graylog returns 0 events, report that honestly in produce_analysis and set threatLevel to Low.
- Keep conversationalReply short and direct (analyst briefing style).
- recommendedActions must be concrete and prioritised (most urgent first).
- Never fabricate log data or CVE numbers.
"""

# ---------------------------------------------------------------------------
# Session store (multi-turn conversation history)
# ---------------------------------------------------------------------------

_sessions: dict[str, list[dict]] = {}
_sessions_lock = threading.Lock()
_MAX_HISTORY = 40  # messages to retain per session (prevents unbounded growth)

# ---------------------------------------------------------------------------
# Graylog helpers
# ---------------------------------------------------------------------------

def _graylog_search(q: str, limit: int = 20, range_s: int = 3600) -> list[dict]:
    try:
        r = requests.get(
            f"{GRAYLOG_BASE}/search/universal/relative",
            params={
                "query": q,
                "range": range_s,
                "limit": limit,
                "fields": (
                    "timestamp,source,level,message,event_type,action,"
                    "source_ip,severity,risk_score,confidence,"
                    "baseline_deviation,entropy,frequency_anomaly,sequence_anomaly"
                ),
            },
            headers=_GL_HEADERS,
            auth=_GL_AUTH,
            timeout=_TIMEOUT,
        )
        r.raise_for_status()
        return r.json().get("messages", [])
    except Exception:
        return []

def _graylog_alive() -> bool:
    try:
        r = requests.get(
            f"{GRAYLOG_BASE}/system",
            auth=_GL_AUTH,
            headers=_GL_HEADERS,
            timeout=3,
        )
        return r.status_code == 200 and r.json().get("lb_status") == "alive"
    except Exception:
        return False

# ---------------------------------------------------------------------------
# ML service helpers
# ---------------------------------------------------------------------------

def _ml_predict(event: dict) -> dict | None:
    try:
        r = requests.post(
            f"{ML_URL}/predict",
            json={"platform": "graylog", "event": event},
            timeout=5,
        )
        r.raise_for_status()
        return r.json()
    except Exception:
        return None

def _ml_alive() -> bool:
    try:
        r = requests.get(f"{ML_URL}/health", timeout=2)
        return r.status_code == 200
    except Exception:
        return False

# ---------------------------------------------------------------------------
# Log → LogEntry (frontend schema)
# ---------------------------------------------------------------------------

def _to_log_entry(msg: dict) -> dict:
    inner = msg.get("message", msg)
    level_raw = str(inner.get("level", inner.get("severity", "INFO"))).upper()
    level_map = {"CRITICAL": "CRITICAL", "ERROR": "ERROR", "WARNING": "WARNING", "WARN": "WARNING"}
    level = level_map.get(level_raw, "INFO")
    return {
        "timestamp": inner.get("timestamp", ""),
        "source":    inner.get("source", inner.get("gl2_source_input", "unknown")),
        "level":     level,
        "message":   inner.get("message", inner.get("short_message", "")),
    }

# ---------------------------------------------------------------------------
# Aggregation helpers (used when Claude is unavailable)
# ---------------------------------------------------------------------------

def _dominant_ml(predictions: list[dict]) -> dict | None:
    if not predictions:
        return None
    predictions.sort(key=lambda p: p.get("combined_risk", 0), reverse=True)
    top = predictions[0]
    any_zero_day = any(p.get("is_zero_day") for p in predictions)
    return {
        "severity":     top.get("ml_severity", "unknown"),
        "confidence":   top.get("ml_confidence", 0.0),
        "zeroDayScore": top.get("zero_day_score", 0.0),
        "isZeroDay":    any_zero_day,
        "combinedRisk": top.get("combined_risk", 0.0),
    }

# ---------------------------------------------------------------------------
# Claude tool executor
# ---------------------------------------------------------------------------

def _execute_tool(
    tool_name: str,
    tool_input: dict,
    state: dict,
) -> tuple[Any, str]:
    """Execute a tool call from Claude. Returns (result_for_claude, tool_use_id)."""

    if tool_name == "search_graylog":
        raw = _graylog_search(
            tool_input["query"],
            tool_input.get("limit", 20),
            tool_input.get("range_seconds", 3600),
        )
        state["log_entries"] = [_to_log_entry(m) for m in raw]
        state["raw_messages"] = raw
        # Return a compact summary to Claude — not the full GELF dump
        events_for_claude = [m.get("message", m) for m in raw[:15]]
        return {"event_count": len(raw), "events": events_for_claude}, "search_graylog"

    if tool_name == "score_events_ml":
        events = tool_input.get("events", [])
        predictions: list[dict] = []
        for e in events[:20]:
            pred = _ml_predict(e)
            if pred:
                predictions.append(pred)
        state["ml_predictions"] = predictions
        state["ml_result"] = _dominant_ml(predictions)
        return {
            "scored_count": len(predictions),
            "dominant": state["ml_result"],
            "sample_predictions": predictions[:5],
        }, "score_events_ml"

    if tool_name == "lookup_cves":
        threat_type = tool_input.get("threat_type", "")
        cves = _CVE_MAP.get(threat_type, [])
        state["cves"] = cves
        return {"threat_type": threat_type, "cves": cves}, "lookup_cves"

    if tool_name == "produce_analysis":
        state["final_analysis"] = tool_input
        return {"status": "analysis_recorded"}, "produce_analysis"

    return {"error": f"Unknown tool: {tool_name}"}, tool_name

# ---------------------------------------------------------------------------
# Claude-powered chat
# ---------------------------------------------------------------------------

def _run_claude_chat(session_id: str, user_query: str) -> dict:
    """Drive the Claude tool-use loop and return a ThreatAnalysis dict."""
    client = _get_claude()

    with _sessions_lock:
        history: list[dict] = list(_sessions.get(session_id, []))

    history.append({"role": "user", "content": user_query})

    state: dict = {
        "log_entries": [],
        "raw_messages": [],
        "ml_predictions": [],
        "ml_result": None,
        "cves": [],
        "final_analysis": None,
    }

    max_iterations = 8  # guard against infinite loops
    for _ in range(max_iterations):
        response = client.messages.create(
            model="claude-opus-4-7",
            max_tokens=4096,
            system=[{
                "type": "text",
                "text": _SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }],
            tools=_TOOLS,
            messages=history,
        )

        # Append full content block list (required for tool_use continuity)
        history.append({"role": "assistant", "content": response.content})

        if response.stop_reason == "end_turn" or response.stop_reason != "tool_use":
            break

        # Process all tool calls in this turn
        tool_results = []
        for block in response.content:
            if block.type != "tool_use":
                continue
            result, _ = _execute_tool(block.name, block.input, state)
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": json.dumps(result),
            })

        history.append({"role": "user", "content": tool_results})

        if state["final_analysis"]:
            break

    # Persist trimmed history
    with _sessions_lock:
        _sessions[session_id] = history[-_MAX_HISTORY:]

    # Build response
    fa = state["final_analysis"]
    if fa:
        return {
            "summary":            fa.get("summary", "Analysis complete."),
            "threatLevel":        fa.get("threatLevel", "Medium"),
            "affectedSystems":    fa.get("affectedSystems", []),
            "recommendedActions": fa.get("recommendedActions", []),
            "logEntries":         state["log_entries"][:20],
            "cves":               state["cves"],
            "mlPrediction":       state["ml_result"],
            "conversationalReply": fa.get("conversationalReply", "Analysis complete."),
            "sessionId":          session_id,
        }

    # Fallback: extract any text Claude wrote
    text = ""
    for block in history[-1].get("content", []) if isinstance(history[-1].get("content"), list) else []:
        if hasattr(block, "text"):
            text += block.text
    return {
        "summary":            text or "Investigation complete — see log entries below.",
        "threatLevel":        "Medium",
        "affectedSystems":    [],
        "recommendedActions": ["Review the log entries manually and escalate if needed."],
        "logEntries":         state["log_entries"][:20],
        "cves":               state["cves"],
        "mlPrediction":       state["ml_result"],
        "conversationalReply": text or "I've finished investigating. Review the findings below.",
        "sessionId":          session_id,
    }

# ---------------------------------------------------------------------------
# Fallback chat (no Anthropic key — keeps original regex-based behaviour)
# ---------------------------------------------------------------------------

_QUERY_MAP = [
    (__import__("re").compile(r"failed.login|login.fail|brute.forc|auth.fail", __import__("re").I), "action:failed AND event_type:auth", "brute_force"),
    (__import__("re").compile(r"credential.stuff|stuffing",                     __import__("re").I), "action:credential_stuffing",        "credential_stuffing"),
    (__import__("re").compile(r"ddos|denial.of.service|flood",                  __import__("re").I), "action:ddos_detected",              "ddos"),
    (__import__("re").compile(r"sql.inject|injection",                          __import__("re").I), "action:sql_injection",              "sql_injection"),
    (__import__("re").compile(r"suspicious.login|suspicious",                   __import__("re").I), "action:suspicious_login",           "suspicious_login"),
    (__import__("re").compile(r"network|traffic|outbound|lateral",              __import__("re").I), "event_type:network",                "network_anomaly"),
    (__import__("re").compile(r"zero.?day|anomal|unknown.threat",               __import__("re").I), "*",                                 "zero_day"),
    (__import__("re").compile(r"error|critical",                                __import__("re").I), "severity:(error OR critical)",      None),
    (__import__("re").compile(r"last.10.min|recent|what.happened|summary",      __import__("re").I), "*",                                 None),
]

def _translate_query(nl: str) -> tuple[str, str | None]:
    for pattern, graylog_q, threat_class in _QUERY_MAP:
        if pattern.search(nl):
            return graylog_q, threat_class
    return "*", None

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

def _threat_level(ml: dict | None, threat_class: str | None) -> str:
    if ml and ml.get("isZeroDay"):
        return "Critical"
    if ml:
        sev = ml.get("severity", "info").lower()
        return {"info": "Low", "low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"}.get(sev, "Medium")
    if threat_class in ("ddos", "zero_day", "sql_injection"):
        return "Critical"
    if threat_class in ("brute_force", "credential_stuffing"):
        return "High"
    return "Medium"

def _summary_fallback(threat_class: str | None, log_count: int, ml: dict | None, nl: str) -> str:
    zd = ml and ml.get("isZeroDay")
    if zd:
        return (
            f"OmniLog's zero-day detector flagged {log_count} event(s) with no matching known-attack signature. "
            f"The IsolationForest anomaly score ({ml['zeroDayScore']:.2f}/1.0) indicates behaviour that deviates "
            "significantly from the learned baseline. Immediate investigation is recommended."
        )
    templates = {
        "brute_force":         f"OmniLog detected {log_count} failed authentication event(s). Pattern consistent with a brute-force or password-spraying campaign.",
        "credential_stuffing": f"Credential-stuffing activity identified across {log_count} event(s). Multiple accounts targeted from automated tooling.",
        "ddos":                f"{log_count} DDoS-related event(s) detected. High-volume traffic anomaly — service availability may be at risk.",
        "sql_injection":       f"SQL injection attempt(s) blocked across {log_count} event(s). Application-layer attack targeting database exposure.",
        "suspicious_login":    f"{log_count} suspicious login event(s) from unexpected geolocations or outside normal hours.",
        "network_anomaly":     f"Unusual network activity across {log_count} event(s) — possible lateral movement or data exfiltration in progress.",
    }
    if threat_class in templates:
        return templates[threat_class]
    return f"OmniLog analysed {log_count} event(s) related to your query: \"{nl}\". Relevant findings are shown below."

def _actions_fallback(threat_class: str | None, ml: dict | None, sources: list[str]) -> list[str]:
    base: list[str] = []
    if ml and ml.get("isZeroDay"):
        base = [
            "Escalate immediately to SOC Tier 2 — zero-day anomaly with no matching rule",
            "Isolate affected hosts from the network pending forensic analysis",
            "Capture full packet captures on the suspicious source for behavioural review",
            "File an internal incident report and consider submitting to CISA / NVD if a new vulnerability is confirmed",
        ]
    elif threat_class == "brute_force":
        base = [
            "Block the source IP at the perimeter firewall immediately",
            "Enable MFA on all accounts targeted by failed login attempts",
            "Review Active Directory for locked/compromised accounts",
            "Correlate with VPN logs — the attacker may already have a foothold",
        ]
    elif threat_class == "credential_stuffing":
        base = [
            "Force password rotation for all accounts receiving hits",
            "Enable CAPTCHA and rate-limiting on the affected authentication endpoint",
            "Block source IPs and ASNs associated with the attack traffic",
        ]
    elif threat_class == "ddos":
        base = [
            "Activate upstream DDoS mitigation (CDN scrubbing / null-routing)",
            "Rate-limit source IP ranges at the firewall",
            "Notify hosting provider and upstream ISP",
        ]
    elif threat_class == "sql_injection":
        base = [
            "Confirm WAF rule coverage and update signature sets",
            "Audit the application for unsanitised parameterisation",
            "Review database access logs for successful exfiltration attempts",
        ]
    else:
        base = [
            "Investigate source IPs and user accounts involved",
            "Enable enhanced logging on the affected systems",
            "Escalate to the SOC team if the pattern persists",
        ]
    if sources:
        base.append(f"Focus initial investigation on: {', '.join(sorted(set(sources))[:5])}")
    return base

def _run_fallback_chat(nl_query: str) -> dict:
    """Regex-based fallback used when ANTHROPIC_API_KEY is not set."""
    graylog_q, threat_class = _translate_query(nl_query)
    raw_messages = _graylog_search(graylog_q, limit=50)
    log_entries  = [_to_log_entry(m) for m in raw_messages]
    sources      = [e["source"] for e in log_entries if e["source"] != "unknown"]

    predictions: list[dict] = []
    for msg in raw_messages[:20]:
        inner = msg.get("message", msg)
        pred = _ml_predict(inner)
        if pred:
            predictions.append(pred)

    ml_result = _dominant_ml(predictions)
    if ml_result and ml_result.get("isZeroDay"):
        threat_class = "zero_day"

    cves = _CVE_MAP.get(threat_class or "", [])
    return {
        "summary":            _summary_fallback(threat_class, len(log_entries), ml_result, nl_query),
        "threatLevel":        _threat_level(ml_result, threat_class),
        "affectedSystems":    sorted(set(sources))[:8],
        "recommendedActions": _actions_fallback(threat_class, ml_result, sources),
        "logEntries":         log_entries[:20],
        "cves":               cves,
        "mlPrediction":       ml_result,
        "conversationalReply": "I've analyzed the recent security logs based on your query. Here's what I found:",
        "sessionId":          None,
    }

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__)
CORS(app)


@app.get("/health")
def health():
    return jsonify({"status": "ok", "claude_enabled": bool(ANTHROPIC_KEY)})


@app.get("/status")
def status():
    gl_ok = _graylog_alive()
    ml_ok = _ml_alive()

    risk_score   = 42
    alert_count  = 0
    total_events = 0

    if gl_ok:
        try:
            r = requests.get(
                f"{GRAYLOG_BASE}/search/universal/relative",
                params={"query": "*", "range": 3600, "limit": 1},
                headers=_GL_HEADERS, auth=_GL_AUTH, timeout=_TIMEOUT,
            )
            total_events = r.json().get("total_results", 0)
            risk_score = min(100, int(total_events / 100))
        except Exception:
            pass

    return jsonify({
        "graylog_connected":      gl_ok,
        "ml_service_connected":   ml_ok,
        "claude_enabled":         bool(ANTHROPIC_KEY),
        "active_alerts":          alert_count,
        "risk_score":             risk_score,
        "total_events_last_hour": total_events,
    })


@app.post("/chat")
def chat():
    body = request.get_json(force=True, silent=True) or {}
    nl_query: str = (body.get("query") or "").strip()
    session_id: str = (body.get("sessionId") or "").strip() or str(uuid.uuid4())

    if not nl_query:
        return jsonify({"error": "query is required"}), 400

    if _get_claude():
        try:
            result = _run_claude_chat(session_id, nl_query)
        except Exception as exc:
            # Fall back gracefully on any Claude API error
            app.logger.warning("Claude error, falling back to regex: %s", exc)
            result = _run_fallback_chat(nl_query)
            result["sessionId"] = session_id
    else:
        result = _run_fallback_chat(nl_query)
        result["sessionId"] = session_id

    return jsonify(result)


@app.delete("/chat/session/<session_id>")
def clear_session(session_id: str):
    with _sessions_lock:
        _sessions.pop(session_id, None)
    return jsonify({"status": "cleared", "sessionId": session_id})


@app.get("/zero-day-alerts")
def zero_day_alerts():
    """
    Scan recent Graylog events through the ML models and return threats that
    Graylog rules would miss: IsolationForest zero-day anomalies and
    high-risk ML predictions from unexpected behaviour patterns.

    Also auto-trains the IsolationForest if it hasn't been trained yet.
    """
    if not _graylog_alive():
        return jsonify({"error": "Graylog not connected", "threats": []}), 503

    raw = _graylog_search("*", limit=200, range_s=3600)
    if not raw:
        return jsonify({
            "total_scanned": 0, "zero_day_count": 0,
            "model_trained": False, "threats": [],
        })

    events = [m.get("message", m) for m in raw]

    # Check zero-day model status and auto-train if needed
    zd_trained = False
    try:
        h = requests.get(f"{ML_URL}/health", timeout=3)
        zd_trained = h.json().get("zero_day_model") == "loaded"
    except Exception:
        pass

    if not zd_trained and len(events) >= 10:
        try:
            requests.post(
                f"{ML_URL}/train/zero-day",
                json={"platform": "graylog", "events": events, "contamination": 0.05},
                timeout=30,
            )
            zd_trained = True
        except Exception:
            pass

    # Batch-score all events
    try:
        sr = requests.post(
            f"{ML_URL}/predict/batch",
            json={"platform": "graylog", "events": events},
            timeout=20,
        )
        sr.raise_for_status()
        predictions = sr.json().get("results", [])
    except Exception as exc:
        return jsonify({"error": f"ML service error: {exc}", "threats": []}), 503

    threats = []
    for i, (msg, pred) in enumerate(zip(raw[:len(predictions)], predictions)):
        inner     = msg.get("message", msg)
        is_zd     = pred.get("is_zero_day", False)
        combined  = pred.get("combined_risk", 0.0)
        zd_score  = pred.get("zero_day_score", 0.0)
        severity  = pred.get("ml_severity", "info")
        confidence = pred.get("ml_confidence", 0.0)

        # Only surface: confirmed zero-days OR high combined-risk threats
        if not is_zd and combined < 0.55:
            continue

        if is_zd:
            attack_type = "Zero-Day Anomaly"
            description = (
                f"IsolationForest detected behaviour deviating from baseline "
                f"(anomaly score {zd_score:.2f}). No known signature match."
            )
        elif severity in ("critical", "high"):
            attack_type = f"High-Risk ML Detection ({severity.title()})"
            description = (
                f"Classifier flagged {severity} severity with {confidence:.0%} confidence. "
                "Pattern not captured by existing Graylog rules."
            )
        else:
            attack_type = "Behavioural Anomaly"
            description = f"Unusual activity pattern (combined risk {combined:.2f})."

        threats.append({
            "id":           inner.get("_id", str(i)),
            "timestamp":    inner.get("timestamp", ""),
            "source":       inner.get("source", inner.get("gl2_source_input", "unknown")),
            "message":      (inner.get("message") or inner.get("short_message", ""))[:120],
            "zero_day_score": round(zd_score, 3),
            "combined_risk":  round(combined, 3),
            "ml_severity":    severity,
            "attack_type":    attack_type,
            "description":    description,
            "is_zero_day":    is_zd,
        })

    threats.sort(key=lambda t: t["combined_risk"], reverse=True)
    threats = threats[:20]

    return jsonify({
        "total_scanned":  len(predictions),
        "zero_day_count": sum(1 for t in threats if t["is_zero_day"]),
        "model_trained":  zd_trained,
        "threats":        threats,
    })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(f"[OmniLog API] Graylog : {GRAYLOG_BASE}")
    print(f"[OmniLog API] ML Svc  : {ML_URL}")
    print(f"[OmniLog API] Port    : {OMNILOG_PORT}")
    print(f"[OmniLog API] Claude  : {'enabled (claude-opus-4-7)' if ANTHROPIC_KEY else 'disabled — set ANTHROPIC_API_KEY'}")
    app.run(host="0.0.0.0", port=OMNILOG_PORT, debug=False)
