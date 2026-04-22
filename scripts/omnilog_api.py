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

# ---------------------------------------------------------------------------
# Threat name classifier (keyword → human-readable threat name)
# ---------------------------------------------------------------------------

_THREAT_KEYWORDS: list[tuple[list[str], str]] = [
    (["ssh failed", "ssh brute", "failed login:", "failed password", "sshd"], "SSH Brute Force"),
    (["credential stuff", "stuffing attempt"], "Credential Stuffing"),
    (["ddos attack", "ddos detected", "denial of service", "volumetric flood"], "DDoS Attack"),
    (["sql inject", "' or 1=1", "union select", "drop table"], "SQL Injection"),
    (["port scan", "nmap", "syn scan", "mass scan"], "Port Scan"),
    (["xss", "cross-site scripting", "<script>"], "Cross-Site Scripting (XSS)"),
    (["ransomware", "encrypt files", "ransom note"], "Ransomware"),
    (["lateral movement", "psexec", "wmi exec", "pass-the-hash"], "Lateral Movement"),
    (["exfil", "large upload", "data transfer out"], "Data Exfiltration"),
    (["privilege escalat", "sudo abuse", "root exploit", "setuid"], "Privilege Escalation"),
    (["malware", "trojan", "backdoor", "c2 beacon", "command and control"], "Malware / C2 Beacon"),
    (["phishing", "spear phish", "suspicious email"], "Phishing Attempt"),
    (["player login failed", "login failed:", "auth fail", "invalid password", "invalid credentials"], "Authentication Failure"),
    (["normal traffic", "baseline traffic"], "Anomalous Baseline Traffic"),
    (["network anomaly", "unusual traffic", "abnormal bandwidth"], "Network Anomaly"),
]

_THREAT_DETAILS: dict[str, dict] = {
    "SSH Brute Force": {
        "severity": "High",
        "description": "Repeated SSH login failures indicating an automated password-guessing attack against game servers.",
        "cves": [
            {"id": "CVE-2023-38408", "description": "OpenSSH pre-auth RCE via forwarded ssh-agent", "cvss": 9.8},
            {"id": "CVE-2023-48795", "description": "SSH Terrapin prefix truncation attack (Prefix Truncation)", "cvss": 5.9},
        ],
        "remediation": [
            "Block the source IP at the perimeter firewall immediately",
            "Switch SSH to key-based authentication and disable password login",
            "Deploy fail2ban (or equivalent) to auto-ban IPs after 5 failed attempts",
            "Move SSH to a non-standard port as a secondary deterrent",
        ],
    },
    "Credential Stuffing": {
        "severity": "High",
        "description": "Automated use of breached username/password pairs against player authentication endpoints.",
        "cves": [
            {"id": "CVE-2021-42013", "description": "Apache path traversal enabling credential extraction", "cvss": 9.8},
            {"id": "CVE-2023-44487", "description": "HTTP/2 Rapid Reset — used to exhaust auth rate-limiting", "cvss": 7.5},
        ],
        "remediation": [
            "Add CAPTCHA and rate-limiting on all login endpoints",
            "Force password reset for any account that received a successful hit",
            "Enable multi-factor authentication (MFA) for all player accounts",
            "Monitor for impossible-travel logins (same account, different country, within minutes)",
        ],
    },
    "DDoS Attack": {
        "severity": "Critical",
        "description": "High-volume attack traffic designed to exhaust game server resources and deny service to players.",
        "cves": [
            {"id": "CVE-2023-44487", "description": "HTTP/2 Rapid Reset DDoS amplification technique", "cvss": 7.5},
            {"id": "CVE-2022-26134", "description": "Confluence OGNL injection used for botnet recruitment", "cvss": 9.8},
        ],
        "remediation": [
            "Activate upstream CDN scrubbing / DDoS mitigation immediately",
            "Null-route attacker IP ranges at the BGP/ISP level if volumetric",
            "Engage cloud autoscaling to absorb traffic spikes",
            "Contact hosting provider and Cloudflare/Akamai for emergency mitigation",
        ],
    },
    "SQL Injection": {
        "severity": "Critical",
        "description": "Malicious SQL injected into game API queries attempting to extract or corrupt database records.",
        "cves": [
            {"id": "CVE-2021-44228", "description": "Log4Shell JNDI injection often delivered via SQL error messages", "cvss": 10.0},
            {"id": "CVE-2023-3024",  "description": "SQL injection via unsanitised input parameters", "cvss": 9.1},
        ],
        "remediation": [
            "Parameterise all database queries (prepared statements — no string concatenation)",
            "Enable WAF SQL injection rule-sets",
            "Audit database logs for successful reads or modifications since the attack began",
            "Rotate database credentials and revoke excessive permissions",
        ],
    },
    "Port Scan": {
        "severity": "Medium",
        "description": "Systematic port probing to identify open services and potential entry points.",
        "cves": [],
        "remediation": [
            "Block the scanning source IP at the perimeter firewall",
            "Audit exposed ports and close everything not needed for game operation",
            "Enable port-scan detection rules in your IDS/IPS",
        ],
    },
    "Cross-Site Scripting (XSS)": {
        "severity": "High",
        "description": "Malicious JavaScript injected into user-facing game pages to steal sessions or redirect players.",
        "cves": [
            {"id": "CVE-2023-34942", "description": "Stored XSS in player profile fields", "cvss": 6.1},
        ],
        "remediation": [
            "Sanitise and escape all user-supplied input before rendering in HTML",
            "Implement a strict Content Security Policy (CSP) header",
            "Audit stored player data for injected payloads",
        ],
    },
    "Authentication Failure": {
        "severity": "Medium",
        "description": "Login failures — could be forgotten passwords, but patterns across many accounts suggest credential attacks.",
        "cves": [
            {"id": "CVE-2023-23397", "description": "NTLM hash theft via malicious calendar invites", "cvss": 9.8},
        ],
        "remediation": [
            "Alert when the same IP generates more than 10 failures in 5 minutes",
            "Confirm whether failures are from real users or automated tools",
            "Temporarily lock accounts with excessive failures and notify the account owner",
        ],
    },
    "Network Anomaly": {
        "severity": "Medium",
        "description": "Unusual traffic volume or patterns inconsistent with normal game-server operation.",
        "cves": [
            {"id": "CVE-2022-26923", "description": "AD CS domain privilege escalation via certificate template abuse", "cvss": 8.8},
        ],
        "remediation": [
            "Capture and inspect packets on the anomalous flow",
            "Confirm source and destination are expected game servers",
            "Check for lateral movement (unexpected internal connections between servers)",
        ],
    },
    "Lateral Movement": {
        "severity": "Critical",
        "description": "Attacker pivoting between internal game servers after initial compromise.",
        "cves": [
            {"id": "CVE-2021-34527", "description": "PrintNightmare — lateral movement via print spooler RCE", "cvss": 8.8},
        ],
        "remediation": [
            "Isolate the compromised host from the internal network immediately",
            "Audit Active Directory for new accounts or privilege changes",
            "Rotate all service account credentials on affected systems",
            "Begin a full incident response investigation",
        ],
    },
    "Data Exfiltration": {
        "severity": "Critical",
        "description": "Sensitive player or game data being transferred to an external destination.",
        "cves": [],
        "remediation": [
            "Block outbound connections from affected hosts immediately",
            "Determine what data was accessed and by whom",
            "Notify your Data Protection Officer — breach disclosure may be required",
            "Deploy Data Loss Prevention (DLP) controls on network egress",
        ],
    },
    "Ransomware": {
        "severity": "Critical",
        "description": "Ransomware activity detected — files may be actively encrypted.",
        "cves": [],
        "remediation": [
            "Isolate affected hosts IMMEDIATELY — disconnect from the network",
            "Do not pay the ransom — contact law enforcement and a forensics firm",
            "Restore from clean offline backups",
            "Identify and close the initial infection vector before reconnecting",
        ],
    },
    "Malware / C2 Beacon": {
        "severity": "Critical",
        "description": "Malware or command-and-control beacon detected on a game server.",
        "cves": [],
        "remediation": [
            "Isolate the affected host immediately",
            "Run a full endpoint security scan",
            "Block C2 IP addresses and domains at the firewall and DNS",
            "Conduct a full forensic investigation of the affected system",
        ],
    },
    "Privilege Escalation": {
        "severity": "Critical",
        "description": "An account is attempting to gain higher permissions than it is authorised for.",
        "cves": [
            {"id": "CVE-2022-21999", "description": "Windows Print Spooler privilege escalation (PrintNightmare variant)", "cvss": 7.8},
        ],
        "remediation": [
            "Review and reduce sudo / admin group memberships immediately",
            "Audit privilege-change events in system logs for the past 24 hours",
            "Apply principle of least privilege across all service accounts",
            "Patch OS and all software to current versions",
        ],
    },
    "Phishing Attempt": {
        "severity": "High",
        "description": "Phishing or spear-phishing activity targeting staff or player accounts.",
        "cves": [],
        "remediation": [
            "Block the phishing domain/IP at the email gateway and DNS",
            "Alert potentially targeted users to change passwords",
            "Run a phishing awareness reminder for staff",
        ],
    },
    "Anomalous Baseline Traffic": {
        "severity": "Low",
        "description": "Traffic that looks normal but has a statistically unusual pattern detected by the ML IsolationForest model.",
        "cves": [],
        "remediation": [
            "Monitor this source for 24 hours — low priority but worth tracking",
            "Correlate with other events from the same source IP",
        ],
    },
    "Zero-Day Anomaly": {
        "severity": "Critical",
        "description": "Behaviour with no matching known-attack signature — flagged by the IsolationForest as deviating from learned baseline.",
        "cves": [
            {"id": "CVE-UNKNOWN", "description": "Unclassified zero-day — no CVE assigned yet", "cvss": None},
        ],
        "remediation": [
            "Escalate immediately to SOC Tier 2 — this is an unclassified threat",
            "Isolate affected hosts pending forensic analysis",
            "Capture full packet traces and process trees on the suspicious source",
            "Consider reporting to CISA / NVD if a new vulnerability is confirmed",
        ],
    },
    "Unknown Anomaly": {
        "severity": "Medium",
        "description": "Anomalous behaviour detected by ML that does not match any known attack pattern.",
        "cves": [],
        "remediation": [
            "Review the raw log events manually",
            "Escalate to SOC team for expert analysis",
            "Enable enhanced logging on affected systems",
        ],
    },
}


def _graylog_rule_assessment(action: str, severity: str, event_type: str, msg: str) -> dict:
    """
    Derive what Graylog's existing rule set would classify this event as,
    based purely on the structured fields that Graylog alert rules inspect.
    """
    a = (action or "").lower()
    s = (severity or "info").lower()
    m = (msg or "").lower()

    if a in ("brute_force",) or ("brute" in m and "force" in m):
        name = "SSH Brute Force"
    elif a in ("credential_stuffing",) or "credential_stuff" in m:
        name = "Credential Stuffing"
    elif a in ("ddos_detected", "flood", "syn_flood") or "ddos" in m:
        name = "DDoS Attack"
    elif a in ("sql_injection",) or "sql" in m:
        name = "SQL Injection"
    elif a in ("xss_attack",) or "xss" in m or "cross-site" in m:
        name = "XSS Attack"
    elif a in ("lateral_movement",) or "lateral" in m:
        name = "Lateral Movement"
    elif a in ("privilege_escalation",) or "privilege" in m:
        name = "Privilege Escalation"
    elif a in ("data_exfiltration", "exfil") or "exfil" in m:
        name = "Data Exfiltration"
    elif a in ("port_scan", "reconnaissance") or "port scan" in m:
        name = "Port Scan"
    elif a in ("malware_detected", "ransomware") or "ransomware" in m:
        name = "Malware / Ransomware"
    elif a in ("failed", "failed_login", "suspicious_login") or "failed login" in m:
        name = "Authentication Failure"
    elif s in ("critical", "emergency"):
        name = "Critical System Event"
    elif s in ("high", "error"):
        name = "High Severity Event"
    else:
        name = "Normal Traffic"

    return {"name": name, "severity": s}


_SEV_ORDER = {"info": 0, "low": 1, "warning": 1, "medium": 2, "error": 2, "high": 3, "critical": 4, "emergency": 5}


def _compute_comparison_delta(
    graylog_name: str, graylog_sev: str,
    ml_name: str,     ml_sev: str,
    is_zd: bool,      confidence: float,
) -> str:
    """Return a plain-English statement comparing what Graylog vs ML found."""
    parts: list[str] = []

    g_low = graylog_name.lower()
    m_low = ml_name.lower()
    names_match = (g_low == m_low) or (m_low in g_low) or (g_low in m_low)

    g_lvl = _SEV_ORDER.get(graylog_sev, 0)
    m_lvl = _SEV_ORDER.get(ml_sev, 0)

    if is_zd:
        parts.append(
            f"ML flagged as zero-day anomaly — this pattern has no matching Graylog alert rule."
        )
        if not names_match:
            parts.append(
                f"Graylog classified it as '{graylog_name}' ({graylog_sev}), "
                f"but ML identifies '{ml_name}' with {confidence:.0%} confidence."
            )
    else:
        if not names_match:
            parts.append(
                f"Threat type mismatch: Graylog saw '{graylog_name}' but ML detected "
                f"'{ml_name}' ({confidence:.0%} confidence)."
            )

    if m_lvl > g_lvl:
        parts.append(
            f"Severity escalated by ML: Graylog rated '{graylog_sev}' \u2192 ML rates '{ml_sev}'."
        )
    elif m_lvl < g_lvl and m_lvl > 0:
        parts.append(
            f"ML rates severity lower than Graylog ('{ml_sev}' vs '{graylog_sev}')."
        )

    if not parts:
        parts.append(
            f"Both Graylog and ML agree: '{ml_name}' at '{ml_sev}' severity. "
            f"ML provided additional confidence ({confidence:.0%}) beyond rule-based detection."
        )

    return " ".join(parts)


def _classify_threat_name(message: str, event_type: str = "", action: str = "") -> str:
    """Classify a threat from message/event content into a human-readable threat name."""
    combined = (message + " " + event_type + " " + action).lower()
    for keywords, name in _THREAT_KEYWORDS:
        if any(k in combined for k in keywords):
            return name
    # Fallback: use the action field directly
    _action_fallback = {
        "failed":              "Authentication Failure",
        "brute_force":         "SSH Brute Force",
        "credential_stuffing": "Credential Stuffing",
        "ddos_detected":       "DDoS Attack",
        "sql_injection":       "SQL Injection",
        "suspicious_login":    "Authentication Failure",
        "network_anomaly":     "Network Anomaly",
    }
    for k, v in _action_fallback.items():
        if k in action.lower():
            return v
    return "Unknown Anomaly"


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
            "Can return up to 1000 events — use a higher limit for thorough investigations. "
            "Use Graylog query syntax: field:value, AND/OR, wildcards (*). "
            "Examples: 'action:failed AND event_type:auth', 'severity:critical', '*'. "
            "Use from_timestamp and to_timestamp (ISO 8601) to query a specific time window."
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
                    "description": "Max events to return (1–1000, default 100)",
                    "default": 100
                },
                "range_seconds": {
                    "type": "integer",
                    "description": "Look-back window in seconds (default 3600 = 1 hour). Ignored if from_timestamp is set.",
                    "default": 3600
                },
                "from_timestamp": {
                    "type": "string",
                    "description": "Start of time window in ISO 8601 format (e.g. '2026-04-22T10:00:00.000Z'). If set, to_timestamp is required."
                },
                "to_timestamp": {
                    "type": "string",
                    "description": "End of time window in ISO 8601 format. Required when from_timestamp is set."
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
You are OmniLog, an AI security analyst for the Catnip Games SIEM platform \
(Graylog 6.1 + OpenSearch 2.15). You have live access to Graylog logs, \
an ML anomaly detector, and a CVE knowledge base.

## How to write conversationalReply
Write it like a briefing to a manager who is not a security expert:
- Lead with the key finding in ONE plain sentence ("I found 47 failed SSH logins \
  from one IP address in the last hour.")
- Quantify: include counts, source IPs, time windows where available.
- Use plain English: say "failed login attempt" not "auth failure"; \
  "unusual outbound traffic" not "anomalous egress telemetry".
- End with one clear action the reader should take.
- Maximum 3 sentences total. No bullet points inside conversationalReply.

## Investigation steps
1. Call search_graylog — request up to 1000 events to get a full picture. \
   Use specific Graylog query syntax (field:value, AND/OR, wildcards).
2. If events are returned, call score_events_ml on a representative sample of up to 20 events.
3. If ML detects a clear threat type or zero-day (is_zero_day=true), call lookup_cves.
4. Call produce_analysis ONCE as your final step — never call another tool after it.

## Rules
- Always use real tool calls — never guess, never fabricate log entries or CVE numbers.
- If Graylog returns 0 events, report that clearly and set threatLevel to Low.
- recommendedActions must be numbered, concrete, and ordered most-urgent first.
- summary should be 3–5 plain sentences suitable for an incident report.
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

def _normalize_ts(ts: str) -> str:
    """Ensure a timestamp has milliseconds — Graylog absolute search requires .000Z."""
    ts = ts.strip()
    if ts.endswith("Z"):
        body = ts[:-1]
        if "." not in body:
            ts = body + ".000Z"
    elif "+" in ts:
        # strip timezone offset and add .000Z
        ts = ts.split("+")[0] + ".000Z"
    return ts


_GRAYLOG_FIELDS = (
    "timestamp,source,level,message,event_type,action,"
    "source_ip,severity,risk_score,confidence,"
    "baseline_deviation,entropy,frequency_anomaly,sequence_anomaly"
)


def _graylog_search(
    q: str,
    limit: int = 100,
    range_s: int = 3600,
    from_ts: str | None = None,
    to_ts: str | None = None,
) -> list[dict]:
    """Search Graylog. Supports relative range or absolute from/to timestamps."""
    try:
        if from_ts and to_ts:
            r = requests.get(
                f"{GRAYLOG_BASE}/search/universal/absolute",
                params={
                    "query": q,
                    "from": _normalize_ts(from_ts),
                    "to":   _normalize_ts(to_ts),
                    "limit": min(limit, 1000),
                    "fields": _GRAYLOG_FIELDS,
                },
                headers=_GL_HEADERS,
                auth=_GL_AUTH,
                timeout=max(_TIMEOUT, 20),
            )
        else:
            r = requests.get(
                f"{GRAYLOG_BASE}/search/universal/relative",
                params={
                    "query": q,
                    "range": range_s,
                    "limit": min(limit, 1000),
                    "fields": _GRAYLOG_FIELDS,
                },
                headers=_GL_HEADERS,
                auth=_GL_AUTH,
                timeout=max(_TIMEOUT, 20),
            )
        r.raise_for_status()
        return r.json().get("messages", [])
    except Exception:
        return []


def _graylog_count(
    q: str,
    range_s: int = 3600,
    from_ts: str | None = None,
    to_ts: str | None = None,
) -> int:
    """Return total_results count — supports relative range or absolute from/to timestamps."""
    try:
        if from_ts and to_ts:
            r = requests.get(
                f"{GRAYLOG_BASE}/search/universal/absolute",
                params={"query": q, "from": _normalize_ts(from_ts), "to": _normalize_ts(to_ts), "limit": 1},
                headers=_GL_HEADERS, auth=_GL_AUTH, timeout=_TIMEOUT,
            )
        else:
            r = requests.get(
                f"{GRAYLOG_BASE}/search/universal/relative",
                params={"query": q, "range": range_s, "limit": 1},
                headers=_GL_HEADERS, auth=_GL_AUTH, timeout=_TIMEOUT,
            )
        r.raise_for_status()
        return int(r.json().get("total_results", 0))
    except Exception:
        return 0

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
            tool_input.get("limit", 100),
            tool_input.get("range_seconds", 3600),
            tool_input.get("from_timestamp"),
            tool_input.get("to_timestamp"),
        )
        state["log_entries"] = [_to_log_entry(m) for m in raw]
        state["raw_messages"] = raw
        # Send a compact summary to Claude (not the full GELF dump)
        # For large batches compress to key fields only
        events_for_claude = []
        for m in raw[:50]:
            inner = m.get("message", m)
            events_for_claude.append({
                "ts":       inner.get("timestamp", ""),
                "src":      inner.get("source", ""),
                "msg":      (inner.get("message") or inner.get("short_message", ""))[:80],
                "sev":      inner.get("severity", inner.get("level", "")),
                "act":      inner.get("action", ""),
                "evt":      inner.get("event_type", ""),
            })
        return {
            "event_count": len(raw),
            "events": events_for_claude,
            "note": f"{len(raw)} events fetched — showing first 50 to Claude; all {len(raw)} available for ML scoring.",
        }, "search_graylog"

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

    risk_score   = 0
    alert_count  = 0
    total_events = 0

    if gl_ok:
        try:
            # Total events in last hour
            r = requests.get(
                f"{GRAYLOG_BASE}/search/universal/relative",
                params={"query": "*", "range": 3600, "limit": 1},
                headers=_GL_HEADERS, auth=_GL_AUTH, timeout=_TIMEOUT,
            )
            total_events = r.json().get("total_results", 0)
        except Exception:
            pass

        try:
            # Active alerts = high/critical severity events + known attack actions
            _ALERT_QUERY = (
                "severity:(critical OR high OR emergency) OR "
                "action:(brute_force OR ddos_detected OR sql_injection OR "
                "credential_stuffing OR suspicious_login OR lateral_movement)"
            )
            ra = requests.get(
                f"{GRAYLOG_BASE}/search/universal/relative",
                params={"query": _ALERT_QUERY, "range": 3600, "limit": 1},
                headers=_GL_HEADERS, auth=_GL_AUTH, timeout=_TIMEOUT,
            )
            alert_count = ra.json().get("total_results", 0)
        except Exception:
            pass

        # Risk score: blend alert density and total volume
        if total_events > 0:
            alert_ratio = alert_count / total_events
            volume_score = min(50, int(total_events / 200))
            alert_score  = min(50, int(alert_ratio * 500))
            risk_score   = min(100, volume_score + alert_score)

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
    ZD_THRESH = -0.05  # mirrors ZeroDayDetector.DEFAULT_THRESHOLD
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

        msg_text  = inner.get("message") or inner.get("short_message", "")
        evt_type  = inner.get("event_type", "")
        action    = inner.get("action", "")
        raw_sev   = inner.get("severity") or inner.get("level", "info")

        # ML classification
        ml_name = _classify_threat_name(msg_text, evt_type, action)
        if is_zd and ml_name == "Unknown Anomaly":
            ml_name = "Zero-Day Anomaly"
        threat_name = ml_name
        details = _THREAT_DETAILS.get(threat_name, _THREAT_DETAILS.get("Unknown Anomaly", {"description": "", "cves": [], "remediation": []}))

        if is_zd:
            description = (
                f"{details['description']} "
                f"IsolationForest anomaly score: {zd_score:.2f} (threshold {ZD_THRESH:.2f})."
            )
        elif severity in ("critical", "high"):
            description = (
                f"{details['description']} "
                f"ML confidence: {confidence:.0%} — pattern not captured by existing Graylog rules."
            )
        else:
            description = f"{details['description']} Combined risk score: {combined:.2f}."

        # Graylog rule-based assessment vs ML assessment comparison
        graylog_assess = _graylog_rule_assessment(action, str(raw_sev), evt_type, msg_text)
        delta = _compute_comparison_delta(
            graylog_assess["name"], graylog_assess["severity"],
            ml_name, severity, is_zd, confidence,
        )

        threats.append({
            "id":            inner.get("_id", str(i)),
            "timestamp":     inner.get("timestamp", ""),
            "source":        inner.get("source", inner.get("gl2_source_input", "unknown")),
            "message":       msg_text[:120],
            "zero_day_score": round(zd_score, 3),
            "combined_risk":  round(combined, 3),
            "ml_severity":    severity,
            "attack_type":    threat_name,
            "description":    description,
            "is_zero_day":    is_zd,
            "cves":           details.get("cves", []),
            "remediation":    details.get("remediation", []),
            "graylog_assessment": graylog_assess,
            "ml_assessment": {
                "name":        ml_name,
                "severity":    severity,
                "confidence":  round(confidence, 3),
                "is_zero_day": is_zd,
            },
            "comparison": {"delta": delta},
        })

    threats.sort(key=lambda t: t["combined_risk"], reverse=True)
    threats = threats[:20]

    return jsonify({
        "total_scanned":  len(predictions),
        "zero_day_count": sum(1 for t in threats if t["is_zero_day"]),
        "model_trained":  zd_trained,
        "threats":        threats,
    })


_DASHBOARD_CATEGORIES = {
    "failed_logins": {
        "label": "Failed Logins",
        "query": '"failed login" OR "login failed" OR action:failed OR action:brute_force OR action:credential_stuffing',
    },
    "errors": {
        "label": "Errors",
        "query": "severity:(error OR critical OR emergency) OR level:(0 OR 1 OR 2 OR 3)",
    },
    "network_activity": {
        "label": "Network Activity",
        "query": 'event_type:network OR event_type:firewall OR event_type:dns OR "traffic" OR "network"',
    },
    "suspicious_behaviour": {
        "label": "Suspicious Behaviour",
        "query": (
            "action:(ddos_detected OR sql_injection OR suspicious_login OR port_scan OR lateral_movement) "
            'OR "suspicious" OR "anomaly" OR "ddos" OR severity:high'
        ),
    },
}


@app.get("/dashboard-counts")
def dashboard_counts():
    """
    Return event counts and recent events for all sidebar filter categories.
    Used to populate count badges and dropdown previews.
    """
    if not _graylog_alive():
        return jsonify({"error": "Graylog not connected"}), 503

    result = {}
    for key, cat in _DASHBOARD_CATEGORIES.items():
        count = _graylog_count(cat["query"])
        raw   = _graylog_search(cat["query"], limit=8)
        events = []
        for m in raw:
            inner = m.get("message", m)
            msg_text = (inner.get("message") or inner.get("short_message", ""))[:100]
            events.append({
                "timestamp": inner.get("timestamp", ""),
                "source":    inner.get("source", "unknown"),
                "message":   msg_text,
                "severity":  str(inner.get("severity", inner.get("level", "info"))).lower(),
                "action":    inner.get("action", ""),
                "event_type": inner.get("event_type", ""),
                "threat_name": _classify_threat_name(
                    msg_text, inner.get("event_type", ""), inner.get("action", "")
                ),
            })
        result[key] = {"count": count, "label": cat["label"], "events": events}

    return jsonify(result)


@app.get("/report")
def generate_report():
    """
    Generate a comprehensive security report.

    Query params:
      from_ts   ISO 8601 start timestamp (optional — defaults to 1 hour ago)
      to_ts     ISO 8601 end timestamp   (optional — defaults to now)

    Analyses up to 10,000 log events, scores a representative ML sample,
    maps findings to CVEs, and returns a prioritised remediation plan.
    """
    import datetime as _dt

    if not _graylog_alive():
        return jsonify({"error": "Graylog not connected"}), 503

    from_ts = request.args.get("from_ts") or None
    to_ts   = request.args.get("to_ts")   or None

    now_utc = _dt.datetime.utcnow()
    now_str = now_utc.isoformat(timespec="seconds") + "Z"

    if from_ts and to_ts:
        try:
            _from_dt = _dt.datetime.fromisoformat(from_ts.rstrip("Z"))
            _to_dt   = _dt.datetime.fromisoformat(to_ts.rstrip("Z"))
            period_label = (
                f"{_from_dt.strftime('%Y-%m-%d %H:%M')} → "
                f"{_to_dt.strftime('%Y-%m-%d %H:%M')} UTC"
            )
        except Exception:
            period_label = f"{from_ts} → {to_ts}"
    else:
        period_label = "Last 1 hour"
        from_ts = to_ts = None  # use relative range

    def _count(q: str) -> int:
        return _graylog_count(q, range_s=3600, from_ts=from_ts, to_ts=to_ts)

    def _search(q: str, limit: int = 200) -> list[dict]:
        return _graylog_search(q, limit=limit, range_s=3600, from_ts=from_ts, to_ts=to_ts)

    # --- overall stats (10 k scan) ---
    total_events = _count("*")

    # --- per-category counts and sample events ---
    categories = []
    all_sample_messages: list[dict] = []
    all_sources: list[str] = []

    for key, cat in _DASHBOARD_CATEGORIES.items():
        count = _count(cat["query"])
        # Fetch up to 200 samples per category for threat analysis
        raw   = _search(cat["query"], limit=200)
        samples = []
        for m in raw:
            inner = m.get("message", m)
            msg_text = (inner.get("message") or inner.get("short_message", ""))[:120]
            source   = inner.get("source", "unknown")
            action   = inner.get("action", "")
            evt_type = inner.get("event_type", "")
            all_sources.append(source)
            all_sample_messages.append(inner)
            samples.append({
                "timestamp": inner.get("timestamp", ""),
                "source":    source,
                "message":   msg_text,
                "severity":  str(inner.get("severity", inner.get("level", "info"))).lower(),
                "threat_name": _classify_threat_name(msg_text, evt_type, action),
            })

        # Tally threat types in this category
        threat_counts: dict[str, int] = {}
        for s in samples:
            n = s["threat_name"]
            threat_counts[n] = threat_counts.get(n, 0) + 1
        dominant = max(threat_counts, key=threat_counts.get) if threat_counts else "Unknown"
        details  = _THREAT_DETAILS.get(dominant, _THREAT_DETAILS["Unknown Anomaly"])

        # Unique threat breakdown for the category
        threat_breakdown = [
            {"name": n, "count": c}
            for n, c in sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)
        ]

        categories.append({
            "key":              key,
            "label":            cat["label"],
            "count":            count,
            "dominant_threat":  dominant,
            "severity":         details["severity"],
            "description":      details["description"],
            "cves":             details["cves"],
            "remediation":      details["remediation"],
            "sample_events":    samples[:8],
            "threat_breakdown": threat_breakdown[:5],
        })

    # --- ML scan: score a representative sample (up to 200 events) ---
    ml_summary = {"status": "unavailable", "zero_day_count": 0, "high_risk_count": 0}
    if _ml_alive() and all_sample_messages:
        # Batch-score via ML service for efficiency
        try:
            sample_for_ml = all_sample_messages[:200]
            sr = requests.post(
                f"{ML_URL}/predict/batch",
                json={"platform": "graylog", "events": sample_for_ml},
                timeout=30,
            )
            sr.raise_for_status()
            predictions = sr.json().get("results", [])
        except Exception:
            predictions = []
            for e in all_sample_messages[:50]:
                p = _ml_predict(e)
                if p:
                    predictions.append(p)

        zd_count   = sum(1 for p in predictions if p.get("is_zero_day"))
        high_count = sum(1 for p in predictions if p.get("ml_severity") in ("critical", "high"))
        ml_summary = {
            "status":          "active",
            "events_scored":   len(predictions),
            "zero_day_count":  zd_count,
            "high_risk_count": high_count,
            "anomaly_rate":    round(zd_count / max(len(predictions), 1), 3),
        }

    # --- top sources ---
    source_freq: dict[str, int] = {}
    for s in all_sources:
        if s and s != "unknown":
            source_freq[s] = source_freq.get(s, 0) + 1
    top_sources = [
        {"source": s, "event_count": c}
        for s, c in sorted(source_freq.items(), key=lambda x: x[1], reverse=True)[:10]
    ]

    # --- unified CVE list (deduplicated) ---
    seen_cves: set[str] = set()
    all_cves: list[dict] = []
    for cat in categories:
        for cve in cat["cves"]:
            if cve["id"] not in seen_cves:
                seen_cves.add(cve["id"])
                all_cves.append({**cve, "related_threat": cat["dominant_threat"]})

    # --- consolidated remediation (ordered by severity) ---
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    sorted_cats = sorted(categories, key=lambda c: sev_order.get(c["severity"], 9))
    remediation_plan: list[dict] = []
    for cat in sorted_cats:
        if cat["count"] > 0 and cat["remediation"]:
            remediation_plan.append({
                "threat":     cat["dominant_threat"],
                "severity":   cat["severity"],
                "count":      cat["count"],
                "steps":      cat["remediation"],
            })

    # --- overall threat level ---
    if any(c["severity"] == "Critical" and c["count"] > 0 for c in categories):
        overall_level = "Critical"
    elif any(c["severity"] == "High" and c["count"] > 0 for c in categories):
        overall_level = "High"
    elif any(c["severity"] == "Medium" and c["count"] > 0 for c in categories):
        overall_level = "Medium"
    else:
        overall_level = "Low"

    failed_logins_count = next((c["count"] for c in categories if c["key"] == "failed_logins"), 0)
    suspicious_count    = next((c["count"] for c in categories if c["key"] == "suspicious_behaviour"), 0)

    executive_summary = (
        f"In the last hour, OmniLog processed {total_events:,} log events across all game servers. "
        f"The overall threat level is {overall_level}. "
        f"Notable findings: {failed_logins_count:,} failed login events and "
        f"{suspicious_count:,} suspicious-behaviour events were recorded. "
        f"The ML anomaly engine scored {ml_summary.get('events_scored', 0)} events, "
        f"flagging {ml_summary.get('zero_day_count', 0)} zero-day anomalies and "
        f"{ml_summary.get('high_risk_count', 0)} high-risk patterns. "
        f"Immediate action is recommended for all Critical and High severity findings below."
    )

    return jsonify({
        "generated_at":       now_str,
        "period":             period_label,
        "overall_threat_level": overall_level,
        "executive_summary":  executive_summary,
        "statistics": {
            "total_events":        total_events,
            "failed_logins":       failed_logins_count,
            "suspicious_events":   suspicious_count,
            "unique_sources":      len(source_freq),
        },
        "categories":         categories,
        "ml_analysis":        ml_summary,
        "cve_mappings":       all_cves,
        "remediation_plan":   remediation_plan,
        "top_sources":        top_sources,
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
