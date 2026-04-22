#!/usr/bin/env python3
"""
Catnip Games SIEM - Automated Security Report Generator
Queries Graylog 6.x API and generates a weekly security summary report
"""

import requests
import json
import datetime
import os
from collections import Counter
from pathlib import Path
from requests.auth import HTTPBasicAuth

# ─────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────
def _read_env(key: str, default: str = "") -> str:
    """Read a value from .env file, falling back to environment variables."""
    env_file = Path(__file__).resolve().parents[1] / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip().rstrip("\r")
            if line.startswith(f"{key}=") and not line.startswith("#"):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return os.environ.get(key, default)

GRAYLOG_HOST = "http://localhost:9000"
GRAYLOG_API  = f"{GRAYLOG_HOST}/api"
GRAYLOG_USER = "admin"
GRAYLOG_PASS = _read_env("GRAYLOG_ADMIN_PASSWORD") or _read_env("GRAYLOG_PASSWORD")

REPORTS_DIR  = os.path.join(os.path.dirname(__file__), "../reports")

HEADERS = {
    "Content-Type":  "application/json",
    "Accept":        "application/json",
    "X-Requested-By": "catnip-report"
}

# ─────────────────────────────────────────
# Graylog API helper
# ─────────────────────────────────────────
def search_messages(query, fields, timerange_seconds=604800, limit=10000):
    """
    Query Graylog 6.x /api/search/messages endpoint.
    Returns list of dicts, one per message, keyed by field name.
    """
    auth = HTTPBasicAuth(GRAYLOG_USER, GRAYLOG_PASS)
    url  = f"{GRAYLOG_API}/search/messages"
    body = {
        "query":     query,
        "timerange": {"type": "relative", "range": timerange_seconds},
        "fields":    fields,
        "size":      limit
    }
    try:
        response = requests.post(url, headers=HEADERS, auth=auth,
                                 data=json.dumps(body), timeout=30)
        response.raise_for_status()
        data   = response.json()
        schema = [col["field"] for col in data.get("schema", [])]
        rows   = data.get("datarows", [])
        return [dict(zip(schema, row)) for row in rows]
    except requests.exceptions.RequestException as e:
        print(f"  [ERROR] API request failed: {e}")
        return []


def count_messages(query, timerange_seconds=604800):
    """Count messages matching a query"""
    rows = search_messages(query, ["source"], timerange_seconds, limit=10000)
    return len(rows)


def top_values(query, field, timerange_seconds=604800, limit=10):
    """Get top N values for a field using Python Counter"""
    rows   = search_messages(query, [field], timerange_seconds, limit=10000)
    values = [row.get(field) for row in rows if row.get(field)]
    return dict(Counter(values).most_common(limit))


# ─────────────────────────────────────────
# Report sections
# ─────────────────────────────────────────
def get_summary_stats():
    print("  Fetching event counts...")
    return {
        "total_events":        count_messages("*"),
        "critical_events":     count_messages("severity:critical"),
        "ssh_failed":          count_messages("event_type:sshd AND action:failed"),
        "ssh_accepted":        count_messages("event_type:sshd AND action:accepted"),
        "ddos_events":         count_messages("action:ddos_detected"),
        "credential_stuffing": count_messages("action:credential_stuffing"),
        "player_auth_failed":  count_messages("event_type:player_auth AND action:login_failed"),
        "player_auth_success": count_messages("event_type:player_auth AND action:login_success"),
        "dev_ssh_suspicious":  count_messages("action:suspicious_login"),
    }


def get_top_attackers():
    print("  Fetching top attacking IPs...")
    return top_values("severity:critical", "source_ip", limit=10)


def get_top_targeted_users():
    print("  Fetching most targeted usernames...")
    return top_values("event_type:sshd AND action:failed", "username", limit=10)


def get_top_targeted_servers():
    print("  Fetching most targeted servers...")
    return top_values("severity:critical", "server_id", limit=10)


def get_ddos_incidents():
    print("  Fetching recent DDoS incidents...")
    return search_messages(
        "action:ddos_detected",
        ["timestamp", "server_id", "traffic_mbps", "source_ip"],
        limit=5
    )


# ─────────────────────────────────────────
# Report builder
# ─────────────────────────────────────────
def build_report(stats, attackers, targeted_users, targeted_servers, ddos_incidents):
    now       = datetime.datetime.now()
    week_ago  = now - datetime.timedelta(days=7)
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
    date_from = week_ago.strftime("%Y-%m-%d")
    date_to   = now.strftime("%Y-%m-%d")

    # Risk level
    if stats["critical_events"] > 10000:
        risk_level, risk_note = "CRITICAL", "Immediate investigation required"
    elif stats["critical_events"] > 5000:
        risk_level, risk_note = "HIGH", "Elevated threat activity detected"
    elif stats["critical_events"] > 1000:
        risk_level, risk_note = "MEDIUM", "Moderate threat activity — monitor closely"
    else:
        risk_level, risk_note = "LOW", "Normal activity levels"

    lines = []
    lines.append("=" * 65)
    lines.append("  CATNIP GAMES INTERNATIONAL")
    lines.append("  WEEKLY SECURITY OPERATIONS REPORT")
    lines.append("=" * 65)
    lines.append(f"  Report generated : {timestamp}")
    lines.append(f"  Period covered   : {date_from} to {date_to}")
    lines.append(f"  Overall risk     : {risk_level} — {risk_note}")
    lines.append("=" * 65)
    lines.append("")

    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * 40)
    lines.append(f"Total log events processed : {stats['total_events']:,}")
    lines.append(f"Critical severity events   : {stats['critical_events']:,}")
    lines.append(f"DDoS incidents detected    : {stats['ddos_events']:,}")
    lines.append(f"Credential stuffing attacks: {stats['credential_stuffing']:,}")
    lines.append(f"Suspicious dev SSH logins  : {stats['dev_ssh_suspicious']:,}")
    lines.append("")

    lines.append("SSH AUTHENTICATION ANALYSIS")
    lines.append("-" * 40)
    lines.append(f"Failed SSH logins    : {stats['ssh_failed']:,}")
    lines.append(f"Successful SSH logins: {stats['ssh_accepted']:,}")
    total_ssh = stats['ssh_failed'] + stats['ssh_accepted']
    if total_ssh > 0:
        lines.append(f"Failure rate         : {(stats['ssh_failed'] / total_ssh * 100):.1f}%")
    lines.append("")

    lines.append("PLAYER AUTHENTICATION ANALYSIS")
    lines.append("-" * 40)
    lines.append(f"Failed player logins    : {stats['player_auth_failed']:,}")
    lines.append(f"Successful player logins: {stats['player_auth_success']:,}")
    total_player = stats['player_auth_failed'] + stats['player_auth_success']
    if total_player > 0:
        lines.append(f"Player failure rate     : {(stats['player_auth_failed'] / total_player * 100):.1f}%")
    lines.append("")

    lines.append("TOP ATTACKING IP ADDRESSES")
    lines.append("-" * 40)
    if attackers:
        for i, (ip, count) in enumerate(sorted(attackers.items(), key=lambda x: x[1], reverse=True)[:10], 1):
            lines.append(f"  {i:2}. {ip:<22} {count:,} events")
    else:
        lines.append("  No attacker data available")
    lines.append("")

    lines.append("MOST TARGETED USERNAMES (SSH)")
    lines.append("-" * 40)
    if targeted_users:
        for i, (user, count) in enumerate(sorted(targeted_users.items(), key=lambda x: x[1], reverse=True)[:10], 1):
            lines.append(f"  {i:2}. {user:<22} {count:,} attempts")
    else:
        lines.append("  No username targeting data available")
    lines.append("")

    lines.append("MOST TARGETED SERVERS")
    lines.append("-" * 40)
    if targeted_servers:
        for i, (server, count) in enumerate(sorted(targeted_servers.items(), key=lambda x: x[1], reverse=True)[:10], 1):
            lines.append(f"  {i:2}. {server:<22} {count:,} events")
    else:
        lines.append("  No server targeting data available")
    lines.append("")

    lines.append("RECENT DDoS INCIDENTS")
    lines.append("-" * 40)
    if ddos_incidents:
        for incident in ddos_incidents[:5]:
            ts      = str(incident.get("timestamp", "unknown"))[:19]
            server  = incident.get("server_id",   "unknown")
            traffic = incident.get("traffic_mbps","unknown")
            source  = incident.get("source_ip",   "unknown")
            lines.append(f"  [{ts}] {server} — {traffic} Mbps from {source}")
    else:
        lines.append("  No DDoS incidents recorded")
    lines.append("")

    lines.append("SECURITY RECOMMENDATIONS")
    lines.append("-" * 40)
    recommendations = []
    if stats["ssh_failed"] > 100:
        recommendations.append("  [!] High SSH failure rate — review firewall rules and consider fail2ban")
    if stats["ddos_events"] > 50:
        recommendations.append("  [!] DDoS activity detected — review rate limiting and consider upstream mitigation")
    if stats["credential_stuffing"] > 100:
        recommendations.append("  [!] Credential stuffing detected — enforce MFA and consider CAPTCHA on login")
    if stats["dev_ssh_suspicious"] > 10:
        recommendations.append("  [!] Suspicious dev SSH activity — audit access logs and review key rotation policy")
    if recommendations:
        lines.extend(recommendations)
    else:
        lines.append("  [OK] No immediate recommendations — continue monitoring")
    lines.append("")

    lines.append("=" * 65)
    lines.append("  END OF REPORT — Catnip Games Security Operations")
    lines.append("=" * 65)

    return "\n".join(lines)


# ─────────────────────────────────────────
# Main
# ─────────────────────────────────────────
def main():
    print("=" * 55)
    print("  Catnip Games SIEM - Report Generator")
    print("=" * 55)

    os.makedirs(REPORTS_DIR, exist_ok=True)

    print("\n[1/5] Fetching summary statistics...")
    stats = get_summary_stats()

    print("[2/5] Fetching top attacking IPs...")
    attackers = get_top_attackers()

    print("[3/5] Fetching most targeted usernames...")
    targeted_users = get_top_targeted_users()

    print("[4/5] Fetching most targeted servers...")
    targeted_servers = get_top_targeted_servers()

    print("[5/5] Fetching recent DDoS incidents...")
    ddos_incidents = get_ddos_incidents()

    print("\nBuilding report...")
    report = build_report(stats, attackers, targeted_users, targeted_servers, ddos_incidents)

    filename = datetime.datetime.now().strftime("security_report_%Y-%m-%d_%H-%M.txt")
    filepath = os.path.join(REPORTS_DIR, filename)
    with open(filepath, "w") as f:
        f.write(report)

    print(f"\nReport saved: {filepath}")
    print("\n" + "=" * 55)
    print(report)


if __name__ == "__main__":
    main()
