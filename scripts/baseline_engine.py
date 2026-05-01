#!/usr/bin/env python3
"""
Catnip Games SIEM - Behavioural Baseline Engine
================================================
Profiles normal login behaviour per user and flags anomalous activity
that threshold-based alerts would miss.

How it works:
1. Polls Graylog every 60 seconds for recent auth events
2. Builds a behavioural profile per username (hours, IPs, fail rates)
3. Scores each new login event against the profile (0-100)
4. Logs anomalies to console and writes them to anomalies.json
5. Sends high-severity anomalies back to Graylog as GELF alerts

Author: Adebowale Adesanya
"""

import os
import json
import time
import socket
import logging
from datetime import datetime, timezone
from collections import defaultdict, deque
from requests.auth import HTTPBasicAuth
import requests

# ─────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────
GRAYLOG_URL      = "http://127.0.0.1:9000"
GRAYLOG_USER     = "admin"
GRAYLOG_PASS     = os.environ.get("GRAYLOG_PASS", "CatnipAdmin@2026")
GELF_HOST        = "127.0.0.1"
GELF_PORT        = 12201
POLL_INTERVAL    = 60          # seconds between Graylog polls
PROFILE_WINDOW   = 3600 * 24  # 24 hours of history per user
OUTPUT_FILE      = os.path.join(os.path.dirname(__file__), "..", "logs", "anomalies.json")

# Anomaly score thresholds
SCORE_WATCH      = 31   # worth watching
SCORE_ALERT      = 61   # anomalous — send alert

HEADERS = {
    "Content-Type":   "application/json",
    "Accept":         "application/json",
    "X-Requested-By": "catnip-baseline"
}

# ─────────────────────────────────────────
# Logging setup
# ─────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("baseline")


# ─────────────────────────────────────────
# User Profile
# ─────────────────────────────────────────
class UserProfile:
    """
    Tracks behavioural patterns for a single username.
    Uses a sliding window of recent events to build the profile.
    """

    def __init__(self, username):
        self.username      = username
        self.login_hours   = defaultdict(int)   # hour → count
        self.known_ips     = defaultdict(int)   # ip → count
        self.fail_counts   = deque(maxlen=100)  # recent failed attempt counts
        self.total_events  = 0
        self.first_seen    = datetime.now(timezone.utc)
        self.last_seen     = datetime.now(timezone.utc)

    def update(self, event):
        """Ingest a new event into the profile."""
        self.total_events += 1
        self.last_seen = datetime.now(timezone.utc)

        # Track login hour
        ts = event.get("timestamp", "")
        if ts:
            try:
                hour = datetime.fromisoformat(ts.replace("Z", "+00:00")).hour
                self.login_hours[hour] += 1
            except Exception:
                pass

        # Track source IP
        ip = event.get("source_ip", "")
        if ip:
            self.known_ips[ip] += 1

        # Track failed attempts
        if event.get("action", "") in ("failed", "login_failed"):
            self.fail_counts.append(1)
        else:
            self.fail_counts.append(0)

    def is_mature(self):
        """Profile needs at least 10 events to be meaningful."""
        return self.total_events >= 10

    def normal_hours(self):
        """Return set of hours with at least 2 logins."""
        return {h for h, c in self.login_hours.items() if c >= 2}

    def normal_ips(self):
        """Return set of IPs seen at least twice."""
        return {ip for ip, c in self.known_ips.items() if c >= 2}

    def avg_fail_rate(self):
        """Return average failed login rate (0.0 to 1.0)."""
        if not self.fail_counts:
            return 0.0
        return sum(self.fail_counts) / len(self.fail_counts)


# ─────────────────────────────────────────
# Anomaly Scorer
# ─────────────────────────────────────────
class AnomalyScorer:
    """
    Scores a login event against a user's profile.
    Returns a score from 0-100 and a list of reasons.
    """

    def score(self, event, profile):
        if not profile.is_mature():
            return 0, ["profile not mature enough — need 10+ events"]

        score   = 0
        reasons = []

        # ── Factor 1: Unusual hour (max 30 points) ──
        ts = event.get("timestamp", "")
        if ts:
            try:
                hour = datetime.fromisoformat(ts.replace("Z", "+00:00")).hour
                normal_hours = profile.normal_hours()
                if normal_hours and hour not in normal_hours:
                    score += 30
                    reasons.append(
                        f"login at unusual hour {hour:02d}:00 "
                        f"(normal hours: {sorted(normal_hours)})"
                    )
            except Exception:
                pass

        # ── Factor 2: Unknown source IP (max 35 points) ──
        ip = event.get("source_ip", "")
        if ip:
            normal_ips = profile.normal_ips()
            if normal_ips and ip not in normal_ips:
                score += 35
                reasons.append(
                    f"login from new IP {ip} "
                    f"(known IPs: {sorted(normal_ips)})"
                )

        # ── Factor 3: Elevated failure rate (max 35 points) ──
        action = event.get("action", "")
        if action in ("failed", "login_failed"):
            avg_fail = profile.avg_fail_rate()
            if avg_fail < 0.1:
                # User almost never fails — this is suspicious
                score += 35
                reasons.append(
                    f"failed login for user with {avg_fail:.0%} historical fail rate"
                )
            elif avg_fail < 0.3:
                score += 15
                reasons.append(
                    f"failed login for user with {avg_fail:.0%} historical fail rate"
                )

        return min(score, 100), reasons


# ─────────────────────────────────────────
# Graylog Interface
# ─────────────────────────────────────────
def fetch_events(since_seconds=120):
    """Fetch recent auth events from Graylog 6.x API."""
    try:
        body = {
            "query":     "event_type:player_auth OR event_type:sshd OR event_type:dev_ssh",
            "timerange": {"type": "relative", "range": since_seconds},
            "fields":    ["username", "source_ip", "action", "event_type", "timestamp"],
            "size":      1000
        }
        resp = requests.post(
            f"{GRAYLOG_URL}/api/search/messages",
            headers=HEADERS,
            auth=HTTPBasicAuth(GRAYLOG_USER, GRAYLOG_PASS),
            json=body,
            timeout=10
        )
        resp.raise_for_status()
        data   = resp.json()
        schema = [col["field"] for col in data.get("schema", [])]
        rows   = data.get("datarows", [])
        return [dict(zip(schema, row)) for row in rows]
    except Exception as e:
        log.warning(f"Graylog query failed: {e}")
        return []


def send_gelf_alert(username, score, reasons, event):
    """Send anomaly alert back to Graylog via GELF UDP."""
    try:
        payload = {
            "version":      "1.1",
            "host":         "baseline-engine",
            "short_message": f"Behavioural anomaly detected for user: {username}",
            "full_message":  "\n".join(reasons),
            "level":         3,  # ERROR
            "_username":     username,
            "_anomaly_score": score,
            "_source_ip":    event.get("source_ip", ""),
            "_event_type":   event.get("event_type", ""),
            "_action":       event.get("action", ""),
            "_reasons":      " | ".join(reasons),
            "_alert_type":   "behavioural_anomaly"
        }
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(json.dumps(payload).encode(), (GELF_HOST, GELF_PORT))
        sock.close()
    except Exception as e:
        log.warning(f"Failed to send GELF alert: {e}")


def save_anomaly(username, score, reasons, event):
    """Append anomaly to the anomalies.json log file."""
    anomaly = {
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "username":      username,
        "score":         score,
        "severity":      "HIGH" if score >= SCORE_ALERT else "MEDIUM",
        "reasons":       reasons,
        "source_ip":     event.get("source_ip", ""),
        "event_type":    event.get("event_type", ""),
        "action":        event.get("action", "")
    }

    # Load existing anomalies
    existing = []
    try:
        with open(OUTPUT_FILE, "r") as f:
            existing = json.load(f)
    except Exception:
        pass

    existing.append(anomaly)

    # Keep last 1000 anomalies
    if len(existing) > 1000:
        existing = existing[-1000:]

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(existing, f, indent=2)


# ─────────────────────────────────────────
# Main Engine
# ─────────────────────────────────────────
class BaselineEngine:

    def __init__(self):
        self.profiles    = {}   # username → UserProfile
        self.scorer      = AnomalyScorer()
        self.seen_events = set()  # deduplicate events
        self.anomaly_count = 0

    def get_or_create_profile(self, username):
        if username not in self.profiles:
            self.profiles[username] = UserProfile(username)
        return self.profiles[username]

    def process_events(self, events):
        new_anomalies = 0

        for event in events:
            username = event.get("username", "")
            if not username or username in ("", "unknown", "null"):
                continue

            # Deduplicate using username+timestamp+ip
            event_key = f"{username}:{event.get('timestamp','')}:{event.get('source_ip','')}"
            if event_key in self.seen_events:
                continue
            self.seen_events.add(event_key)

            # Keep seen_events set bounded
            if len(self.seen_events) > 10000:
                self.seen_events = set(list(self.seen_events)[-5000:])

            profile = self.get_or_create_profile(username)

            # Score BEFORE updating profile (score against historical behaviour)
            score, reasons = self.scorer.score(event, profile)

            # Now update the profile with this event
            profile.update(event)

            # Handle anomalies
            if score >= SCORE_WATCH:
                self.anomaly_count += 1
                new_anomalies += 1
                severity = "HIGH" if score >= SCORE_ALERT else "MEDIUM"

                log.warning(
                    f"[{severity}] Anomaly for '{username}' "
                    f"score={score}/100 | {' | '.join(reasons)}"
                )

                save_anomaly(username, score, reasons, event)

                if score >= SCORE_ALERT:
                    send_gelf_alert(username, score, reasons, event)

        return new_anomalies

    def print_status(self):
        log.info(
            f"Profiles tracked: {len(self.profiles)} users | "
            f"Total anomalies detected: {self.anomaly_count}"
        )
        for username, profile in sorted(self.profiles.items()):
            if profile.is_mature():
                log.info(
                    f"  {username}: {profile.total_events} events | "
                    f"normal hours={sorted(profile.normal_hours())} | "
                    f"known IPs={sorted(profile.normal_ips())} | "
                    f"fail rate={profile.avg_fail_rate():.0%}"
                )

    def run(self):
        log.info("=" * 60)
        log.info("  Catnip Games SIEM - Behavioural Baseline Engine")
        log.info("=" * 60)
        log.info(f"  Polling Graylog every {POLL_INTERVAL} seconds")
        log.info(f"  Anomaly threshold: MEDIUM={SCORE_WATCH}+, HIGH={SCORE_ALERT}+")
        log.info(f"  Anomaly log: {OUTPUT_FILE}")
        log.info("=" * 60)

        # Initial bootstrap — fetch last 24 hours to build profiles
        log.info("Building initial user profiles from last 24 hours...")
        initial_events = fetch_events(since_seconds=86400)
        log.info(f"Loaded {len(initial_events)} historical events")

        for event in initial_events:
            username = event.get("username", "")
            if username:
                profile = self.get_or_create_profile(username)
                profile.update(event)

        log.info(f"Profiles built for {len(self.profiles)} users:")
        for username, profile in sorted(self.profiles.items()):
            log.info(
                f"  {username}: {profile.total_events} events | "
                f"mature={profile.is_mature()}"
            )

        log.info("Now monitoring for anomalies...")
        log.info("-" * 60)

        cycle = 0
        while True:
            time.sleep(POLL_INTERVAL)
            cycle += 1

            events = fetch_events(since_seconds=POLL_INTERVAL + 10)
            if events:
                new_anomalies = self.process_events(events)
                log.info(
                    f"Cycle {cycle}: {len(events)} events processed, "
                    f"{new_anomalies} anomalies detected"
                )
            else:
                log.info(f"Cycle {cycle}: no new events")

            # Print full status every 10 cycles
            if cycle % 10 == 0:
                self.print_status()


# ─────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────
if __name__ == "__main__":
    engine = BaselineEngine()
    try:
        engine.run()
    except KeyboardInterrupt:
        log.info("Baseline engine stopped.")
        engine.print_status()
