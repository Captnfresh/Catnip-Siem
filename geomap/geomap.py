#!/usr/bin/env python3
"""
Catnip Games SIEM - Live IP Geolocation Attack Map
Polls Graylog 6.x API, geolocates attacker IPs via ip-api.com,
and serves a live dark-themed world map on port 8888.
Author: Akhamas Balouch
"""

import os
import json
import time
import threading
import requests
from pathlib import Path
from flask import Flask, send_file, jsonify
from requests.auth import HTTPBasicAuth

def _read_env(key: str, default: str = "") -> str:
    """Read a value from .env file, falling back to environment variables."""
    env_file = Path(__file__).resolve().parents[1] / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip().rstrip("\r")
            if line.startswith(f"{key}=") and not line.startswith("#"):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return os.environ.get(key, default)

GRAYLOG_URL   = "http://127.0.0.1:9000"
GRAYLOG_USER  = "admin"
GRAYLOG_PASS  = _read_env("GRAYLOG_ADMIN_PASSWORD") or _read_env("GRAYLOG_PASSWORD")
POLL_INTERVAL = 15
OUTPUT_FILE   = os.path.join(os.path.dirname(__file__), "attacks.json")

HEADERS = {
    "Content-Type":   "application/json",
    "Accept":         "application/json",
    "X-Requested-By": "catnip-geomap"
}

app = Flask(__name__)

def get_recent_attacks():
    try:
        body = {
            "query":     "action:failed OR action:login_failed OR action:credential_stuffing OR action:suspicious_login",
            "timerange": {"type": "relative", "range": 3600},
            "fields":    ["source_ip", "event_type", "action", "username"],
            "size":      500
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
        print(f"[!] Graylog query failed: {e}")
        return []

def is_public_ip(ip):
    if not ip:
        return False
    return not (
        ip.startswith("10.")      or
        ip.startswith("172.")     or
        ip.startswith("192.168.") or
        ip.startswith("127.")     or
        ip.startswith("0.")
    )

def geolocate(ip):
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,lat,lon,country,city",
            timeout=5
        )
        d = r.json()
        if d.get("status") == "success":
            return d
    except Exception:
        pass
    return None

def poll_and_update():
    geo_cache = {}
    while True:
        print("[*] Polling Graylog...")
        messages = get_recent_attacks()
        print(f"[*] Got {len(messages)} attack messages")

        ip_counts = {}
        ip_meta   = {}

        for msg in messages:
            ip         = msg.get("source_ip", "")
            event_type = msg.get("event_type", "unknown")
            if not is_public_ip(ip):
                continue
            if ip not in ip_counts:
                ip_counts[ip] = 0
                ip_meta[ip]   = event_type
            ip_counts[ip] += 1

        points = []
        for ip, count in ip_counts.items():
            if ip not in geo_cache:
                geo = geolocate(ip)
                if geo:
                    geo_cache[ip] = geo
                    print(f"  [{ip}] -> {geo.get('city')}, {geo.get('country')}")
                else:
                    continue
            geo = geo_cache[ip]
            points.append({
                "ip":         ip,
                "lat":        geo["lat"],
                "lon":        geo["lon"],
                "country":    geo.get("country", "Unknown"),
                "city":       geo.get("city", "Unknown"),
                "count":      count,
                "event_type": ip_meta.get(ip, "unknown")
            })

        with open(OUTPUT_FILE, "w") as f:
            json.dump(points, f)

        print(f"[OK] {len(points)} attack sources mapped.")
        time.sleep(POLL_INTERVAL)

@app.route("/")
def index():
    return send_file(os.path.join(os.path.dirname(__file__), "map.html"))

@app.route("/attacks.json")
def attacks():
    try:
        return send_file(OUTPUT_FILE)
    except Exception:
        return jsonify([])

if __name__ == "__main__":
    if not os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, "w") as f:
            json.dump([], f)
    t = threading.Thread(target=poll_and_update, daemon=True)
    t.start()
    print("=============================================================")
    print("  Catnip Games SIEM - Live IP Attack Map")
    print("=============================================================")
    print("  Map available at: http://127.0.0.1:8888")
    print(f"  Polling Graylog every {POLL_INTERVAL} seconds")
    print("  Press Ctrl+C to stop")
    print("=============================================================")
    app.run(port=8888, debug=False)
