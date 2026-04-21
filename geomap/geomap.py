import requests, json, time, re
from flask import Flask, send_file, jsonify

import requests, json, time, re
from flask import Flask, send_file, jsonify

GRAYLOG_URL   = "http://127.0.0.1:9000"
GRAYLOG_USER  = "admin"
GRAYLOG_PASS  = "CatnipAdmin@2026"   # ← your actual password
POLL_INTERVAL = 15
OUTPUT_FILE   = "attacks.json"

app = Flask(__name__)

def get_recent_attacks():
    try:
        resp = requests.get(
            f"{GRAYLOG_URL}/api/search/universal/relative",
            params={
                "query": 'action:failed OR action:login_failed OR event_type:ssh_brute OR event_type:credential_stuffing',
                "range": 3600,
                "limit": 100
            },
            auth=(GRAYLOG_USER, GRAYLOG_PASS),
            headers={"Accept": "application/json"},
            timeout=5
        )
        return resp.json().get("messages", [])
    except Exception as e:
        print(f"[!] Graylog query failed: {e}")
        return []

def is_public_ip(ip):
    if not ip:
        return False
    return not (ip.startswith("10.") or
                ip.startswith("172.") or
                ip.startswith("192.168.") or
                ip.startswith("127."))

def extract_ip(msg_obj):
    # source_ip is the most reliable field in Catnip logs
    ip = msg_obj.get("source_ip", "")
    if is_public_ip(ip):
        return ip
    # fallback to regex on message text
    txt = msg_obj.get("message", "")
    m = re.search(r'from (\d+\.\d+\.\d+\.\d+)', txt)
    if m and is_public_ip(m.group(1)):
        return m.group(1)
    return None

def geolocate(ip):
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,lat,lon,country,city",
            timeout=5)
        d = r.json()
        if d.get("status") == "success":
            return d
    except:
        pass
    return None

def poll_and_update():
    seen = {}
    while True:
        print("[*] Polling Graylog...")
        points = []
        messages = get_recent_attacks()
        print(f"[*] Got {len(messages)} attack messages")
        for m in messages:
            msg_obj = m.get("message", {})
            ip = extract_ip(msg_obj)
            if not ip:
                continue
            if ip not in seen:
                geo = geolocate(ip)
                if geo:
                    seen[ip] = {
                        "ip": ip,
                        "lat": geo["lat"],
                        "lon": geo["lon"],
                        "country": geo.get("country", "?"),
                        "city": geo.get("city", "?"),
                        "count": 1,
                        "event_type": msg_obj.get("event_type", "unknown")
                    }
                    print(f"  [{ip}] -> {seen[ip]['city']}, {seen[ip]['country']}")
            else:
                seen[ip]["count"] += 1
            if ip in seen:
                points.append(seen[ip])
        with open(OUTPUT_FILE, "w") as f:
            json.dump(points, f)
        print(f"[✓] {len(points)} points written.")
        time.sleep(POLL_INTERVAL)

@app.route("/")
def index():
    return send_file("map.html")

@app.route("/attacks.json")
def attacks():
    try:
        return send_file(OUTPUT_FILE)
    except:
        return jsonify([])

if __name__ == "__main__":
    import threading
    t = threading.Thread(target=poll_and_update, daemon=True)
    t.start()
    print("[*] Map available at http://127.0.0.1:8888")
    app.run(port=8888)
