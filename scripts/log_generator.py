#!/usr/bin/env python3
"""
Catnip Games SIEM - Log Generator
Simulates game server, player auth, and DDoS log events
Sends structured GELF messages to Graylog via UDP port 12201
"""

import socket
import json
import time
import random
import datetime
import struct
import zlib

# ─────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────
GRAYLOG_HOST = "127.0.0.1"
GRAYLOG_PORT = 12201

# Simulated infrastructure
GAME_SERVERS = [f"game-server-{i:02d}" for i in range(1, 11)]
DEV_SERVERS  = [f"dev-server-{i:02d}"  for i in range(1, 4)]

# Legitimate users — these build up baseline profiles
LEGIT_USERS = [
    "alice", "bob", "charlie", "diana",
    "eve", "frank", "grace", "henry"
]

# Legitimate IPs — regular engineers and players
LEGIT_IPS = [
    "192.168.1.10", "192.168.1.11", "192.168.1.12",
    "192.168.1.20", "192.168.1.21", "10.0.0.5",
    "10.0.0.6",     "10.0.0.7"
]

# Attacker IPs — these should trigger alerts and anomaly scores
ATTACKER_IPS = [
    "45.33.32.156",  "185.220.101.45", "103.21.244.0",
    "194.165.16.11", "91.108.4.0",     "198.199.88.0",
    "159.89.49.0",   "165.227.88.0"
]

# Player usernames for auth simulation
PLAYER_NAMES = [
    "ProGamer99", "ShadowBlade", "NightWolf", "CryptoKing",
    "PixelHunter", "StormRider", "DarkMatter", "IronFist",
    "GhostSniper", "ThunderBolt", "FireStorm", "IceQueen"
]

# ─────────────────────────────────────────
# GELF sender
# ─────────────────────────────────────────
def send_gelf(message: dict):
    """Send a GELF message to Graylog via UDP"""
    message.setdefault("version", "1.1")
    message.setdefault("host",    "catnip-simulator")

    payload = json.dumps(message).encode("utf-8")
    compressed = zlib.compress(payload)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(compressed, (GRAYLOG_HOST, GRAYLOG_PORT))
    finally:
        sock.close()

# ─────────────────────────────────────────
# Event generators
# ─────────────────────────────────────────
def generate_player_auth_success():
    """Simulate a legitimate player login"""
    player   = random.choice(PLAYER_NAMES)
    source   = random.choice(LEGIT_IPS)
    server   = random.choice(GAME_SERVERS)
    send_gelf({
        "short_message": f"Player login successful: {player}",
        "event_type":    "player_auth",
        "action":        "login_success",
        "username":      player,
        "source_ip":     source,
        "server_id":     server,
        "severity":      "info",
        "level":         6
    })
    print(f"[AUTH SUCCESS] {player} from {source}")


def generate_player_auth_failure():
    """Simulate a failed player login — could be credential stuffing"""
    player  = random.choice(PLAYER_NAMES)
    # 70% chance attacker IP, 30% legit (mistyped password)
    source  = random.choice(ATTACKER_IPS if random.random() < 0.7 else LEGIT_IPS)
    server  = random.choice(GAME_SERVERS)
    send_gelf({
        "short_message": f"Player login failed: {player}",
        "event_type":    "player_auth",
        "action":        "login_failed",
        "username":      player,
        "source_ip":     source,
        "server_id":     server,
        "severity":      "warning",
        "level":         4
    })
    print(f"[AUTH FAILED]  {player} from {source}")


def generate_game_traffic_normal():
    """Simulate normal game server traffic"""
    server       = random.choice(GAME_SERVERS)
    player_count = random.randint(50, 800)
    traffic_mbps = round(random.uniform(10, 200), 2)
    send_gelf({
        "short_message": f"Normal traffic on {server}",
        "event_type":    "game_traffic",
        "action":        "normal",
        "server_id":     server,
        "player_count":  player_count,
        "traffic_mbps":  traffic_mbps,
        "severity":      "info",
        "level":         6
    })
    print(f"[TRAFFIC OK]   {server} — {player_count} players, {traffic_mbps} Mbps")


def generate_ddos_attack():
    """Simulate a DDoS attack against a game server"""
    server       = random.choice(GAME_SERVERS)
    source       = random.choice(ATTACKER_IPS)
    traffic_mbps = round(random.uniform(5000, 15000), 2)
    player_count = random.randint(0, 20)
    send_gelf({
        "short_message": f"DDoS attack detected on {server}",
        "event_type":    "game_traffic",
        "action":        "ddos_detected",
        "source_ip":     source,
        "server_id":     server,
        "player_count":  player_count,
        "traffic_mbps":  traffic_mbps,
        "severity":      "critical",
        "level":         2
    })
    print(f"[DDOS]         {server} — {traffic_mbps} Mbps from {source}")


def generate_dev_ssh_normal():
    """Simulate normal engineer SSH login to dev server"""
    user   = random.choice(LEGIT_USERS)
    source = random.choice(LEGIT_IPS)
    server = random.choice(DEV_SERVERS)
    send_gelf({
        "short_message": f"SSH login successful: {user} on {server}",
        "event_type":    "dev_ssh",
        "action":        "login_success",
        "username":      user,
        "source_ip":     source,
        "server_id":     server,
        "severity":      "info",
        "level":         6
    })
    print(f"[DEV SSH OK]   {user} from {source} to {server}")


def generate_dev_ssh_suspicious():
    """Simulate suspicious SSH activity on dev server"""
    user   = random.choice(LEGIT_USERS)
    source = random.choice(ATTACKER_IPS)
    server = random.choice(DEV_SERVERS)
    send_gelf({
        "short_message": f"Suspicious SSH login: {user} on {server}",
        "event_type":    "dev_ssh",
        "action":        "suspicious_login",
        "username":      user,
        "source_ip":     source,
        "server_id":     server,
        "severity":      "critical",
        "level":         2
    })
    print(f"[DEV SSH WARN] {user} from {source} to {server} — SUSPICIOUS")


def generate_credential_stuffing():
    """Simulate a credential stuffing burst against player accounts"""
    source = random.choice(ATTACKER_IPS)
    server = random.choice(GAME_SERVERS)
    count  = random.randint(10, 50)
    for _ in range(count):
        player = random.choice(PLAYER_NAMES)
        send_gelf({
            "short_message": f"Credential stuffing attempt: {player}",
            "event_type":    "player_auth",
            "action":        "credential_stuffing",
            "username":      player,
            "source_ip":     source,
            "server_id":     server,
            "severity":      "critical",
            "level":         2
        })
    print(f"[CRED STUFF]   {count} attempts from {source}")

# ─────────────────────────────────────────
# Main simulation loop
# ─────────────────────────────────────────
def run():
    print("=" * 55)
    print("  Catnip Games SIEM - Log Generator")
    print(f"  Sending to {GRAYLOG_HOST}:{GRAYLOG_PORT}")
    print("  Press Ctrl+C to stop")
    print("=" * 55)

    event_count = 0

    while True:
        hour = datetime.datetime.now().hour

        # Daytime (8am-10pm): busy — more events
        if 8 <= hour <= 22:
            weights = [30, 15, 25, 5, 15, 3, 7]
        else:
            # Night: quieter — attackers more active
            weights = [10, 25, 15, 15, 10, 15, 10]

        events = [
            generate_player_auth_success,
            generate_player_auth_failure,
            generate_game_traffic_normal,
            generate_ddos_attack,
            generate_dev_ssh_normal,
            generate_dev_ssh_suspicious,
            generate_credential_stuffing
        ]

        chosen = random.choices(events, weights=weights, k=1)[0]
        chosen()

        event_count += 1
        if event_count % 20 == 0:
            print(f"\n  [{event_count} events sent]\n")

        time.sleep(random.uniform(0.5, 2.0))


if __name__ == "__main__":
    run()
