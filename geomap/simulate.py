import socket
import time
import random

# Realistic international IPs that geolocate to different countries
ips = [
    '185.220.101.1',   # Germany
    '185.220.101.5',   # Germany
    '91.108.4.1',      # Russia
    '91.108.4.15',     # Russia
    '103.86.96.1',     # China
    '103.86.96.20',    # China
    '45.142.212.1',    # Netherlands
    '45.142.212.10',   # Netherlands
    '187.33.208.1',    # Brazil
    '41.223.56.1',     # Africa
    '202.12.29.1',     # Japan
    '196.207.40.1',    # Kenya
    '89.248.167.1',    # Netherlands
    '193.32.162.1',    # Russia
    '171.25.193.1',    # Sweden
    '199.195.250.1',   # USA
]

def send_log(ip, attempt_num):
    msg = (f'<134>Apr 14 12:00:{attempt_num:02d} '
           f'sshd[1234]: Failed password for root '
           f'from {ip} port 22 ssh2')
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(msg.encode(), ('127.0.0.1', 1514))
    sock.close()

print("[*] Starting attack simulation...")
print("[*] Sending logs to Graylog — map will update within 15 seconds\n")

attempt = 0
round_num = 1

while True:
    print(f"[*] Round {round_num} — sending {len(ips)} attack logs...")
    for ip in ips:
        send_log(ip, attempt % 60)
        attempt += 1
        time.sleep(0.2)  # small delay between each log
    print(f"[✓] Round {round_num} done — waiting 30 seconds before next wave...")
    print(f"    Check your map at http://127.0.0.1:8888\n")
    round_num += 1
    time.sleep(30)  # send a new wave every 30 seconds
