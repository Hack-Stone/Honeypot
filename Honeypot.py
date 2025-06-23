import socket
import datetime
import json
import requests
import re
import sqlite3
import os
from termcolor import colored

# Config
HOST = '0.0.0.0'
PORT = 9999
JSON_LOG_FILE = 'honeypot_logs.json'
DB_FILE = 'honeypot_logs.db'
WHITELIST_IPS = []
BLACKLIST_IPS = []

SUSPICIOUS_PATTERNS = [
    r"(select|union|insert|drop|delete|update).*",
    r"(cmd|powershell|bash|sh).*",
    r"(\.\./|\%2e\%2e/)",
    r"(wget|curl|nc|ncat|telnet).*",
]

# Ensure DB
def setup_db():
    if not os.path.exists(DB_FILE):
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''CREATE TABLE logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip TEXT,
            port INTEGER,
            data TEXT,
            country TEXT,
            city TEXT,
            org TEXT,
            suspicious INTEGER
        )''')
        conn.commit()
        conn.close()

# Get IP Geolocation
def get_geo(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}").json()
        return {
            "country": res.get("country", "N/A"),
            "city": res.get("city", "N/A"),
            "org": res.get("org", "N/A")
        }
    except:
        return {"country": "N/A", "city": "N/A", "org": "N/A"}

# Check for suspicious data
def is_suspicious(data):
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, data, re.IGNORECASE):
            return True
    return False

# Fake response for attackers
def send_fake_response(client_socket):
    try:
        fake = "[root@honeypot /]$ command not found\n"
        client_socket.send(fake.encode())
    except:
        pass

# Log to JSON and SQLite
def log_event(addr, data, geo, suspicious):
    log_entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "ip": addr[0],
        "port": addr[1],
        "data": data,
        "geo": geo,
        "suspicious": suspicious
    }

    with open(JSON_LOG_FILE, 'a') as f:
        f.write(json.dumps(log_entry) + '\n')

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO logs (timestamp, ip, port, data, country, city, org, suspicious) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
              (log_entry["timestamp"], addr[0], addr[1], data, geo["country"], geo["city"], geo["org"], int(suspicious)))
    conn.commit()
    conn.close()

# Honeypot Server
def start_honeypot():
    setup_db()
    print(colored(f"\n[STARTED] Honeypot listening on {HOST}:{PORT}", "green"))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((HOST, PORT))
        server.listen(10)

        while True:
            client, addr = server.accept()

            if addr[0] in BLACKLIST_IPS:
                print(colored(f"[BLOCKED] Connection from blacklisted IP {addr[0]}", "red"))
                client.close()
                continue
            elif addr[0] in WHITELIST_IPS:
                print(colored(f"[IGNORED] Whitelisted IP {addr[0]}", "cyan"))
                client.close()
                continue

            try:
                data = client.recv(2048).decode(errors='ignore').strip()
                geo = get_geo(addr[0])
                suspicious = is_suspicious(data)
                log_event(addr, data, geo, suspicious)

                print(colored(f"\n[NEW] {addr[0]}:{addr[1]}", "blue"))
                print(colored(f" ↳ Location: {geo['city']}, {geo['country']} | Org: {geo['org']}", "yellow"))
                print(colored(f" ↳ Data: {data}", "green"))
                if suspicious:
                    print(colored(" ⚠ Suspicious activity detected!", "red", attrs=["bold"]))
                    send_fake_response(client)

            except Exception as e:
                print(colored(f"[ERROR] {e}", "red"))

            finally:
                client.close()

if __name__ == "__main__":
    start_honeypot()