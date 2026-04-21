# 🪞 ISP Spy Mirror

> See exactly what your ISP can observe about your network traffic — in real time.

An educational network intelligence tool that captures your own outbound traffic
and displays what your Internet Service Provider sees about you. Runs entirely on
your own machine, analyzes only your own packets, sends nothing anywhere.

---

## ✨ Features

### 🔍 Traffic Analysis
- DNS Queries — Every domain your machine looks up
- TLS/SNI — HTTPS destinations visible to ISP even with encryption
- HTTP Requests — Full URLs, headers, user agents on plaintext connections
- Connection Metadata — IPs, ports, protocols, packet sizes

### 🧠 Intelligence
- Device Fingerprinting — OS, browser, device type from TCP stack + JA3 hashes
- Behavioral Profiling — Activity patterns, interests, sleep schedule inference
- Tracker Mapping — Identifies 50+ ad networks, data brokers, analytics companies
- VPN Leak Detection — DNS leaks and traffic escaping your VPN tunnel

### 🔐 Security
- Sensitive Data Detection — Plaintext passwords, tokens, cookies, API keys
- DNS Spoof Detection — TTL anomalies, cross-verification against trusted resolvers
- Credential Leak Alerts — FTP, SMTP, HTTP Basic Auth in plaintext

### 📊 Reports (all saved locally)
- Live Terminal Dashboard — Rich UI with bandwidth graph and intelligence panels
- Session Log — Human-readable .log file
- JSON Data — Structured .json for programmatic analysis
- SQLite Database — Cross-session history and queries
- PCAP Export — Open in Wireshark
- ISP Dossier — JSON report showing what ISPs could sell to data brokers
- HTML Report — Interactive charts and full session breakdown

---

## 🚀 Installation

### Requirements
- Kali Linux (or any Linux with root access)
- Python 3.10+
- Root/sudo privileges (required for packet capture)

### Install

git clone https://github.com/Abdullah-Al-Raju/isp-spy-mirror.git
cd isp-spy-mirror
pip install -r requirements.txt

---

## 🎯 Usage

sudo python main.py                   # Auto-detect interface
sudo python main.py -i eth0           # Specify interface
sudo python main.py -d 300            # Capture for 5 minutes
sudo python main.py --show-all        # Show all traffic
sudo python main.py --no-geo          # Disable geo lookups
sudo python main.py -o mysession.log  # Custom log file

---

## 📁 Output Files

Every session generates:

| File | Description |
|------|-------------|
| isp_spy_session_TIMESTAMP.log | Human-readable traffic log |
| isp_spy_session_TIMESTAMP.json | Structured JSON session data |
| isp_spy.db | SQLite database (all sessions) |
| reports/pcaps/capture_TIMESTAMP.pcap | Wireshark-compatible capture |
| reports/dossiers/dossier_TIMESTAMP.json | ISP intelligence dossier |
| reports/html/report_TIMESTAMP.html | Interactive HTML report |

---

## 🗂 Project Structure

isp_spy_mirror/
├── main.py                     # Entry point
├── capture.py                  # Packet capture engine
├── analyzers/
│   ├── dns_analyzer.py         # DNS query extraction
│   ├── http_analyzer.py        # Plaintext HTTP analysis
│   ├── tls_analyzer.py         # TLS/SNI extraction
│   ├── metadata_analyzer.py    # Connection metadata
│   ├── sensitive_detector.py   # Credential leak detection
│   ├── fingerprint_analyzer.py # Device fingerprinting + JA3
│   ├── tracker_analyzer.py     # Ad/tracker identification
│   ├── vpn_leak_detector.py    # VPN leak detection
│   ├── dns_spoof_detector.py   # DNS spoofing detection
│   └── behavior_analyzer.py    # Behavioral profiling
├── resolvers/
│   ├── hostname_resolver.py    # Reverse DNS with caching
│   └── geo_resolver.py         # IP geolocation
├── dashboard/
│   └── live_display.py         # Rich terminal dashboard
├── data/
│   └── database.py             # SQLite backend
├── reports/
│   ├── pcap_export.py          # PCAP file export
│   ├── dossier.py              # ISP dossier generator
│   └── html_report.py          # HTML report generator
├── logger/
│   └── session_logger.py       # Session file logger
└── utils/
    └── helpers.py              # Shared utilities

---

## 🔒 Privacy and Ethics

- Captures only your own traffic on your own machine
- No data sent anywhere — everything stays local
- Geo lookups use ip-api.com free tier (no account needed)
- All output files are gitignored — your traffic never gets pushed
- Never use on networks or traffic you do not own

---

## 🛠 Tech Stack

| Tool | Purpose |
|------|---------|
| Scapy | Packet capture and parsing |
| Rich | Terminal dashboard UI |
| Requests | Geo API calls |
| SQLite3 | Session database (built-in) |
| Chart.js | HTML report charts |

---

## ⚠ Legal Notice

This tool is for educational purposes only.
Run it only on your own machine and your own network traffic.
The author is not responsible for misuse.

---

## 📜 License

MIT License — free to use, modify, and distribute.
