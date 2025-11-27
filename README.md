🚨 NetGuard – Automated Network Security Scanner & Vulnerability Monitor
Enterprise-grade security monitoring platform built with Python.
Performs deep port scanning, CVE detection, historical tracking, scheduling, and real-time security alerts.

🌐 Overview
NetGuard is a powerful, fully automated network security scanning and monitoring tool designed for both home labs and enterprise-grade environments.
It combines multi-threaded scanning, dual-mode CVE detection, historical analysis, and email alerts into one complete security platform.

It’s essentially a lightweight alternative to tools like Nessus, OpenVAS, and Qualys — but built from scratch.

🔥 Features
🛰️ 1. Core Network Scanner
Multi-threaded port scanning (up to 100 threads)
Service detection & banner grabbing
TTL-based OS fingerprinting
Weak configuration testing:
Anonymous FTP
Missing security headers
Support for single IPs, ranges, and CIDR
Scan modes:
Fast (16 ports)
Full (1024 ports)
Custom mode

🧠 2. Dual CVE Detection System
Local CVE database (~30 curated vulnerabilities)
Live NIST NVD API integration (200K+ CVEs)
Smart caching layer to reduce API calls
CVSS scoring & severity classification
Automatic version extraction from banners
Detection modes:
Local-only
API-enhanced
Smart mode (both)

🗓️ 3. Automated Scheduling System
Daily, weekly, or monthly scan scheduling
Multiple concurrent schedules
Background service operation
JSON-based configuration management
Add / remove / enable / disable schedules
Timestamped output files

🗄️ 4. Historical Tracking Database
SQLite database for scan history
Tracks hosts, services, and discovered CVEs
Detects changes between scans
Security trend analysis over time
Automatic retention & cleanup features

📧 5. Email Notification Engine
Interactive setup wizard (setup_email.py)
Supports Gmail, Outlook, Yahoo, custom SMTP
Instant alerts for:
Critical CVEs
Network/host changes
Scan failures
Weekly summaries
HTML-formatted emails with tables + colors
SSL certificate bypass for corporate networks

📊 6. Professional Reporting
Interactive HTML reports (Chart.js visualizations)
JSON export for API integrations
CSV export for spreadsheets
Executive dashboards
Color-coded severity indicators
Timestamped reports


🎥 Demo Video

Here’s a full demonstration of NetGuard scanning a network, detecting vulnerabilities, generating reports, and sending security alerts:

https://www.youtube.com/watch?v=APRyghfkTjo


📧 Email Notification Example

![NetGuard Gmail Notification](screenshots/gmail.png)


📁 Project Structure
netguard/
│── main.py                 # Main orchestrator (CLI)
│── scanner.py              # Port scanning engine
│── cve_checker.py          # CVE detection module
│── database.py             # SQLite historical tracking
│── scheduler.py            # Automated scan scheduler
│── notifications.py        # Email alerts engine
│── report.py               # HTML / JSON / CSV reporting
│── utils.py                # Helper functions
│── setup_email.py          # Email configuration wizard
│
├── data/
│   ├── cves.json
│   ├── api_cache.json
│   └── scan_history.db
│
├── config/
│   ├── email_config.json
│   └── scheduler_config.json
│
├── reports/                # Generated reports
├── logs/                   # Application logs
├── screenshots/            # Saved demo screenshots
│
└── requirements.txt



🛠️ Installation
git clone https://github.com/safimousa123/NetGuard.git
cd NetGuard
pip install -r requirements.txt



🚀 Usage
Run a scan:
python3 main.py --range 192.168.1.0/24 --mode fast --use-api

Enable scheduling:
python3 scheduler.py --add-weekly --network "192.168.1.0/24"
python3 scheduler.py --start

Configure email alerts:
python3 setup_email.py


🧩 Future Enhancements
Web dashboard (Flask or FastAPI)
AD / LDAP enumeration
SNMP device detection
Plugin architecture
Docker container version
Multi-host parallel scanning


⭐ Final Notes
If you like the project, give it a star ⭐ on GitHub!
This project represents serious work in Cyber Security, Network Engineering, Automation, and Software Development — perfect for your portfolio and CV.


















































