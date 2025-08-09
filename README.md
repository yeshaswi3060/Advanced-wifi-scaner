@"
# 📡 Advanced WiFi Scanner & Monitor (WiFi-Monitor-Pro-V2)

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-success.svg)]()

A professional-grade WiFi monitoring and scanning tool with **Intrusion Detection System (IDS)**, **traffic analysis**, and a **modern web-based dashboard**.  
Ideal for network administrators, penetration testers, and cybersecurity researchers.

---

## ✨ Features
- 🔍 **Intrusion Detection (IDS)** — Detects unusual WiFi activity in real time.
- 📡 **Packet Sniffer** — Captures and analyzes WiFi packets.
- 🖥 **Device Discovery** — Identifies connected devices on the network.
- 📊 **Traffic Monitoring** — Real-time and historical traffic stats.
- 📝 **Report Generation** — Exportable network activity reports.
- 🌐 **Web Dashboard** — Responsive and clean web interface.

---

## 📂 Project Structure
\`\`\`
core/        # Core database, models, and utilities
data/        # SQLite database file
monitor/     # IDS and sniffer modules
reports/     # Reporting engine
scanners/    # Device discovery scripts
web/         # Static files and HTML templates
app.py       # Application entry point
config.py    # Configuration settings
requirements.txt  # Python dependencies
\`\`\`

---

## ⚙️ Installation
```powershell
# Clone the repository
git clone https://github.com/yeshaswi3060/Advanced-wifi-scaner.git
cd Advanced-wifi-scaner

# Install dependencies
pip install -r requirements.txt
