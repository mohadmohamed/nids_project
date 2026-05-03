# Python Network Intrusion Detection System (NIDS)

A custom, Python-based Network Intrusion Detection System designed to monitor network traffic, detect malicious behavior, securely log incidents using AES-256 encryption, and provide a real-time administrative dashboard.

## Features

- **Packet Sniffing**: Uses `scapy` to capture real-time network packets.
- **Custom Rule Engine**: Detects multiple types of attacks:
  - Port Scans (TCP SYN scans)
  - SYN Flood (DDoS)
  - UDP Flood
  - ICMP Flood (Ping of Death)
  - Payload Inspection (SQL Injection, XSS, Path Traversal)
- **Automated IP Banning**: Automatically blocks malicious IPs by integrating with the Windows firewall and tracking failed login attempts.
- **Secure Logging**: 
  - All alerts and system logs are encrypted locally using AES-256-CBC and HMAC-SHA256.
  - Logs can be exported securely to analyze offline.
- **Web Dashboard**: Real-time web UI using Flask & SocketIO to monitor attacks, manage banned IPs, and export logs safely.
- **Decryption Utility**: Includes a standalone, offline CLI utility (`decrypt_exported_logs.py`) to easily decrypt and view exported `.bin` logs from the dashboard.

## Prerequisites

- Python 3.8+
- Administrator/Root privileges (required for `scapy` to capture packets and for modifying firewall rules).
- Npcap or WinPcap (if running on Windows).

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/mohadmohamed/nids_project.git
   cd nids_project
   ```

2. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

## ⚙️ Running the System

### 1. Starting the Admin Dashboard
The Admin Dashboard provides real-time visibility into alerts and allows you to configure rules and export logs.
```bash
python app.py
```
- Open your browser and navigate to the address shown in the terminal (usually `http://127.0.0.1:5000`).
- You will be prompted to log in. (Check the `config.json` for default admin credentials, or you will be asked to set them up on the first run).

### 2. Starting the NIDS Engine
The NIDS engine actively monitors network interfaces for suspicious activity. **Must be run as Administrator!**
```bash
python main.py
```
- On startup, it will ask for the **Admin Dashboard Password** to secure the session log files.
- Select `1` from the menu to start capturing traffic. 

### 3. Decrypting Exported Logs Offline
If you exported a `.bin` log file from the dashboard, you can decrypt it offline:
```bash
python decrypt_exported_logs.py
```
- It will prompt for your Admin Dashboard Password.
- Paste the full path to the `.bin` or `.json` file you downloaded.
- The script will decrypt the logs, save them to a formatted JSON file, and automatically open it for you.

## Project Structure

- `main.py`: Entry point for the CLI NIDS Engine.
- `app.py`: Flask backend for the Real-time Web Dashboard.
- `packet_sniffer.py`: Scapy packet capture logic.
- `rule_engine.py`: Defines and executes the intrusion detection rules.
- `encryption.py`: Cryptographic helpers (AES/HMAC).
- `decrypt_exported_logs.py`: Standalone CLI tool to decrypt logs offline.
- `logger.py`: Secure logging subsystem.
- `config.json` & `rules_config.json`: Configuration state for rules, credentials, and settings.
- `templates/` & `static/`: Frontend files for the Web Dashboard.

## 🔒 Security Note
This system encrypts logs using a PBKDF2 derived key from your Admin password. If you lose your Admin password, previous logs cannot be recovered.
