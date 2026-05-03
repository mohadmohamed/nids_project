import time
import json
import os
from threading import Lock

# --- Dynamic Configuration ---
RULES_CONFIG_FILE = 'rules_config.json'

DEFAULT_CONFIG = {
    "time_window": 10,
    "icmp_flood": {"standard": 30, "trusted": 100},
    "syn_flood": {"standard": 30, "trusted": 80},
    "common_port_traffic": {"standard": 800, "trusted": 1500},
    "ddos": {"standard": 800, "trusted": 2000},
    "port_scan": {"standard": 20, "trusted": 40},
    "common_ports": [80, 443, 22, 21, 53, 3306, 3389, 8080],
    "trusted_ip_prefixes": ["142.250.", "172.217.", "142.251.", "8.8.8.", "8.8.4."]
}

_config_cache = None
_config_mtime = 0

def load_config():
    """Loads configuration from rules_config.json, using cache if file hasn't changed."""
    global _config_cache, _config_mtime

    try:
        if not os.path.exists(RULES_CONFIG_FILE):
            return DEFAULT_CONFIG

        mtime = os.path.getmtime(RULES_CONFIG_FILE)
        if _config_cache is not None and mtime == _config_mtime:
            return _config_cache

        with open(RULES_CONFIG_FILE, 'r') as f:
            config = json.load(f)
        _config_cache = config
        _config_mtime = mtime
        return config
    except Exception as e:
        print(f"[-] Error loading rules config: {e}")
        return DEFAULT_CONFIG

def save_config(config):
    """Saves configuration to rules_config.json and updates cache."""
    global _config_cache, _config_mtime
    try:
        with open(RULES_CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        
        # Update cache immediately to prevent reload delays
        _config_cache = config
        _config_mtime = os.path.getmtime(RULES_CONFIG_FILE)
        return True
    except Exception as e:
        print(f"[-] Error saving rules config: {e}")
        raise e

def get_default_config():
    """Returns a deep copy of the default configuration."""
    return json.loads(json.dumps(DEFAULT_CONFIG))


# --- State Tracking ---
ddos_counts = {}
syn_counts = {}
port_scans = {}
icmp_counts = {}
normal_port_usage = {}

_lock = Lock()
last_cleanup_time = time.time()


def _cleanup_old_ips(max_age=60):
    global last_cleanup_time
    now = time.time()

    if now - last_cleanup_time < 60:
        return
    last_cleanup_time = now

    for d in (ddos_counts, syn_counts, port_scans, icmp_counts, normal_port_usage):
        stale = []

        for ip, entries in d.items():
            if isinstance(entries, list) and entries:
                if now - max(entries) > max_age:
                    stale.append(ip)
            elif isinstance(entries, dict) and entries:
                if now - max(entries.values()) > max_age:
                    stale.append(ip)

        for ip in stale:
            del d[ip]


def analyze_packet(packet_data):

    # Load current configuration
    config = load_config()
    TIME_WINDOW = config.get("time_window", 10)
    COMMON_PORTS = set(config.get("common_ports", [80, 443, 22, 21, 53, 3306, 3389, 8080]))
    TRUSTED_IPS_START = config.get("trusted_ip_prefixes", [])

    src_ip    = packet_data.get("source_ip", "Unknown")
    dst_ip    = packet_data.get("destination_ip", "Unknown")
    dst_port  = packet_data.get("destination_port", "N/A")
    tcp_flags = packet_data.get("tcp_flags", "")
    protocol  = packet_data.get("protocol", "TCP")
    timestamp = packet_data.get("timestamp", time.time())

    is_trusted = any(src_ip.startswith(ip) for ip in TRUSTED_IPS_START)

    with _lock:
        _cleanup_old_ips()

        # =========================
        # ICMP Flood (مستقل)
        # =========================
        if protocol == "ICMP":

            key = (src_ip, dst_ip)

            if key not in icmp_counts:
                icmp_counts[key] = []

            icmp_counts[key].append(timestamp)
            icmp_counts[key] = [t for t in icmp_counts[key] if timestamp - t <= TIME_WINDOW]

            icmp_cfg = config.get("icmp_flood", {})
            threshold = icmp_cfg.get("trusted", 100) if is_trusted else icmp_cfg.get("standard", 30)

            if len(icmp_counts[key]) > threshold:
                icmp_counts[key].clear()
                return {
                    "attacker_ip": src_ip,
                    "victim_ip": dst_ip,
                    "attack_type": "ICMP Flood",
                    "timestamp": timestamp
                }

            return None

        # =========================
        # Handle Common Ports (Browsing Safe Zone)
        # =========================
        if str(dst_port).isdigit() and int(dst_port) in COMMON_PORTS:
            port = int(dst_port)
            key = (src_ip, dst_ip)

            if key not in normal_port_usage:
                normal_port_usage[key] = []

            normal_port_usage[key].append(timestamp)
            normal_port_usage[key] = [
                t for t in normal_port_usage[key]
                if timestamp - t <= TIME_WINDOW
            ]

            # threshold عالي عشان browsing
            cpt_cfg = config.get("common_port_traffic", {})
            threshold = cpt_cfg.get("trusted", 1500) if is_trusted else cpt_cfg.get("standard", 800)

            if len(normal_port_usage[key]) > threshold:
                normal_port_usage[key].clear()
                return {
                    "attacker_ip": src_ip,
                    "victim_ip": dst_ip,
                    "port": port,
                    "attack_type": "High Traffic on Common Port",
                    "timestamp": timestamp
                }

            return None  # 🚨 يمنع باقي rules

        # =========================
        # Port Scan (FIXED)
        # =========================
        if str(dst_port).isdigit():
            port = int(dst_port)
            key = src_ip 

            if key not in port_scans:
                port_scans[key] = {}

            port_scans[key][port] = timestamp
            port_scans[key] = {
                p: t for p, t in port_scans[key].items()
                if timestamp - t <= TIME_WINDOW
            }

            ps_cfg = config.get("port_scan", {})
            threshold = ps_cfg.get("trusted", 40) if is_trusted else ps_cfg.get("standard", 20)

            if len(port_scans[key]) > threshold:
                port_scans[key].clear()
                return {
                    "attacker_ip": src_ip,
                    "victim_ip": dst_ip,
                    "port": "Multiple",
                    "attack_type": "Port Scan",
                    "timestamp": timestamp
                }

        # =========================
        # SYN Flood
        # =========================
        if tcp_flags and "S" in str(tcp_flags):
            key = (src_ip, dst_ip)

            if key not in syn_counts:
                syn_counts[key] = []

            syn_counts[key].append(timestamp)
            syn_counts[key] = [
                t for t in syn_counts[key]
                if timestamp - t <= TIME_WINDOW
            ]

            syn_cfg = config.get("syn_flood", {})
            threshold = syn_cfg.get("trusted", 80) if is_trusted else syn_cfg.get("standard", 30)

            if len(syn_counts[key]) > threshold:
                syn_counts[key].clear()
                return {
                    "attacker_ip": src_ip,
                    "victim_ip": dst_ip,
                    "port": "multiple",
                    "attack_type": "SYN Flood",
                    "timestamp": timestamp
                }

            return None

        # =========================
        # DDoS (غير البورتات الطبيعية)
        # =========================
        if src_ip not in ddos_counts:
            ddos_counts[src_ip] = []

        ddos_counts[src_ip].append(timestamp)
        ddos_counts[src_ip] = [t for t in ddos_counts[src_ip] if timestamp - t <= TIME_WINDOW]

        ddos_cfg = config.get("ddos", {})
        threshold = ddos_cfg.get("trusted", 2000) if is_trusted else ddos_cfg.get("standard", 800)

        if len(ddos_counts[src_ip]) > threshold:
            ddos_counts[src_ip].clear()
            return {
                "attacker_ip": src_ip,
                "victim_ip": dst_ip,
                "port": dst_port,
                "attack_type": "DDoS High-Rate Traffic",
                "timestamp": timestamp
            }

    return None