import json
import os
import sys

# Path to the banned_ips.json file
BANNED_IPS_FILE = os.path.join('logs', 'banned_ips.json')
FAILED_ATTEMPTS_FILE = os.path.join('logs', 'failed_attempts.json')

def unban_ip(target_ip):
    if not os.path.exists(BANNED_IPS_FILE):
        print("[!] Ban file not found. No IPs are currently banned.")
        return

    try:
        with open(BANNED_IPS_FILE, 'r') as f:
            banned = json.load(f)
    except Exception as e:
        print(f"[!] Error reading ban file: {e}")
        return

    if target_ip in banned:
        del banned[target_ip]
        try:
            with open(BANNED_IPS_FILE, 'w') as f:
                json.dump(banned, f, indent=2)
            print(f"[+] SUCCESS: IP {target_ip} has been unbanned.")
        except Exception as e:
            print(f"[!] Error writing to ban file: {e}")
            return
    else:
        print(f"[-] INFO: IP {target_ip} not found in ban list.")

    # Also clear failed attempts for good measure
    if os.path.exists(FAILED_ATTEMPTS_FILE):
        try:
            with open(FAILED_ATTEMPTS_FILE, 'r') as f:
                attempts = json.load(f)
            if target_ip in attempts:
                del attempts[target_ip]
                with open(FAILED_ATTEMPTS_FILE, 'w') as f:
                    json.dump(attempts, f, indent=2)
                print(f"[+] SUCCESS: Failed attempts counter reset for {target_ip}.")
        except:
            pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python unban.py <IP_ADDRESS>")
        print("Example: python unban.py 192.168.1.100")
        sys.exit(1)

    ip_to_unban = sys.argv[1]
    unban_ip(ip_to_unban)
