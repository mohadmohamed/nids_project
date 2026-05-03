import json
import os
import sys
import subprocess
from encryption import encrypt_data, decrypt_data

# The system-level secret used for administrative data persistence
SYSTEM_SECRET = "nids-system-core-vault-998811"

def unban_ip(target_ip):
    # 1. Handle Dashboard Bans (banned_ips.bin)
    db_ban_file = os.path.join('logs', 'banned_ips.bin')
    if os.path.exists(db_ban_file):
        try:
            with open(db_ban_file, 'rb') as f:
                encrypted = f.read()
            decrypted_str = decrypt_data(encrypted, SYSTEM_SECRET)
            banned = json.loads(decrypted_str)
            
            if target_ip in banned:
                del banned[target_ip]
                # Re-encrypt and save
                json_data = json.dumps(banned)
                new_encrypted = encrypt_data(json_data, SYSTEM_SECRET)
                with open(db_ban_file, 'wb') as f:
                    f.write(new_encrypted)
                print(f"[+] SUCCESS: IP {target_ip} unbanned from Dashboard access.")
            else:
                print(f"[-] INFO: IP {target_ip} not found in Dashboard ban list.")
        except Exception as e:
            print(f"[!] Error processing Dashboard bans: {e}")
    else:
        print("[!] Dashboard ban file not found.")

    # 2. Handle Firewall Bans (firewall_banned_ips.bin)
    fw_ban_file = os.path.join('logs', 'firewall_banned_ips.bin')
    if os.path.exists(fw_ban_file):
        try:
            with open(fw_ban_file, 'rb') as f:
                encrypted = f.read()
            decrypted_str = decrypt_data(encrypted, SYSTEM_SECRET)
            fw_banned = json.loads(decrypted_str)
            
            if target_ip in fw_banned:
                # Remove from OS Firewall
                print(f"[*] Removing Windows Firewall rules for {target_ip}...")
                rule_in = f"NIDS_BLOCK_IN_{target_ip}"
                rule_out = f"NIDS_BLOCK_OUT_{target_ip}"
                
                # Execute netsh commands
                subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_in}"', shell=True, capture_output=True)
                subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_out}"', shell=True, capture_output=True)
                
                del fw_banned[target_ip]
                # Re-encrypt and save
                json_data = json.dumps(fw_banned)
                new_encrypted = encrypt_data(json_data, SYSTEM_SECRET)
                with open(fw_ban_file, 'wb') as f:
                    f.write(new_encrypted)
                print(f"[+] SUCCESS: IP {target_ip} unbanned from Network/Firewall level.")
            else:
                print(f"[-] INFO: IP {target_ip} not found in Firewall ban list.")
        except Exception as e:
            print(f"[!] Error processing Firewall bans: {e}")
    else:
        print("[!] Firewall ban file not found.")

    # 3. Handle Failed Attempts (failed_attempts.bin)
    attempts_file = os.path.join('logs', 'failed_attempts.bin')
    if os.path.exists(attempts_file):
        try:
            with open(attempts_file, 'rb') as f:
                encrypted = f.read()
            decrypted_str = decrypt_data(encrypted, SYSTEM_SECRET)
            attempts = json.loads(decrypted_str)
            
            if target_ip in attempts:
                del attempts[target_ip]
                json_data = json.dumps(attempts)
                new_encrypted = encrypt_data(json_data, SYSTEM_SECRET)
                with open(attempts_file, 'wb') as f:
                    f.write(new_encrypted)
                print(f"[+] SUCCESS: Failed login attempts reset for {target_ip}.")
        except Exception as e:
            print(f"[!] Error processing Failed Attempts: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python unban.py <IP_ADDRESS>")
        sys.exit(1)
    
    ip = sys.argv[1]
    unban_ip(ip)
