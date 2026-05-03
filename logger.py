import json
import os
import struct
from encryption import encrypt_data, decrypt_data, SecurityException

LOG_DIR = "logs"

def ensure_logs_dir():
    """Creates the logs directory if it doesn't exist."""
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)

def list_logs():
    """Returns a list of all web session .bin log files, sorted by name (newest first)."""
    ensure_logs_dir()
    # Only include session logs, exclude system admin files
    exclude_prefixes = ("banned_ips", "failed_attempts", "login_history")
    files = [f for f in os.listdir(LOG_DIR) if f.endswith(".bin") and not f.startswith(exclude_prefixes)]
    # Sort files (assuming newest first based on filename timestamp)
    files.sort(reverse=True)
    return files

def delete_log(filename):
    """Deletes a log file from the logs directory if it exists."""
    file_path = os.path.join(LOG_DIR, os.path.basename(filename))
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
            return True
        except Exception as e:
            print(f"[-] Error deleting log {filename}: {e}")
            return False
    return False

def delete_all_logs():
    """Deletes only session .bin log files, protecting system admin files."""
    ensure_logs_dir()
    files = list_logs()  # Uses the filtered list to exclude system files
    success = True
    for f in files:
        if not delete_log(f):
            success = False
    return success

def save_encrypted_alert(alert_dict, password, file_path):
    """
    Converts alert dictionary to JSON string, encrypts it, and appends to the specified file_path.
    """
    ensure_logs_dir()
    try:
        json_data = json.dumps(alert_dict)
        encrypted_data = encrypt_data(json_data, password)
        
        with open(file_path, "ab") as f:
            f.write(struct.pack("<I", len(encrypted_data)))
            f.write(encrypted_data)
    except Exception as e:
        print(f"[-] Error saving alert to {file_path}: {e}")

def read_and_decrypt_logs(password, file_path):
    """
    Reads all encrypted log entries from file_path, decrypts them, and displays results.
    """
    if not os.path.exists(file_path):
        print(f"[*] File {file_path} does not exist.")
        return

    print(f"\n--- Decrypted Entries from: {os.path.basename(file_path)} ---")
    entry_count = 0
    try:
        with open(file_path, "rb") as f:
            while True:
                length_bytes = f.read(4)
                if not length_bytes:
                    break
                
                length = struct.unpack("<I", length_bytes)[0]
                encrypted_data = f.read(length)
                
                if len(encrypted_data) != length:
                    print("[-] Incomplete block found. Possible corruption.")
                    break
                
                try:
                    decrypted_json = decrypt_data(encrypted_data, password)
                    alert_dict = json.loads(decrypted_json)
                    entry_count += 1
                    print(f"[{alert_dict.get('timestamp')}] ALERT: {alert_dict.get('attack_type')}")
                    print(f"    Attacker: {alert_dict.get('attacker_ip')}")
                    print(f"    Victim:   {alert_dict.get('victim_ip')}:{alert_dict.get('port')}\n")
                except SecurityException as e:
                    print(f"[-] Decryption failure: {e}")
                except Exception as e:
                    print(f"[-] Error processing entry: {e}")
    except Exception as e:
        print(f"[-] Error reading logs: {e}")
    
    if entry_count == 0:
        print("[*] No readable alerts found in this file.")
    print("-------------------------------------------\n")
