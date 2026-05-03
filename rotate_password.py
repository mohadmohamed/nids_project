import os
import struct
import getpass
from encryption import decrypt_data, encrypt_data, SecurityException

def list_logs():
    logs_dir = "logs"
    if not os.path.exists(logs_dir):
        return []
    exclude_prefixes = ("banned_ips", "failed_attempts", "login_history")
    return [os.path.join(logs_dir, f) for f in os.listdir(logs_dir) 
            if f.endswith(".bin") and not f.startswith(exclude_prefixes)]

def rotate_password():
    print("========================================")
    print(" NIDS Password Rotation Utility ")
    print("========================================")
    
    logs = list_logs()
    if not logs:
        print("[-] No log files found in 'logs/' directory.")
        return

    print("\nAvailable Log Files:")
    for i, log_path in enumerate(logs):
        print(f"{i+1}) {os.path.basename(log_path)}")
    
    try:
        choice = int(input("\nSelect a file to re-encrypt (1-{}): ".format(len(logs)))) - 1
        if choice < 0 or choice >= len(logs):
            print("[-] Invalid choice.")
            return
        target_file = logs[choice]
    except ValueError:
        print("[-] Invalid input.")
        return

    old_password = getpass.getpass("Enter CURRENT password for {}: ".format(os.path.basename(target_file)))
    
    # 1. Read and decrypt existing data
    decrypted_entries = []
    try:
        with open(target_file, "rb") as f:
            while True:
                length_bytes = f.read(4)
                if not length_bytes:
                    break
                length = struct.unpack("<I", length_bytes)[0]
                encrypted_data = f.read(length)
                
                # Decrypt entry
                try:
                    entry_json = decrypt_data(encrypted_data, old_password)
                    decrypted_entries.append(entry_json)
                except SecurityException:
                    print("[-] Incorrect password or corrupted data. Aborting.")
                    return
    except Exception as e:
        print("[-] Error reading file: {}".format(e))
        return

    print("[+] Successfully decrypted {} entries.".format(len(decrypted_entries)))
    
    # 2. Get new password
    new_password = getpass.getpass("Enter NEW password: ")
    confirm_password = getpass.getpass("Confirm NEW password: ")
    
    if new_password != confirm_password:
        print("[-] Passwords do not match. Aborting.")
        return
    
    # 3. Re-encrypt and save to a temporary file first
    temp_file = target_file + ".tmp"
    try:
        with open(temp_file, "wb") as f:
            for entry_json in decrypted_entries:
                encrypted_data = encrypt_data(entry_json, new_password)
                f.write(struct.pack("<I", len(encrypted_data)))
                f.write(encrypted_data)
        
        # 4. Replace original file
        os.replace(temp_file, target_file)
        print("[+] SUCCESS: Password updated for {}.".format(os.path.basename(target_file)))
    except Exception as e:
        if os.path.exists(temp_file):
            os.remove(temp_file)
        print("[-] Failed to save new logs: {}".format(e))

if __name__ == "__main__":
    rotate_password()
