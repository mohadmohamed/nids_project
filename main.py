import sys
import getpass
import os
import time
from datetime import datetime
from packet_sniffer import start_sniffing
from rule_engine import analyze_packet
from logger import save_encrypted_alert, read_and_decrypt_logs, list_logs, LOG_DIR

def main():
    print("==================================================")
    print(" Python NIDS (Network Intrusion Detection System) ")
    print("==================================================")
    
    # Generate unique filename for this session
    session_time = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    current_session_file = os.path.join(LOG_DIR, f"session_{session_time}.bin")
    
    # Request admin password securely at startup
    admin_password = getpass.getpass("Enter Admin Password for secure Storage/Decryption: ")
    
    print(f"[*] New logs will be saved to: {current_session_file}")

    def packet_callback(packet_data):
        """Callback to handle newly sniffed packets."""
        alert = analyze_packet(packet_data)
        if alert:
            # Human readable timestamp for logging
            alert['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"\n[!] ALERT: {alert['attack_type']} from {alert['attacker_ip']}")
            
            # Securely store the alert in the session file
            save_encrypted_alert(alert, admin_password, current_session_file)
            print(f"[+] Encrypted Alert Stored in {os.path.basename(current_session_file)}")

    while True:
        print("\n--- NIDS CLI Menu ---")
        print("1) Start Monitoring Network (New Session)")
        print("2) View/Select Decrypted Logs (Choose File)")
        print("3) Exit")
        
        choice = input("Select an option (1-3): ").strip()
        
        if choice == "1":
            print(f"\n[*] Starting packet monitoring [File: {os.path.basename(current_session_file)}]")
            print("[*] Press Ctrl+C to stop...")
            try:
                start_sniffing(packet_callback)
            except KeyboardInterrupt:
                print("\n[*] Stopped network monitoring. Returning to menu...")
            except PermissionError:
                print("\n[-] Permission denied: Please run the script as Administrator/Root.")
            except Exception as e:
                print(f"\n[-] Unexpected error: {e}")
                
        elif choice == "2":
            files = list_logs()
            if not files:
                print("\n[-] No log files found in 'logs/' folder.")
                continue
            
            print("\nAvailable Log Files:")
            for i, filename in enumerate(files):
                print(f"{i+1}) {filename}")
            
            try:
                file_choice = input("\nSelect a file number to view (or 'b' to go back): ").strip()
                if file_choice.lower() == 'b':
                    continue
                
                idx = int(file_choice) - 1
                if 0 <= idx < len(files):
                    target_path = os.path.join(LOG_DIR, files[idx])
                    # We use the password entered at startup, or ask again if needed? 
                    # For now, use the session password for consistency.
                    read_and_decrypt_logs(admin_password, target_path)
                else:
                    print("[-] Invalid selection.")
            except ValueError:
                print("[-] Please enter a valid number.")
            
        elif choice == "3":
            print("[*] Securely exiting NIDS. Goodbye!")
            sys.exit(0)
            
        else:
            print("[-] Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
