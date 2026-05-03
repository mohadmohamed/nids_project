import os
import sys
import struct
import json
import getpass
from encryption import decrypt_data, SecurityException

def decrypt_log_file():
    print("========================================")
    print(" NIDS Log Decryption Utility ")
    print("========================================")

    password = getpass.getpass("\nEnter the Admin Dashboard Password (only asked once): ")

    while True:
        file_path = input("\nEnter the full path to the log file (.bin or .json): ").strip()
        
        # Remove quotes if pasted with them
        if file_path.startswith('"') and file_path.endswith('"'):
            file_path = file_path[1:-1]
            
        if not os.path.exists(file_path):
            print(f"[-] Error: File not found at '{file_path}'")
            continue

        # Check if it's already a decrypted JSON file
        try:
            with open(file_path, 'r', encoding='utf-8') as check_f:
                # Try to parse it as JSON to see if it's already plaintext
                json.load(check_f)
            print(f"[*] This file appears to ALREADY be a decrypted JSON file.")
            
            try:
                os.startfile(file_path)
                print(f"[+] Opened '{file_path}' automatically.")
            except AttributeError:
                import subprocess
                if sys.platform == "darwin":
                    subprocess.call(["open", file_path])
                else:
                    subprocess.call(["xdg-open", file_path])
            except Exception as e:
                print(f"[-] Could not open file automatically: {e}")
                
            more = input("\nDo you want to decrypt another file? (y/n): ").strip().lower()
            if more != 'y':
                print("Exiting utility. Goodbye!")
                break
            continue
        except (UnicodeDecodeError, json.JSONDecodeError):
            # If it's not valid text/JSON, assume it's encrypted binary data and proceed
            pass

        decrypted_entries = []
        decryption_success = False
        try:
            with open(file_path, "rb") as f:
                while True:
                    length_bytes = f.read(4)
                    if not length_bytes:
                        decryption_success = True
                        break
                    
                    try:
                        length = struct.unpack("<I", length_bytes)[0]
                        encrypted_data = f.read(length)
                        
                        decrypted_json = decrypt_data(encrypted_data, password)
                        decrypted_entries.append(json.loads(decrypted_json))
                    except SecurityException:
                        print("[-] Decryption failed: Incorrect password or corrupted data.")
                        break
                    except Exception as e:
                         print(f"[-] Error processing entry: {e}")
                         break

            if decryption_success and decrypted_entries:
                print(f"\n[+] SUCCESS: Decrypted {len(decrypted_entries)} entries successfully!")
                
                # Auto-save file
                out_path = file_path.rsplit('.', 1)[0] + "_decrypted.json"
                with open(out_path, "w") as out_f:
                    json.dump(decrypted_entries, out_f, indent=4)
                print(f"[+] Decrypted data saved to '{out_path}'")
                
                # Auto-open file
                try:
                    os.startfile(out_path)
                    print(f"[+] Opened '{out_path}' automatically.")
                except AttributeError:
                    import subprocess
                    if sys.platform == "darwin":
                        subprocess.call(["open", out_path])
                    else:
                        subprocess.call(["xdg-open", out_path])
                except Exception as e:
                    print(f"[-] Could not open file automatically: {e}")
            elif decryption_success and not decrypted_entries:
                print("[-] Decryption succeeded, but the file was empty.")

        except Exception as e:
            print(f"[-] Error reading file: {e}")
            
        more = input("\nDo you want to decrypt another file? (y/n): ").strip().lower()
        if more != 'y':
            print("Exiting utility. Goodbye!")
            break

if __name__ == "__main__":
    decrypt_log_file()
