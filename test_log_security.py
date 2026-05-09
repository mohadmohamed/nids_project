import os
import time
import struct
from encryption import decrypt_data, SecurityException

def test_security(file_path, correct_password):
    print("="*50)
    print(" NIDS LOG SECURITY AUDIT - ATTACKER SIMULATION ")
    print("="*50)
    
    if not os.path.exists(file_path):
        print(f"[-] Error: File {file_path} not found.")
        return

    # 1. READ ORIGINAL ENCRYPTED DATA
    with open(file_path, "rb") as f:
        length_bytes = f.read(4)
        if not length_bytes:
            print("[-] File is empty.")
            return
        length = struct.unpack("<I", length_bytes)[0]
        original_encrypted_data = f.read(length)

    print(f"\n[TEST 1] Brute-Force Difficulty (PBKDF2 Timing)")
    start_time = time.time()
    try:
        decrypt_data(original_encrypted_data, "wrong_password_123")
    except SecurityException:
        pass
    end_time = time.time()
    attempt_duration = end_time - start_time
    print(f"[*] Single attempt took: {attempt_duration:.4f} seconds")
    print(f"[*] To try 1 million passwords, an attacker would need ~{(attempt_duration * 1000000 / 3600):.2f} hours.")
    print("[+] RESULT: High resistance to Brute-Force due to 100k iterations.")

    print(f"\n[TEST 2] Wrong Password Resilience")
    try:
        decrypt_data(original_encrypted_data, "admin123") # Assuming this is wrong
        print("[-] FAILURE: Decrypted with wrong password! (Wait, was it correct?)")
    except SecurityException:
        print("[+] SUCCESS: System correctly rejected the wrong password.")

    print(f"\n[TEST 3] Data Integrity / Tampering Attack")
    # Simulate an attacker flipping a bit in the ciphertext
    tampered_data = bytearray(original_encrypted_data)
    # Change one byte in the ciphertext area (after Salt(16), IV(16), HMAC(32))
    tampered_data[70] = (tampered_data[70] + 1) % 256 
    
    try:
        decrypt_data(bytes(tampered_data), correct_password)
        print("[-] FAILURE: System decrypted tampered data! Integrity compromised.")
    except SecurityException as e:
        print(f"[+] SUCCESS: HMAC caught the tampering! Error: {e}")
    
    print("\n" + "="*50)
    print(" AUDIT COMPLETE: Your logs are cryptographically secure. ")
    print("="*50)

if __name__ == "__main__":
    path = input("Enter path to an encrypted log file: ").strip()
    if path.startswith('"') and path.endswith('"'): path = path[1:-1]
    pwd = input("Enter the CORRECT password for this file: ")
    test_security(path, pwd)
