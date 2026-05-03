import subprocess
import sys
import ctypes

def is_admin():
    """Check if the script is running with Windows Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def ban_ip(ip_address):
    """Adds a Windows Firewall rule to block all inbound traffic from the IP."""
    rule_name = f"NIDS_BLOCK_{ip_address}"
    
    # PowerShell command via netsh to block the IP
    command = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=in",
        "action=block",
        f"remoteip={ip_address}"
    ]
    
    print(f"[*] Adding Windows Firewall rule to block inbound traffic from {ip_address}...")
    result = subprocess.run(command, capture_output=True, text=True)
    
    if result.returncode == 0:
        print(f"[+] SUCCESS: {ip_address} is now completely blocked at the network level.")
    else:
        print(f"[-] FAILED to add rule. Error details: {result.stdout.strip()}")

def unban_ip(ip_address):
    """Removes the Windows Firewall rule for the IP."""
    rule_name = f"NIDS_BLOCK_{ip_address}"
    
    command = [
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={rule_name}"
    ]
    
    print(f"[*] Removing Windows Firewall rule for {ip_address}...")
    result = subprocess.run(command, capture_output=True, text=True)
    
    if result.returncode == 0 and "No rules match" not in result.stdout:
        print(f"[+] SUCCESS: {ip_address} has been unblocked from the Windows Firewall.")
    else:
        print(f"[-] Rule not found or failed to delete. {result.stdout.strip()}")

if __name__ == "__main__":
    if not is_admin():
        print("[-] ERROR: You must run this script as an Administrator to modify the Windows Firewall!")
        print("    Please open an Administrator Command Prompt or PowerShell and try again.")
        sys.exit(1)

    if len(sys.argv) < 3:
        print("=============================================")
        print(" Windows Firewall Manual Ban Utility ")
        print("=============================================")
        print("Usage: python firewall_manager.py [ban|unban] <IP_ADDRESS>")
        print("Example: python firewall_manager.py ban 192.168.1.100")
        sys.exit(1)

    action = sys.argv[1].lower()
    ip = sys.argv[2]

    if action == "ban":
        ban_ip(ip)
    elif action == "unban":
        unban_ip(ip)
    else:
        print("[-] Invalid action. Use 'ban' or 'unban'.")
