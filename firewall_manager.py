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
    """Adds a Windows Firewall rule to block all inbound and outbound traffic from the IP."""
    rule_name_in = f"NIDS_BLOCK_IN_{ip_address}"
    rule_name_out = f"NIDS_BLOCK_OUT_{ip_address}"
    
    command_in = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name_in}", "dir=in", "action=block", f"remoteip={ip_address}"
    ]
    command_out = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name_out}", "dir=out", "action=block", f"remoteip={ip_address}"
    ]
    
    print(f"[*] Adding Windows Firewall rules to block all traffic for {ip_address}...")
    res_in = subprocess.run(command_in, capture_output=True, text=True)
    res_out = subprocess.run(command_out, capture_output=True, text=True)
    
    if res_in.returncode == 0 and res_out.returncode == 0:
        print(f"[+] SUCCESS: {ip_address} is now completely blocked at the network level (Inbound & Outbound).")
    else:
        print(f"[-] FAILED to add rules.")
        if res_in.returncode != 0: print(f"Inbound Error: {res_in.stdout.strip()}")
        if res_out.returncode != 0: print(f"Outbound Error: {res_out.stdout.strip()}")

def unban_ip(ip_address):
    """Removes the Windows Firewall rules for the IP."""
    rule_name_in = f"NIDS_BLOCK_IN_{ip_address}"
    rule_name_out = f"NIDS_BLOCK_OUT_{ip_address}"
    
    command_in = [
        "netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name_in}"
    ]
    command_out = [
        "netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name_out}"
    ]
    
    print(f"[*] Removing Windows Firewall rules for {ip_address}...")
    res_in = subprocess.run(command_in, capture_output=True, text=True)
    res_out = subprocess.run(command_out, capture_output=True, text=True)
    
    if res_in.returncode == 0 or "No rules match" in res_in.stdout:
        print(f"[+] SUCCESS: {ip_address} has been unblocked from the Windows Firewall.")
    else:
        print(f"[-] Failed to delete rule. {res_in.stdout.strip()}")

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
