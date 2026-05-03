import subprocess
import sys

def is_admin():
    """
    Reliably check Windows Administrator privileges using 'net session'.
    This works correctly regardless of UAC settings or Flask reloader behaviour.
    'net session' returns exit code 0 only when the process is elevated.
    """
    try:
        result = subprocess.run(
            ['net', 'session'],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False

def ban_ip(ip_address):
    """
    Adds Windows Firewall rules to block all inbound and outbound traffic for an IP.
    Returns: (success: bool, message: str)
    """
    rule_name_in = f"NIDS_BLOCK_IN_{ip_address}"
    rule_name_out = f"NIDS_BLOCK_OUT_{ip_address}"

    cmd_in = f'netsh advfirewall firewall add rule name="{rule_name_in}" dir=in action=block remoteip={ip_address}'
    cmd_out = f'netsh advfirewall firewall add rule name="{rule_name_out}" dir=out action=block remoteip={ip_address}'

    res_in = subprocess.run(cmd_in, capture_output=True, text=True, shell=True)
    res_out = subprocess.run(cmd_out, capture_output=True, text=True, shell=True)

    # Check for success or "already exists"
    in_ok = res_in.returncode == 0 or "already exists" in res_in.stdout.lower() or "already exists" in res_in.stderr.lower()
    out_ok = res_out.returncode == 0 or "already exists" in res_out.stdout.lower() or "already exists" in res_out.stderr.lower()

    if in_ok and out_ok:
        msg = f"[+] SUCCESS: {ip_address} is now blocked at the network level."
        print(msg)
        return True, msg
    else:
        errors = []
        if not in_ok: errors.append(f"Inbound: {res_in.stdout.strip() or res_in.stderr.strip()}")
        if not out_ok: errors.append(f"Outbound: {res_out.stdout.strip() or res_out.stderr.strip()}")
        msg = f"[-] FAILED to add firewall rules. {'; '.join(errors)}"
        print(msg)
        return False, msg

def unban_ip(ip_address):
    """
    Removes Windows Firewall rules for the IP.
    Returns: (success: bool, message: str)
    """
    rule_name_in = f"NIDS_BLOCK_IN_{ip_address}"
    rule_name_out = f"NIDS_BLOCK_OUT_{ip_address}"

    cmd_in = f'netsh advfirewall firewall delete rule name="{rule_name_in}"'
    cmd_out = f'netsh advfirewall firewall delete rule name="{rule_name_out}"'

    res_in = subprocess.run(cmd_in, capture_output=True, text=True, shell=True)
    res_out = subprocess.run(cmd_out, capture_output=True, text=True, shell=True)

    # "No rules match" is acceptable
    in_ok = res_in.returncode == 0 or "no rules match" in res_in.stdout.lower()
    out_ok = res_out.returncode == 0 or "no rules match" in res_out.stdout.lower()

    if in_ok and out_ok:
        msg = f"[+] SUCCESS: {ip_address} unblocked from Firewall."
        print(msg)
        return True, msg
    else:
        msg = f"[-] Failed to remove firewall rules: {res_in.stderr.strip() or res_out.stderr.strip()}"
        print(msg)
        return False, msg

# --- CLI entrypoint ---
if __name__ == "__main__":
    if not is_admin():
        print("[-] ERROR: You must run this script as an Administrator to modify the Windows Firewall!")
        print("    Please open an Administrator Command Prompt or PowerShell and try again.")
        sys.exit(1)

    if len(sys.argv) < 3:
        print("=============================================")
        print("   Windows Firewall Manual Ban Utility      ")
        print("=============================================")
        print("Usage:   python firewall_manager.py [ban|unban] <IP_ADDRESS>")
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
