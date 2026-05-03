
import os
import threading
import time
import json
import hashlib
import uuid
import struct
import io
import zipfile
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
from flask_socketio import SocketIO, emit
import logging

# Suppress Werkzeug development warning
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

from packet_sniffer import start_sniffing
from rule_engine import analyze_packet, load_config, save_config, get_default_config
from logger import save_encrypted_alert, list_logs, read_and_decrypt_logs, LOG_DIR, ensure_logs_dir, delete_log, delete_all_logs
from firewall_manager import ban_ip as fw_ban_ip, unban_ip as fw_unban_ip, is_admin as fw_is_admin

app = Flask(__name__)
app.config['SECRET_KEY'] = 'nids-secret-key-12345'
app.permanent_session_lifetime = timedelta(days=30)
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins='*')

# Map session IDs to passwords (because Flask session may not be available in SocketIO handlers)
client_passwords = {}

# Unique ID for this server run to handle session expiration on restart
SERVER_ID = str(uuid.uuid4())
CONFIG_FILE = 'config.json'

# --- Security Helpers ---
def get_stored_username_hash():
    default_hash = hashlib.sha256('admin_nids'.encode()).hexdigest()
    if not os.path.exists(CONFIG_FILE):
        return default_hash
    with open(CONFIG_FILE, 'r') as f:
        try:
            config = json.load(f)
            return config.get('username_hash', default_hash)
        except:
            return default_hash

def get_stored_hash():
    if not os.path.exists(CONFIG_FILE):
        return hashlib.sha256('123'.encode()).hexdigest()
    with open(CONFIG_FILE, 'r') as f:
        try:
            config = json.load(f)
            return config.get('password_hash')
        except:
            return hashlib.sha256('123'.encode()).hexdigest()

def update_password_hash(new_password):
    hashed = hashlib.sha256(new_password.encode()).hexdigest()
    config = {}
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            try:
                config = json.load(f)
            except: pass
            
    config['password_hash'] = hashed
    if 'username_hash' not in config:
        config['username_hash'] = hashlib.sha256('admin_nids'.encode()).hexdigest()
        
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f)

# Global state for the sniffer
sniffer_thread = None
sniffer_active = False
sniffer_password = None
current_session_file = None
live_alerts = []  # In-memory buffer for current session alerts

from encryption import encrypt_data, decrypt_data, SecurityException

LOGIN_HISTORY_FILE = os.path.join(LOG_DIR, 'login_history.bin')
BANNED_IPS_FILE = os.path.join(LOG_DIR, 'banned_ips.bin')
FAILED_ATTEMPTS_FILE = os.path.join(LOG_DIR, 'failed_attempts.bin')
FIREWALL_BANNED_IPS_FILE = os.path.join(LOG_DIR, 'firewall_banned_ips.bin')
MAX_FAILED_ATTEMPTS = 3

# Internal system secret for administrative files (allows checking bans before login)
SYSTEM_SECRET = "nids-system-core-vault-998811"

def get_banned_ips():
    if not os.path.exists(BANNED_IPS_FILE): return {}
    try:
        with open(BANNED_IPS_FILE, 'rb') as f:
            encrypted_data = f.read()
            if not encrypted_data: return {}
            decrypted_json = decrypt_data(encrypted_data, SYSTEM_SECRET)
            return json.loads(decrypted_json)
    except: return {}

def save_banned_ips(banned_dict):
    try:
        json_data = json.dumps(banned_dict)
        encrypted_data = encrypt_data(json_data, SYSTEM_SECRET)
        with open(BANNED_IPS_FILE, 'wb') as f:
            f.write(encrypted_data)
    except Exception as e:
        print(f"[-] Error saving banned IPs: {e}")

def get_failed_attempts():
    if not os.path.exists(FAILED_ATTEMPTS_FILE): return {}
    try:
        with open(FAILED_ATTEMPTS_FILE, 'rb') as f:
            encrypted_data = f.read()
            if not encrypted_data: return {}
            decrypted_json = decrypt_data(encrypted_data, SYSTEM_SECRET)
            return json.loads(decrypted_json)
    except: return {}

def save_failed_attempts(attempts_dict):
    try:
        json_data = json.dumps(attempts_dict)
        encrypted_data = encrypt_data(json_data, SYSTEM_SECRET)
        with open(FAILED_ATTEMPTS_FILE, 'wb') as f:
            f.write(encrypted_data)
    except Exception as e:
        print(f"[-] Error saving failed attempts: {e}")

def get_firewall_banned_ips():
    """Return the dict of IPs banned at the Windows Firewall level."""
    if not os.path.exists(FIREWALL_BANNED_IPS_FILE): return {}
    try:
        with open(FIREWALL_BANNED_IPS_FILE, 'rb') as f:
            encrypted_data = f.read()
            if not encrypted_data: return {}
            decrypted_json = decrypt_data(encrypted_data, SYSTEM_SECRET)
            return json.loads(decrypted_json)
    except: return {}

def save_firewall_banned_ips(fw_dict):
    """Persist the firewall banned IPs dict (encrypted)."""
    try:
        json_data = json.dumps(fw_dict)
        encrypted_data = encrypt_data(json_data, SYSTEM_SECRET)
        with open(FIREWALL_BANNED_IPS_FILE, 'wb') as f:
            f.write(encrypted_data)
    except Exception as e:
        print(f"[-] Error saving firewall banned IPs: {e}")

def log_login_event(username, status, ip):
    """Logs a login attempt to an encrypted JSON file."""
    ensure_logs_dir()
    event = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now().strftime("%b %d, %Y • %I:%M %p"),
        "username": username or "Unknown",
        "status": status,
        "ip": ip
    }
    
    history = []
    if os.path.exists(LOGIN_HISTORY_FILE):
        try:
            with open(LOGIN_HISTORY_FILE, 'rb') as f:
                encrypted_data = f.read()
                if encrypted_data:
                    decrypted_json = decrypt_data(encrypted_data, SYSTEM_SECRET)
                    history = json.loads(decrypted_json)
        except: pass
        
    history.insert(0, event)
    history = history[:100]
    
    try:
        json_data = json.dumps(history)
        encrypted_data = encrypt_data(json_data, SYSTEM_SECRET)
        with open(LOGIN_HISTORY_FILE, 'wb') as f:
            f.write(encrypted_data)
    except Exception as e:
        print(f"[-] Error saving login history: {e}")


@app.before_request
def security_checks():
    ip = request.remote_addr
    banned = get_banned_ips()
    
    if ip in banned:
        # Allow access to the banned page itself if it were a route, 
        # but here we'll just return the template directly for any requested page.
        return render_template('banned.html', reason=banned[ip]['reason']), 403

    # Allow access to login and static files
    if request.endpoint in ['login', 'static'] or not request.endpoint:
        return
        
    if 'logged_in' in session:
        # If user didn't choose 'Remember Me', check if server has restarted
        if not session.get('is_permanent'):
            if session.get('server_id') != SERVER_ID:
                session.clear()
                return redirect(url_for('login'))

@app.route('/')
def index():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('tab_route', tab='dashboard'))

@app.route('/<tab>')
def tab_route(tab):
    valid_tabs = ['dashboard', 'history', 'security', 'login-history', 'banned-ips', 'settings']
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    if tab not in valid_tabs:
        return redirect(url_for('tab_route', tab='dashboard'))
    return render_template('index.html', active_tab=tab)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = request.args.get('error')
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember')
        
        user_hash = hashlib.sha256(username.encode()).hexdigest() if username else ""
        pwd_hash = hashlib.sha256(password.encode()).hexdigest() if password else ""
        
        if user_hash == get_stored_username_hash() and pwd_hash == get_stored_hash():
            log_login_event(username, "Success", request.remote_addr)
            
            # Reset attempts on success
            attempts = get_failed_attempts()
            if request.remote_addr in attempts:
                del attempts[request.remote_addr]
                save_failed_attempts(attempts)
                
            session.clear()
            session['logged_in'] = True
            session['password'] = password
            
            if remember:
                session.permanent = True
                session['is_permanent'] = True
            else:
                session.permanent = False
                session['is_permanent'] = False
                session['server_id'] = SERVER_ID
                
            print(f"[*] User logged in successfully.")
            return redirect(url_for('index'))
        else:
            log_login_event(username, "Failed", request.remote_addr)
            
            # Track failed attempts
            attempts = get_failed_attempts()
            count = attempts.get(request.remote_addr, 0) + 1
            attempts[request.remote_addr] = count
            save_failed_attempts(attempts)
            
            if count >= MAX_FAILED_ATTEMPTS:
                banned = get_banned_ips()
                banned[request.remote_addr] = {
                    "reason": "Too many wrong password attempts",
                    "timestamp": datetime.now().strftime("%b %d, %Y • %I:%M %p"),
                    "username": username or "Unknown"
                }
                save_banned_ips(banned)
                # Redirect to login which will trigger the before_request ban check
                return redirect(url_for('login'))
                
            error_msg = f"Invalid username or password. ({count}/{MAX_FAILED_ATTEMPTS} attempts)"
            return redirect(url_for('login', error=error_msg))
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/status')
def get_status():
    if 'logged_in' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({
        "active": sniffer_active,
        "file": os.path.basename(current_session_file) if current_session_file else None,
        "alerts": live_alerts,
        "alert_count": len(live_alerts)
    })

@app.route('/api/change_password', methods=['POST'])
def change_password():
    if 'logged_in' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    
    if hashlib.sha256(old_password.encode()).hexdigest() != get_stored_hash():
        return jsonify({"error": "Current password incorrect"}), 400
    
    update_password_hash(new_password)
    session['password'] = new_password
    return jsonify({"success": True, "message": "Password updated"})

@app.route('/api/logs')
def get_logs():
    if 'logged_in' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(list_logs())

@app.route('/api/login_history')
def get_login_history():
    if 'logged_in' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    if os.path.exists(LOGIN_HISTORY_FILE):
        try:
            with open(LOGIN_HISTORY_FILE, 'rb') as f:
                encrypted_data = f.read()
                if encrypted_data:
                    decrypted_json = decrypt_data(encrypted_data, SYSTEM_SECRET)
                    return jsonify(json.loads(decrypted_json))
        except Exception as e:
            print(f"[-] Error reading login history: {e}")
            return jsonify([])
    return jsonify([])

@app.route('/api/clear_login_history', methods=['POST'])
def clear_login_history():
    if 'logged_in' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        if os.path.exists(LOGIN_HISTORY_FILE):
            os.remove(LOGIN_HISTORY_FILE)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/delete_login_entry', methods=['POST'])
def delete_login_entry():
    if 'logged_in' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    entry_id = request.json.get('id')
    if not entry_id:
        return jsonify({"error": "No ID provided"}), 400
    
    if os.path.exists(LOGIN_HISTORY_FILE):
        try:
            with open(LOGIN_HISTORY_FILE, 'rb') as f:
                encrypted_data = f.read()
            
            if encrypted_data:
                decrypted_json = decrypt_data(encrypted_data, SYSTEM_SECRET)
                history = json.loads(decrypted_json)
                new_history = [e for e in history if e.get('id') != entry_id]
                
                json_data = json.dumps(new_history)
                new_encrypted = encrypt_data(json_data, SYSTEM_SECRET)
                with open(LOGIN_HISTORY_FILE, 'wb') as f:
                    f.write(new_encrypted)
                return jsonify({"success": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    return jsonify({"error": "File not found"}), 404

@app.route('/api/view_log', methods=['POST'])
def view_log():
    if 'logged_in' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    filename = data.get('filename')
    password = session.get('password')
    
    if not filename:
        return jsonify({"error": "No filename"}), 400
    
    file_path = os.path.join(LOG_DIR, filename)
    import struct
    from encryption import decrypt_data
    from concurrent.futures import ThreadPoolExecutor
    
    # Read all encrypted chunks first (fast I/O)
    chunks = []
    try:
        with open(file_path, "rb") as f:
            while True:
                length_bytes = f.read(4)
                if not length_bytes: break
                length = struct.unpack("<I", length_bytes)[0]
                encrypted_data = f.read(length)
                chunks.append(encrypted_data)
    except Exception as e:
        return jsonify({"error": f"Failed to read log: {str(e)}"}), 500
    
    # Decrypt all chunks concurrently (PBKDF2 is the bottleneck)
    def decrypt_chunk(chunk):
        try:
            return json.loads(decrypt_data(chunk, password))
        except:
            return None
    
    with ThreadPoolExecutor(max_workers=min(8, len(chunks) or 1)) as pool:
        results = list(pool.map(decrypt_chunk, chunks))
    
    entries = [r for r in results if r is not None]
    return jsonify(entries)

@app.route('/api/delete_log', methods=['POST'])
def api_delete_log():
    if 'logged_in' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    filename = data.get('filename')
    
    if not filename:
        return jsonify({"error": "No filename provided"}), 400
        
    if delete_log(filename):
        return jsonify({"success": True, "message": "Log deleted successfully"})
    else:
        return jsonify({"error": "Failed to delete log or file not found"}), 500

@app.route('/api/delete_logs_batch', methods=['POST'])
def api_delete_logs_batch():
    if 'logged_in' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    filenames = data.get('filenames', [])
    
    if not filenames:
        return jsonify({"error": "No filenames provided"}), 400
        
    success = True
    for filename in filenames:
        if not delete_log(filename):
            success = False
            
    if success:
        return jsonify({"success": True, "message": f"Deleted {len(filenames)} logs"})
    else:
        return jsonify({"error": "Some logs failed to delete"}), 500

@app.route('/api/export_logs', methods=['POST'])
def export_logs():
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    filenames = data.get('filenames', [])
    password = session.get('password')

    if not password:
        return jsonify({"error": "Session expired or password missing"}), 400

    if not filenames:
        return jsonify({"error": "No files selected"}), 400

    try:
        if len(filenames) == 1:
            # Export single file as .bin (Encrypted)
            filename = filenames[0]
            file_path = os.path.join(LOG_DIR, os.path.basename(filename))
            
            return send_file(
                file_path,
                mimetype='application/octet-stream',
                as_attachment=True,
                download_name=filename
            )
        else:
            # Export multiple files as ZIP containing encrypted .bin files
            memory_file = io.BytesIO()
            with zipfile.ZipFile(memory_file, 'w') as zf:
                for filename in filenames:
                    file_path = os.path.join(LOG_DIR, os.path.basename(filename))
                    try:
                        if os.path.exists(file_path):
                            zf.write(file_path, arcname=filename)
                    except:
                        continue # Skip corrupted or missing files in zip
            
            memory_file.seek(0)
            return send_file(
                memory_file,
                mimetype='application/zip',
                as_attachment=True,
                download_name=f"nids_logs_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
            )
    except Exception as e:
        print(f"[-] Export error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/delete_all_logs', methods=['POST'])
def api_delete_all_logs():
    if 'logged_in' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    if delete_all_logs():
        return jsonify({"success": True, "message": "All logs deleted successfully"})
    else:
        return jsonify({"error": "Failed to delete all logs"}), 500

@app.route('/api/rules_config', methods=['GET'])
def api_get_rules_config():
    if 'logged_in' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(load_config())

@app.route('/api/rules_config', methods=['POST'])
def api_update_rules_config():
    if 'logged_in' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    try:
        new_config = request.json
        save_config(new_config)
        return jsonify({"success": True, "message": "Configuration updated"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/rules_config/reset', methods=['POST'])
def api_reset_rules_config():
    if 'logged_in' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    try:
        save_config(get_default_config())
        return jsonify({"success": True, "message": "Configuration reset to defaults", "config": get_default_config()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@socketio.on('connect')
def handle_connect():
    global sniffer_active, current_session_file
    # Store password for this socket client
    if 'password' in session:
        client_passwords[request.sid] = session.get('password')
    if 'logged_in' in session:
        emit('status_update', {
            'status': 'active' if sniffer_active else 'inactive',
            'file': os.path.basename(current_session_file) if current_session_file else None
        })

@socketio.on('disconnect')
def handle_disconnect():
    client_passwords.pop(request.sid, None)

@socketio.on('toggle_sniffer')
def handle_toggle_sniffer(data):
    global sniffer_thread, sniffer_active, sniffer_password, current_session_file

    action = data.get('action')
    print(f"[*] Received toggle_sniffer: {action}")

    if action == 'start':
        if not sniffer_active:
            sniffer_active = True
            # Get password from our safe mapping or session
            sniffer_password = client_passwords.get(request.sid) or session.get('password')
            ensure_logs_dir()
            # Create session time with readable format
            now = datetime.now()
            month_name = now.strftime("%b")
            day = now.day
            year = now.year
            hour = int(now.strftime("%I"))
            minute = now.strftime("%M")
            second = now.strftime("%S")
            ampm = now.strftime("%p")
            session_time = f"{month_name}-{day}-{year}_{hour}-{minute}-{second}_{ampm}"
            current_session_file = os.path.join(LOG_DIR, f"web_session_{session_time}.bin")

            sniffer_thread = threading.Thread(target=run_sniffer)
            sniffer_thread.daemon = True
            sniffer_thread.start()

        # Always emit ONLY to the requesting client so they get unblocked
        emit('status_update', {
            'status': 'active',
            'file': os.path.basename(current_session_file)
        })

    elif action == 'stop':
        sniffer_active = False
        live_alerts.clear()
        emit('status_update', {'status': 'inactive'})

def run_sniffer():
    global sniffer_active, sniffer_password, current_session_file
    print("[*] Background sniffer thread started.")
    
    def web_packet_callback(packet_data):
        if not sniffer_active: return
        alert = analyze_packet(packet_data)
        if alert:
            now = datetime.now()
            alert['timestamp'] = now.strftime("%b %d, %Y • %I:%M:%S %p")
            save_encrypted_alert(alert, sniffer_password, current_session_file)
            live_alerts.append(alert)
            socketio.emit('new_alert', alert)

    def stop_sniffer_check(packet):
        return not sniffer_active

    try:
        start_sniffing(web_packet_callback, stop_check=stop_sniffer_check)
    except Exception as e:
        print(f"[!] Sniffer Error: {e}")
        sniffer_active = False
        socketio.emit('error', {'message': str(e)})

@app.route('/api/banned_ips')
def api_get_banned_ips():
    if 'logged_in' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(get_banned_ips())

@app.route('/api/unban_ip', methods=['POST'])
def api_unban_ip():
    if 'logged_in' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    ip = request.json.get('ip')
    if not ip:
        return jsonify({"error": "IP is required"}), 400
    
    banned = get_banned_ips()
    if ip in banned:
        del banned[ip]
        save_banned_ips(banned)
        
    # Also reset failed attempts for this IP
    attempts = get_failed_attempts()
    if ip in attempts:
        del attempts[ip]
        save_failed_attempts(attempts)
        
    return jsonify({"success": True})

@app.route('/api/ban_ip_manual', methods=['POST'])
def api_ban_manual():
    if 'logged_in' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    ip = request.json.get('ip')
    reason = request.json.get('reason', 'Manually banned by admin')
    if not ip:
        return jsonify({"error": "IP is required"}), 400
    
    banned = get_banned_ips()
    banned[ip] = {
        "reason": reason,
        "timestamp": datetime.now().strftime("%b %d, %Y • %I:%M %p"),
        "username": "N/A (Manual)"
    }
    save_banned_ips(banned)
    return jsonify({"success": True})

# ── Firewall (Network-Level) Ban API ─────────────────────────────────────────

@app.route('/api/firewall_banned_ips')
def api_get_firewall_banned_ips():
    if 'logged_in' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(get_firewall_banned_ips())

@app.route('/api/firewall_ban_ip', methods=['POST'])
def api_firewall_ban_ip():
    try:
        if 'logged_in' not in session:
            return jsonify({"error": "Unauthorized"}), 401
        
        ip = request.json.get('ip')
        reason = request.json.get('reason', 'Manually blocked at network level')
        if not ip:
            return jsonify({"error": "IP is required"}), 400

        success, message = fw_ban_ip(ip)
        if not success:
            print(f"[*] Firewall Ban Error: {message}")
            if "requires elevation" in message.lower() or "access is denied" in message.lower():
                return jsonify({
                    "error": "Administrator privileges required. Please restart the NIDS server as Administrator to use Firewall bans."
                }), 403
            return jsonify({"error": message}), 500

        fw_banned = get_firewall_banned_ips()
        fw_banned[ip] = {
            "reason": reason,
            "timestamp": datetime.now().strftime("%b %d, %Y • %I:%M %p"),
            "message": message
        }
        save_firewall_banned_ips(fw_banned)
        return jsonify({"success": True, "message": message})
    except Exception as e:
        print(f"[*] CRITICAL API ERROR: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/firewall_unban_ip', methods=['POST'])
def api_firewall_unban_ip():
    try:
        if 'logged_in' not in session:
            return jsonify({"error": "Unauthorized"}), 401
            
        ip = request.json.get('ip')
        if not ip:
            return jsonify({"error": "IP is required"}), 400

        success, message = fw_unban_ip(ip)
        if not success:
            print(f"[*] Firewall Unban Error: {message}")
            if "requires elevation" in message.lower() or "access is denied" in message.lower():
                return jsonify({
                    "error": "Administrator privileges required. Please restart the NIDS server as Administrator to remove Firewall bans."
                }), 403
            return jsonify({"error": message}), 500

        fw_banned = get_firewall_banned_ips()
        if ip in fw_banned:
            del fw_banned[ip]
            save_firewall_banned_ips(fw_banned)
        return jsonify({"success": True, "message": message})
    except Exception as e:
        print(f"[*] CRITICAL API ERROR: {e}")
        return jsonify({"error": str(e)}), 500

def print_dashboard_banner():
    # Only print on the main process (not the reloader)
    if os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        green = "\033[32m"
        cyan = "\033[36m"
        yellow = "\033[33m"
        reset = "\033[0m"
        bold = "\033[1m"
        
        print(f"\n  {bold}{cyan}NIDS SERVER v1.0.0{reset}  {green}ready{reset}")
        print(f"\n  {green}>{reset}  {bold}Dashboard:{reset}  {cyan}http://localhost:5000/{reset}")
        print(f"  {green}>{reset}  {bold}Network:{reset}    {yellow}http://{socket_get_host_ip()}:5000/{reset}")
        print(f"\n  {reset}Press {bold}Ctrl+C{reset} to stop\n")

def socket_get_host_ip():
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

if __name__ == '__main__':
    print_dashboard_banner()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
