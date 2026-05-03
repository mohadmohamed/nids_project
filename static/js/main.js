const socket = io();
let snifferActive = false;
let alertCount = 0;

// Initialize on load
document.addEventListener('DOMContentLoaded', () => {
    checkInitialState();
    
    // Set initial tab from server variable
    if (window.INITIAL_TAB) {
        showTab(window.INITIAL_TAB, false); // false = don't push state again
    } else {
        showTab('dashboard', false);
    }

    // Handle back/forward buttons
    window.onpopstate = (event) => {
        if (event.state && event.state.tab) {
            showTab(event.state.tab, false);
        }
    };

    // Attach click listeners to nav items for SPA feel
    document.querySelectorAll('.nav-item').forEach(item => {
        if (item.classList.contains('logout')) return;
        
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const tabName = item.getAttribute('href').replace('/', '');
            showTab(tabName);
        });
    });
});

// Sync state with server
async function checkInitialState() {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();
        if (data.active) {
            updateStatusUI('active', data.file);
            // Restore live alerts from server buffer
            if (data.alerts && data.alerts.length > 0) {
                alertCount = data.alert_count || data.alerts.length;
                document.getElementById('total-alerts').innerText = alertCount;
                const alertList = document.getElementById('alert-list');
                alertList.innerHTML = '';
                data.alerts.forEach(alert => addAlertToList(alert, 'alert-list'));
            }
        } else {
            updateStatusUI('inactive');
        }
    } catch (e) {
        console.error("Failed to sync state:", e);
    }
}

// Logic to show different tabs
function showTab(tabName, shouldPushState = true) {
    document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));
    
    const tabEl = document.getElementById(`${tabName}-tab`);
    if (!tabEl) return;
    
    tabEl.classList.add('active');
    
    // Highlight correct nav item
    const navItem = document.getElementById(`nav-${tabName}`);
    if (navItem) navItem.classList.add('active');

    if (tabName === 'history') loadLogFiles();
    if (tabName === 'login-history') loadLoginHistory();
    if (tabName === 'banned-ips') { loadBannedIPs(); loadFirewallBannedIPs(); }
    if (tabName === 'settings') loadRulesConfig();

    // Update URL without reload
    if (shouldPushState) {
        history.pushState({ tab: tabName }, "", `/${tabName}`);
    }
}

/**
 * Custom Confirmation Modal Logic
 */
let currentConfirmAction = null;

function showConfirmModal(title, message, confirmText, onConfirm) {
    document.getElementById('modal-title').innerText = title;
    document.getElementById('modal-message').innerText = message;
    const confirmBtn = document.getElementById('modal-confirm-btn');
    confirmBtn.innerText = confirmText;
    
    currentConfirmAction = onConfirm;
    
    document.getElementById('confirm-modal').classList.add('active');
}

function closeModal() {
    document.getElementById('confirm-modal').classList.remove('active');
    currentConfirmAction = null;
}

// Initial setup for modal
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('modal-confirm-btn').onclick = () => {
        if (currentConfirmAction) currentConfirmAction();
        closeModal();
    };
});

function toggleSniffer() {
    const btn = document.getElementById('toggle-btn');
    const action = snifferActive ? 'stop' : 'start';
    
    // Visual feedback that request was sent
    btn.disabled = true;
    btn.innerText = 'Processing...';
    
    socket.emit('toggle_sniffer', { action: action });
}

// Socket communication
socket.on('status_update', (data) => {
    const btn = document.getElementById('toggle-btn');
    btn.disabled = false;
    updateStatusUI(data.status, data.file);
});

socket.on('new_alert', (alert) => {
    addAlertToList(alert, 'alert-list');
    updateStats();
    triggerAlertEffect();
});

socket.on('error', (data) => {
    alert('System Error: ' + data.message);
    const btn = document.getElementById('toggle-btn');
    btn.disabled = false;
    btn.innerText = 'Start Monitoring';
});

function formatSessionName(file) {
    if (!file) return 'session.bin';
    
    // New format: web_session_Apr-25-2026_3-55-21_AM.bin
    const newMatch = file.match(/web_session_([A-Za-z]+)-(\d{1,2})-(\d{4})_(\d{1,2})-(\d{2})-(\d{2})_(AM|PM)\.bin/);
    if (newMatch) {
        const [_, month, day, year, hour, min, sec, ampm] = newMatch;
        return `${month} ${parseInt(day)}, ${year} • ${parseInt(hour)}:${min} ${ampm}`;
    }
    
    // Old format: web_session_2026-04-25_03-55-21_AM.bin
    const oldMatch = file.match(/web_session_(\d{4})-(\d{2})-(\d{2})_(\d{1,2})-(\d{2})-(\d{2})_(AM|PM)\.bin/);
    if (oldMatch) {
        const [_, year, month, day, hour, min, sec, ampm] = oldMatch;
        const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
        const monthName = months[parseInt(month) - 1];
        return `${monthName} ${parseInt(day)}, ${year} • ${parseInt(hour)}:${min} ${ampm}`;
    }
    
    return file;
}

function updateStatusUI(status, fileName) {
    const btn = document.getElementById('toggle-btn');
    const dot = document.getElementById('status-dot');
    const text = document.getElementById('status-text');
    const sessionInfo = document.getElementById('session-file');
    const alertList = document.getElementById('alert-list');

    if (status === 'active') {
        snifferActive = true;
        btn.innerHTML = `
            <svg class="btn-icon" width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="6" width="12" height="12"></rect></svg>
            <span>Stop Monitoring</span>
        `;
        btn.className = 'btn primary active'; // Use the red gradient 'active' style
        dot.className = 'dot active';
        text.innerText = 'System Active';
        sessionInfo.innerText = 'Logging to: ' + formatSessionName(fileName);
        
        // Update empty state if no alerts yet
        const emptyState = alertList.querySelector('.empty-state');
        if (emptyState) {
            emptyState.innerText = 'Monitoring active... Scanning for threats.';
            emptyState.classList.add('pulse-text');
        }
    } else {
        snifferActive = false;
        btn.innerHTML = `
            <svg class="btn-icon" width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"></path></svg>
            <span>Start Monitoring</span>
        `;
        btn.className = 'btn primary';
        dot.className = 'dot inactive';
        text.innerText = 'System Inactive';
        sessionInfo.innerText = 'No session active';

        // Reset empty state if list is empty
        if (alertList.children.length <= 1 && alertList.querySelector('.empty-state')) {
            const emptyState = alertList.querySelector('.empty-state');
            emptyState.innerText = 'Waiting for monitoring to start...';
            emptyState.classList.remove('pulse-text');
        }
    }
}

function addAlertToList(alert, containerId) {
    const container = document.getElementById(containerId);
    if (container.querySelector('.empty-state')) {
        container.innerHTML = '';
    }

    const div = document.createElement('div');
    div.className = 'alert-item';
    div.innerHTML = `
        <div class="alert-info">
            <span class="alert-type">${alert.attack_type || alert.type || "Unknown Attack"}</span>
            <span class="alert-ips">${alert.attacker_ip || alert.src} → ${alert.victim_ip || alert.dst}</span>
        </div>
        <span class="alert-time">${alert.timestamp}</span>
    `;
    container.prepend(div);
}

function updateStats() {
    alertCount++;
    document.getElementById('total-alerts').innerText = alertCount;
}

function triggerAlertEffect() {
    const cards = document.querySelectorAll('.stat-card');
    cards.forEach(card => {
        card.classList.add('pulse-glow');
        setTimeout(() => card.classList.remove('pulse-glow'), 2000);
    });
}

// HISTORY LOGS
async function loadLogFiles() {
    const response = await fetch('/api/logs');
    const files = await response.json();
    const list = document.getElementById('log-file-list');
    list.innerHTML = '';

    files.forEach(file => {
        const displayName = formatSessionName(file);

        const div = document.createElement('div');
        div.className = 'file-item';
        div.innerHTML = `
            <div style="display: flex; align-items: center; gap: 12px; flex: 1;">
                <input type="checkbox" class="file-checkbox" value="${file}" onclick="toggleDeleteSelectedBtn(event)">
                <span class="file-name">${displayName}</span>
            </div>
            <button class="delete-btn" onclick="deleteLogFile('${file}', this.parentElement, event)" title="Delete Session">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18"></path><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
            </button>
        `;
        div.onclick = (e) => {
            // Prevent viewing when clicking the delete button or checkbox
            if(e.target.tagName !== 'BUTTON' && e.target.tagName !== 'INPUT' && e.target.closest('.delete-btn') === null) {
                viewLogFile(file, div);
            }
        };
        list.appendChild(div);
    });
}

async function deleteLogFile(filename, element, event) {
    if (event) event.stopPropagation(); // Prevent opening the viewer
    
    showConfirmModal(
        'Delete Session?',
        `Are you sure you want to permanently delete "${filename}"? This action cannot be undone.`,
        'Delete Session',
        async () => {
            try {
                const response = await fetch('/api/delete_log', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ filename })
                });
                
                if (response.ok) {
                    element.remove();
                    showToast('Session deleted successfully', 'success');
                    // Clear viewer if current file was deleted
                    if (document.getElementById('viewer-title').innerText === filename) {
                        document.getElementById('viewer-title').innerText = 'Select a session';
                        document.getElementById('viewer-content').innerHTML = '<div class="empty-state">Logs will appear here after selection.</div>';
                    }
                }
            } catch (error) {
                showToast('Failed to delete session', 'error');
            }
        }
    );
}

async function deleteAllLogFiles() {
    showConfirmModal(
        'Delete All Sessions?',
        'Are you sure you want to permanently delete ALL historical sessions? This action cannot be undone.',
        'Delete Everything',
        async () => {
            try {
                const response = await fetch('/api/delete_all_logs', { method: 'POST' });
                if (response.ok) {
                    document.getElementById('log-file-list').innerHTML = '';
                    document.getElementById('viewer-title').innerText = 'Select a session';
                    document.getElementById('viewer-content').innerHTML = '<div class="empty-state">Logs will appear here after selection.</div>';
                    showToast('All sessions deleted successfully', 'success');
                } else {
                    showToast('Failed to delete all sessions', 'error');
                }
            } catch (e) {
                showToast(`Connection Error: ${e.message || 'Server unreachable'}`, 'error');
            }
        }
    );
}

function toggleDeleteSelectedBtn(event) {
    if (event) event.stopPropagation();
    const checkboxes = document.querySelectorAll('.file-checkbox:checked');
    const deleteBtn = document.getElementById('btn-delete-selected');
    const exportBtn = document.getElementById('btn-export-selected');
    const deselectBtn = document.getElementById('btn-deselect-all');
    
    if (checkboxes.length > 0) {
        deleteBtn.style.display = 'flex';
        exportBtn.style.display = 'flex';
        if (deselectBtn) deselectBtn.style.display = 'flex';
        
        deleteBtn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18"></path><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg> Delete (${checkboxes.length})`;
        exportBtn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg> Export (${checkboxes.length})`;
    } else {
        deleteBtn.style.display = 'none';
        exportBtn.style.display = 'none';
        if (deselectBtn) deselectBtn.style.display = 'none';
    }
}

function deselectAllLogs() {
    document.querySelectorAll('.file-checkbox').forEach(cb => cb.checked = false);
    toggleDeleteSelectedBtn();
}

async function exportSelectedLogs() {
    const checkboxes = document.querySelectorAll('.file-checkbox:checked');
    const filesToExport = Array.from(checkboxes).map(cb => cb.value);
    
    if (filesToExport.length === 0) return;

    showToast('Preparing download...', 'info');

    try {
        const response = await fetch('/api/export_logs', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filenames: filesToExport })
        });
        
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            
            // Set filename based on count
            if (filesToExport.length === 1) {
                a.download = filesToExport[0].replace('.bin', '.json');
            } else {
                a.download = `nids_logs_export_${new Date().getTime()}.zip`;
            }
            
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            showToast('Download started', 'success');
        } else {
            const err = await response.json();
            showToast(err.error || 'Export failed', 'error');
        }
    } catch (e) {
        showToast(`Connection Error: ${e.message || 'Server unreachable'}`, 'error');
    }
}

async function deleteSelectedLogs() {
    const checkboxes = document.querySelectorAll('.file-checkbox:checked');
    const filesToDelete = Array.from(checkboxes).map(cb => cb.value);
    
    if (filesToDelete.length === 0) return;

    showConfirmModal(
        'Delete Selected Sessions?',
        `Are you sure you want to permanently delete ${filesToDelete.length} session(s)? This action cannot be undone.`,
        'Delete Selected',
        async () => {
            try {
                const response = await fetch('/api/delete_logs_batch', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ filenames: filesToDelete })
                });
                
                if (response.ok) {
                    showToast(`${filesToDelete.length} sessions deleted successfully`, 'success');
                    
                    document.getElementById('viewer-title').innerText = 'Select a session';
                    document.getElementById('viewer-content').innerHTML = '<div class="empty-state">Logs will appear here after selection.</div>';
                    
                    loadLogFiles();
                    toggleDeleteSelectedBtn();
                } else {
                    showToast('Failed to delete some sessions', 'error');
                }
            } catch (e) {
                showToast(`Connection Error: ${e.message || 'Server unreachable'}`, 'error');
            }
        }
    );
}

async function viewLogFile(filename, element) {
    // UI selection
    document.querySelectorAll('.file-item').forEach(i => i.classList.remove('active'));
    element.classList.add('active');
    
    const displayName = formatSessionName(filename);
    document.getElementById('viewer-title').innerText = 'Loading...';
    document.getElementById('viewer-content').innerHTML = '<div class="empty-state">Decrypting session data...</div>';
    
    const response = await fetch('/api/view_log', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filename: filename })
    });
    
    const entries = await response.json();
    const content = document.getElementById('viewer-content');
    content.innerHTML = '';
    document.getElementById('viewer-title').innerText = displayName;

    if (entries.length === 0) {
        content.innerHTML = '<div class="empty-state">No alerts found in this session or wrong password.</div>';
    } else {
        // Batch render for better performance
        const fragment = document.createDocumentFragment();
        entries.forEach(entry => {
            const div = document.createElement('div');
            div.className = 'alert-item';
            const timeStr = entry.timestamp || '';
            div.innerHTML = `
                <div class="alert-info">
                    <h4>${entry.attack_type || 'Unknown'}</h4>
                    <span class="subtext">${entry.attacker_ip || '?'} → ${entry.victim_ip || '?'}</span>
                </div>
                <span class="alert-time">${timeStr}</span>
            `;
            fragment.appendChild(div);
        });
        content.appendChild(fragment);
    }
}

// Toast Management
function showToast(message, type = 'success') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    let icon = '';
    if (type === 'success') {
        icon = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>';
    } else if (type === 'info') {
        icon = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>';
    } else {
        icon = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>';
    }
    
    toast.innerHTML = `${icon} <span>${message}</span>`;
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(20px)';
        toast.style.transition = 'all 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// Password Management
async function updatePassword() {
    const oldPwd = document.getElementById('old-pwd').value;
    const newPwd = document.getElementById('new-pwd').value;
    const confirmPwd = document.getElementById('confirm-pwd').value;

    if (!oldPwd || !newPwd || !confirmPwd) {
        showPwdMessage("Please fill all fields", "error");
        return;
    }

    if (newPwd !== confirmPwd) {
        showPwdMessage("Passwords do not match!", "error");
        return;
    }

    const response = await fetch('/api/change_password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ old_password: oldPwd, new_password: newPwd })
    });

    const result = await response.json();
    if (result.success) {
        showPwdMessage("Password updated successfully!", "success");
        document.getElementById('old-pwd').value = '';
        document.getElementById('new-pwd').value = '';
        document.getElementById('confirm-pwd').value = '';
    } else {
        showPwdMessage(result.error || "Failed to update password", "error");
    }
}

function showPwdMessage(text, type) {
    const msgEl = document.getElementById('pwd-msg');
    msgEl.innerText = text;
    msgEl.style.display = 'block';
    msgEl.style.background = type === 'success' ? 'rgba(0, 255, 157, 0.1)' : 'rgba(255, 77, 77, 0.1)';
    msgEl.style.color = type === 'success' ? 'var(--accent-green)' : 'var(--accent-red)';
    msgEl.style.border = `1px solid ${type === 'success' ? 'rgba(0, 255, 157, 0.2)' : 'rgba(255, 77, 77, 0.2)'}`;
    
    setTimeout(() => {
        msgEl.style.display = 'none';
    }, 5000);
}

// Clear ALL login history
async function clearLoginHistory() {
    showConfirmModal(
        'Clear All History?',
        'This will permanently delete ALL login attempt logs. Are you sure?',
        'Clear Everything',
        async () => {
            const response = await fetch('/api/clear_login_history', { method: 'POST' });
            if (response.ok) {
                document.getElementById('login-history-body').innerHTML = '';
                showToast('Login history cleared', 'success');
            }
        }
    );
}

// Delete single login entry
async function deleteLoginEntry(id) {
    showConfirmModal(
        'Delete Log Entry?',
        'Are you sure you want to remove this login attempt from the logs?',
        'Delete Entry',
        async () => {
            const response = await fetch('/api/delete_login_entry', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id })
            });

            if (response.ok) {
                loadLoginHistory();
                showToast('Log entry removed', 'success');
            }
        }
    );
}


async function loadLoginHistory() {
    const tbody = document.getElementById('login-history-body');
    if (!tbody) return;
    
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;">Loading...</td></tr>';
    
    try {
        const response = await fetch('/api/login_history');
        const data = await response.json();
        
        tbody.innerHTML = '';
        if (data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;">No history recorded yet.</td></tr>';
            return;
        }

        data.forEach(event => {
            const row = document.createElement('tr');
            const isSuccess = event.status === 'Success';
            const badgeClass = isSuccess ? 'status-success' : 'status-failed';
            const icon = isSuccess 
                ? '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>'
                : '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>';
            
            row.innerHTML = `
                <td style="color: var(--text-secondary);">${event.timestamp}</td>
                <td style="font-weight: 600;">${event.username}</td>
                <td style="font-family: monospace; color: var(--accent-blue);">${event.ip}</td>
                <td>
                    <span class="status-badge ${badgeClass}">
                        ${icon} ${event.status}
                    </span>
                </td>
                <td style="text-align: right;">
                    <button class="delete-btn" onclick="deleteLoginEntry('${event.id}')" title="Delete Entry">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18"></path><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
                    </button>
                </td>
            `;
            tbody.appendChild(row);
        });
    } catch (e) {
        console.error("Failed to load login history:", e);
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:#ef4444;">Error loading history.</td></tr>';
    }
}

/**
 * Banned IPs Management
 */
async function loadBannedIPs() {
    const tbody = document.getElementById('banned-ips-body');
    if (!tbody) return;
    
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">Checking ban list...</td></tr>';
    
    try {
        const response = await fetch('/api/banned_ips');
        const banned = await response.json();
        
        tbody.innerHTML = '';
        const ips = Object.keys(banned);
        
        if (ips.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">No IPs are currently banned.</td></tr>';
            return;
        }

        ips.forEach(ip => {
            const data = banned[ip];
            const row = document.createElement('tr');
            row.innerHTML = `
                <td style="font-family: monospace; font-weight: 600; color: var(--accent-red);">${ip}</td>
                <td style="color: var(--text-secondary); max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${data.reason}">${data.reason}</td>
                <td style="color: var(--text-secondary);">${data.username}</td>
                <td style="color: var(--text-secondary);">${data.timestamp}</td>
                <td style="text-align: right;">
                    <button class="delete-btn" onclick="unbanIP('${ip}')" title="Remove Ban">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18"></path><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
                    </button>
                </td>
            `;
            tbody.appendChild(row);
        });
    } catch (e) {
        console.error("Failed to load banned list:", e);
        showToast('Error loading ban list', 'error');
    }
}

async function manualBanIP() {
    const ipInput = document.getElementById('ban-ip-input');
    const reasonInput = document.getElementById('ban-reason-input');
    const ip = ipInput.value.trim();
    const reason = reasonInput.value.trim();

    if (!ip) {
        showToast('Please enter a valid IP address', 'error');
        return;
    }

    try {
        const response = await fetch('/api/ban_ip_manual', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, reason })
        });

        if (response.ok) {
            showToast(`IP ${ip} banned successfully`, 'success');
            ipInput.value = '';
            reasonInput.value = '';
            loadBannedIPs();
        } else {
            showToast('Failed to ban IP', 'error');
        }
    } catch (e) {
        showToast('System error occurred', 'error');
    }
}

async function unbanIP(ip) {
    showConfirmModal(
        'Remove Ban?',
        `Are you sure you want to restore access for IP ${ip}?`,
        'Restore Access',
        async () => {
            try {
                const response = await fetch('/api/unban_ip', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip })
                });

                if (response.ok) {
                    showToast('IP unbanned successfully', 'success');
                    loadBannedIPs();
                } else {
                    showToast('Failed to remove ban', 'error');
                }
            } catch (e) {
                showToast(`Connection Error: ${e.message || 'Server unreachable'}`, 'error');
            }
        }
    );
}

/**
 * Firewall (Network-Level) Ban Management
 */
async function loadFirewallBannedIPs() {
    const tbody = document.getElementById('firewall-banned-ips-body');
    if (!tbody) return;

    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;">Checking firewall rules...</td></tr>';

    try {
        const response = await fetch('/api/firewall_banned_ips');
        const banned = await response.json();

        tbody.innerHTML = '';
        const ips = Object.keys(banned);

        if (ips.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color: var(--text-secondary);">No IPs are currently blocked at the firewall level.</td></tr>';
            return;
        }

        ips.forEach(ip => {
            const data = banned[ip];
            const row = document.createElement('tr');
            row.innerHTML = `
                <td style="font-family: monospace; font-weight: 600; color: #a78bfa;">${ip}</td>
                <td style="color: var(--text-secondary); max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${data.reason}">${data.reason}</td>
                <td style="color: var(--text-secondary);">${data.timestamp}</td>
                <td style="text-align: right;">
                    <button class="delete-btn" onclick="unbanFirewallIP('${ip}')" title="Remove Firewall Ban" style="border-color: rgba(167,139,250,0.3); color: #a78bfa;">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18"></path><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
                    </button>
                </td>
            `;
            tbody.appendChild(row);
        });
    } catch (e) {
        console.error("Failed to load firewall ban list:", e);
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:#ef4444;">Error loading firewall rules.</td></tr>';
    }
}

async function manualFirewallBanIP() {
    const ipInput = document.getElementById('fw-ban-ip-input');
    const reasonInput = document.getElementById('fw-ban-reason-input');
    const ip = ipInput.value.trim();
    const reason = reasonInput.value.trim() || 'Manually blocked at network level';

    if (!ip) {
        showToast('Please enter a valid IP address', 'error');
        return;
    }

    try {
        const response = await fetch('/api/firewall_ban_ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, reason })
        });

        const result = await response.json();

        if (response.status === 403) {
            const notice = document.getElementById('fw-admin-notice');
            if (notice) notice.style.display = 'flex';
            showToast('Admin privileges required — see the notice above', 'error');
            return;
        }

        if (response.ok) {
            const notice = document.getElementById('fw-admin-notice');
            if (notice) notice.style.display = 'none';
            showToast(`✓ ${ip} blocked at Windows Firewall level`, 'success');
            ipInput.value = '';
            reasonInput.value = '';
            loadFirewallBannedIPs();
        } else {
            showToast(result.error || 'Failed to add firewall rule', 'error');
        }
    } catch (e) {
        showToast(`Connection Error: ${e.message || 'Server unreachable'}`, 'error');
    }
}

async function unbanFirewallIP(ip) {
    showConfirmModal(
        'Remove Firewall Block?',
        `This will delete the Windows Firewall rules for ${ip}, allowing it to communicate with your device again. Are you sure?`,
        'Remove Block',
        async () => {
            try {
                const response = await fetch('/api/firewall_unban_ip', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip })
                });

                const result = await response.json();

                if (response.status === 403) {
                    const notice = document.getElementById('fw-admin-notice');
                    if (notice) notice.style.display = 'flex';
                    showToast('Admin privileges required to remove firewall rules', 'error');
                    return;
                }

                if (response.ok) {
                    showToast(`Firewall block removed for ${ip}`, 'success');
                    loadFirewallBannedIPs();
                } else {
                    showToast(result.error || 'Failed to remove firewall rule', 'error');
                }
            } catch (e) {
                showToast(`Connection Error: ${e.message || 'Server unreachable'}`, 'error');
            }
        }
    );
}

/**
 * Rules Configuration Management
 */
async function loadRulesConfig() {
    try {
        const response = await fetch('/api/rules_config');
        const config = await response.json();
        populateSettingsForm(config);
    } catch (e) {
        console.error('Failed to load rules config:', e);
        showToast('Failed to load settings', 'error');
    }
}

function populateSettingsForm(config) {
    document.getElementById('cfg-time-window').value = config.time_window || 10;
    document.getElementById('cfg-icmp-standard').value = config.icmp_flood?.standard || 30;
    document.getElementById('cfg-icmp-trusted').value = config.icmp_flood?.trusted || 100;
    document.getElementById('cfg-syn-standard').value = config.syn_flood?.standard || 30;
    document.getElementById('cfg-syn-trusted').value = config.syn_flood?.trusted || 80;
    document.getElementById('cfg-cpt-standard').value = config.common_port_traffic?.standard || 800;
    document.getElementById('cfg-cpt-trusted').value = config.common_port_traffic?.trusted || 1500;
    document.getElementById('cfg-ddos-standard').value = config.ddos?.standard || 800;
    document.getElementById('cfg-ddos-trusted').value = config.ddos?.trusted || 2000;
    document.getElementById('cfg-ps-standard').value = config.port_scan?.standard || 20;
    document.getElementById('cfg-ps-trusted').value = config.port_scan?.trusted || 40;
}

function gatherSettingsForm() {
    return {
        time_window: parseInt(document.getElementById('cfg-time-window').value) || 10,
        icmp_flood: {
            standard: parseInt(document.getElementById('cfg-icmp-standard').value) || 30,
            trusted: parseInt(document.getElementById('cfg-icmp-trusted').value) || 100
        },
        syn_flood: {
            standard: parseInt(document.getElementById('cfg-syn-standard').value) || 30,
            trusted: parseInt(document.getElementById('cfg-syn-trusted').value) || 80
        },
        common_port_traffic: {
            standard: parseInt(document.getElementById('cfg-cpt-standard').value) || 800,
            trusted: parseInt(document.getElementById('cfg-cpt-trusted').value) || 1500
        },
        ddos: {
            standard: parseInt(document.getElementById('cfg-ddos-standard').value) || 800,
            trusted: parseInt(document.getElementById('cfg-ddos-trusted').value) || 2000
        },
        port_scan: {
            standard: parseInt(document.getElementById('cfg-ps-standard').value) || 20,
            trusted: parseInt(document.getElementById('cfg-ps-trusted').value) || 40
        },
        common_ports: [80, 443, 22, 21, 53, 3306, 3389, 8080],
        trusted_ip_prefixes: ["142.250.", "172.217.", "142.251.", "8.8.8.", "8.8.4."]
    };
}

async function saveRulesConfig() {
    const config = gatherSettingsForm();
    try {
        const response = await fetch('/api/rules_config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });
        if (response.ok) {
            showToast('Configuration saved successfully', 'success');
        } else {
            showToast('Failed to save configuration', 'error');
        }
    } catch (e) {
        showToast(`Connection Error: ${e.message || 'Server unreachable'}`, 'error');
    }
}

async function resetRulesConfig() {
    showConfirmModal(
        'Reset to Defaults?',
        'This will reset ALL detection thresholds back to the factory defaults. Are you sure?',
        'Reset Defaults',
        async () => {
            try {
                const response = await fetch('/api/rules_config/reset', { method: 'POST' });
                const data = await response.json();
                if (response.ok) {
                    populateSettingsForm(data.config);
                    showToast('Settings reset to defaults', 'success');
                } else {
                    showToast('Failed to reset settings', 'error');
                }
            } catch (e) {
                showToast(`Connection Error: ${e.message || 'Server unreachable'}`, 'error');
            }
        }
    );
}
