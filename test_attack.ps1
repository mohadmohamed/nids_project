# NIDS Attack Simulation Script
# This script sends packets to trigger the NIDS dashboard for testing purposes.

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " NIDS Real-time Attack Simulator " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$target = "8.8.8.8"

Write-Host "[*] Starting ICMP Flood (Pings)..." -ForegroundColor Yellow
# Sends 30 pings rapidly
1..30 | ForEach-Object { ping -n 1 -l 10 -w 100 8.8.8.8 }

###

for ($i=0; $i -lt 200; $i++) {
    ping -n 1 192.168.1.10 | Out-Null
}

Write-Host "[+] ICMP Flood completed." -ForegroundColor Green

Write-Host "[*] Starting SYN Flood Simulation (TCP)..." -ForegroundColor Yellow
# Using python one-liner for a clean SYN capture simulation if scapy is available
python -c "from scapy.all import IP, TCP, send; send(IP(dst='$target')/TCP(flags='S'), count=20, verbose=False)"
Write-Host "[+] SYN Flood completed." -ForegroundColor Green

Write-Host "`n[*] Check your NIDS Dashboard - alerts should appear instantly!" -ForegroundColor Cyan
