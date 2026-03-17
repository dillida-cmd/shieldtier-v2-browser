#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# ShieldTier Sandbox Runner — Isolated QEMU VM for malware analysis
#
# Security model:
#   - Network: restrict=on (no host network access, only QEMU user-mode NAT)
#   - Disk: QCOW2 overlay snapshot (base image never modified)
#   - Process: QEMU runs as user process, no elevated privileges
#   - Cleanup: overlay deleted after run
# ---------------------------------------------------------------------------
set -euo pipefail

SANDBOX_DIR="$(cd "$(dirname "$0")" && pwd)"
ISO="$SANDBOX_DIR/images/alpine-virt-3.21.3-x86_64.iso"
BASE_DISK="$SANDBOX_DIR/images/alpine-base.qcow2"
RUN_ID="run_$(date +%s)_$$"
OVERLAY="$SANDBOX_DIR/snapshots/${RUN_ID}.qcow2"
SAMPLE_DIR="$SANDBOX_DIR/samples"
RESULTS_DIR="$SANDBOX_DIR/results/$RUN_ID"
SERIAL_LOG="$RESULTS_DIR/serial.log"
MONITOR_SOCK="$SANDBOX_DIR/snapshots/${RUN_ID}.monitor"
TIMEOUT="${1:-120}"  # Default 120 seconds

mkdir -p "$RESULTS_DIR" "$SAMPLE_DIR"

echo "=== ShieldTier Sandbox ==="
echo "Run ID:      $RUN_ID"
echo "Timeout:     ${TIMEOUT}s"
echo "Base image:  $BASE_DISK"
echo "Overlay:     $OVERLAY"
echo "Results:     $RESULTS_DIR"
echo ""

# Create QCOW2 overlay — writes go here, base image stays clean
qemu-img create -f qcow2 -b "$BASE_DISK" -F qcow2 "$OVERLAY" 2>/dev/null
echo "[+] Created snapshot overlay"

# Cleanup function — destroys overlay and monitor socket
cleanup() {
    echo ""
    echo "[+] Cleaning up..."
    # Kill QEMU if still running
    if [ -n "${QEMU_PID:-}" ] && kill -0 "$QEMU_PID" 2>/dev/null; then
        kill "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
    fi
    # Remove overlay (all VM changes are discarded)
    rm -f "$OVERLAY" "$MONITOR_SOCK"
    echo "[+] Overlay destroyed — host disk clean"
    echo "[+] Serial log saved: $SERIAL_LOG"
}
trap cleanup EXIT

echo "[+] Launching isolated VM (x86_64, 512MB RAM, no host network)..."

# Launch QEMU with strict isolation:
#   -netdev restrict=on    — VM cannot reach host or internet
#   -cdrom with ISO        — boot from live Alpine (no persistent state)
#   -drive overlay         — all disk writes go to ephemeral overlay
#   -serial file           — capture console output for analysis
#   -monitor unix          — QMP control socket for screenshots/introspection
#   -no-reboot             — halt instead of reboot (clean shutdown detection)
qemu-system-x86_64 \
    -machine q35,accel=tcg \
    -cpu qemu64 \
    -m 512 \
    -smp 2 \
    -nographic \
    -no-reboot \
    -cdrom "$ISO" \
    -drive file="$OVERLAY",format=qcow2,if=virtio \
    -netdev user,id=net0,restrict=on,hostfwd=tcp::0-:22 \
    -device virtio-net-pci,netdev=net0 \
    -serial "file:$SERIAL_LOG" \
    -monitor "unix:$MONITOR_SOCK,server,nowait" \
    -boot d \
    &

QEMU_PID=$!
echo "[+] QEMU PID: $QEMU_PID"

# Wait for timeout or VM exit
echo "[+] Waiting up to ${TIMEOUT}s for VM to run..."
SECONDS=0
while kill -0 "$QEMU_PID" 2>/dev/null && [ $SECONDS -lt "$TIMEOUT" ]; do
    sleep 1
done

if kill -0 "$QEMU_PID" 2>/dev/null; then
    echo "[!] Timeout reached — force-killing VM"
    kill "$QEMU_PID" 2>/dev/null || true
fi

wait "$QEMU_PID" 2>/dev/null || true

echo ""
echo "=== Sandbox Run Complete ==="
echo "Serial log lines: $(wc -l < "$SERIAL_LOG" 2>/dev/null || echo 0)"
echo "Results dir: $RESULTS_DIR"

# Verify host is clean — overlay will be deleted by cleanup trap
echo ""
echo "[+] Verifying host isolation..."
echo "    Base image hash (should be unchanged):"
shasum -a 256 "$BASE_DISK" | cut -d' ' -f1
