#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# ShieldTier — Analyze .exe in isolated Windows VM
#
# Usage: ./analyze-exe.sh <path-to-exe> [timeout_seconds]
#
# Prerequisites:
#   - Windows QCOW2 base image at: sandbox/images/windows-base.qcow2
#   - Agent pre-installed at C:\ShieldTier\sandbox-agent.ps1
#   - VirtIO drivers installed in Windows guest
#
# Isolation:
#   - QCOW2 overlay (base image immutable)
#   - Network: restrict=on (no host/internet access)
#   - virtfs 9p share for sample injection + result collection
#   - Overlay destroyed after run
# ---------------------------------------------------------------------------
set -euo pipefail

SANDBOX_DIR="$(cd "$(dirname "$0")" && pwd)"
SAMPLE="${1:?Usage: $0 <exe_path> [timeout]}"
TIMEOUT="${2:-120}"
BASE_IMAGE="${SHIELDTIER_WIN_IMAGE:-$SANDBOX_DIR/images/windows11-base.qcow2}"
RUN_ID="win_$(date +%s)_$$"
OVERLAY="$SANDBOX_DIR/snapshots/${RUN_ID}.qcow2"
SHARE_DIR="$SANDBOX_DIR/dynamic-win-${RUN_ID}"

if [ ! -f "$BASE_IMAGE" ]; then
    echo "ERROR: Windows base image not found at $BASE_IMAGE"
    echo "Run: ./setup-windows-vm.sh to create it"
    exit 1
fi

if [ ! -f "$SAMPLE" ]; then
    echo "ERROR: Sample not found: $SAMPLE"
    exit 1
fi

SAMPLE_NAME=$(basename "$SAMPLE")
SAMPLE_SHA256=$(shasum -a 256 "$SAMPLE" | cut -d' ' -f1)

mkdir -p "$SHARE_DIR/samples" "$SHARE_DIR/results"
cp "$SAMPLE" "$SHARE_DIR/samples/"

echo "=================================================="
echo "  ShieldTier — Windows .exe Dynamic Analysis"
echo "=================================================="
echo "Sample:   $SAMPLE_NAME"
echo "SHA256:   $SAMPLE_SHA256"
echo "Timeout:  ${TIMEOUT}s"
echo "Run ID:   $RUN_ID"
echo "Network:  ISOLATED"
echo ""

# --- Static analysis first ---
echo "--- Static Analysis ---"
if [ -f "$SANDBOX_DIR/../build/shieldtier_analyze" ]; then
    "$SANDBOX_DIR/../build/shieldtier_analyze" "$SAMPLE" 2>&1
    echo ""
fi

# --- Dynamic analysis in VM ---
echo "--- Dynamic Analysis (Windows VM) ---"

# Record base image hash
BASE_HASH=$(shasum -a 256 "$BASE_IMAGE" | cut -d' ' -f1)
echo "Base image hash: $BASE_HASH"

# Create overlay
qemu-img create -f qcow2 -b "$BASE_IMAGE" -F qcow2 "$OVERLAY" 2>/dev/null
echo "[+] Overlay created"

# Cleanup on exit
cleanup() {
    [ -n "${QEMU_PID:-}" ] && kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null || true
    rm -f "$OVERLAY"
    echo "[+] Overlay destroyed"

    # Verify host
    POST_HASH=$(shasum -a 256 "$BASE_IMAGE" | cut -d' ' -f1)
    if [ "$BASE_HASH" = "$POST_HASH" ]; then
        echo "[+] Host isolation: PASS (base image unchanged)"
    else
        echo "[!] Host isolation: FAIL (base image modified!)"
    fi
}
trap cleanup EXIT

echo "[+] Launching Windows VM..."
qemu-system-x86_64 \
    -machine q35,accel=tcg \
    -cpu qemu64 \
    -m 4096 \
    -smp 4 \
    -display none \
    -no-reboot \
    -drive "file=$OVERLAY,format=qcow2" \
    -netdev "user,id=net0,restrict=on" \
    -device "e1000,netdev=net0" \
    -virtfs "local,path=$SHARE_DIR,mount_tag=samples,security_model=mapped-xattr,id=host0" \
    &

QEMU_PID=$!
echo "[+] QEMU PID: $QEMU_PID"
echo "[+] Waiting ${TIMEOUT}s for analysis..."

# Wait for VM to finish or timeout
SECONDS=0
while kill -0 "$QEMU_PID" 2>/dev/null && [ $SECONDS -lt "$TIMEOUT" ]; do
    # Check for results periodically
    if [ -f "$SHARE_DIR/results/agent.log" ]; then
        LINES=$(wc -l < "$SHARE_DIR/results/agent.log" 2>/dev/null || echo 0)
        if grep -q "All samples processed" "$SHARE_DIR/results/agent.log" 2>/dev/null; then
            echo "[+] Agent completed analysis"
            break
        fi
    fi
    sleep 5
done

echo ""
echo "--- Results ---"
if [ -f "$SHARE_DIR/results/agent.log" ]; then
    cat "$SHARE_DIR/results/agent.log"
else
    echo "No results (Windows may not have booted in time)"
    echo "Try increasing timeout: $0 $SAMPLE 300"
fi

echo ""
echo "--- Artifacts ---"
find "$SHARE_DIR/results" -type f 2>/dev/null | while read f; do
    SIZE=$(wc -c < "$f" | tr -d ' ')
    echo "  $(echo "$f" | sed "s|$SHARE_DIR/results/||") (${SIZE}B)"
done

# Cleanup share
rm -rf "$SHARE_DIR"
echo "[+] Share directory cleaned"
