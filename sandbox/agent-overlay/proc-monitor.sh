#!/bin/sh
# ShieldTier /proc-based process monitor — replaces strace on minimal systems.
# Polls /proc for the target PID and captures:
#   - syscall in progress
#   - open file descriptors
#   - memory maps
#   - network sockets
#   - child processes

TARGET_PID="$1"
OUTDIR="$2"
INTERVAL="${3:-1}"  # poll interval in seconds

[ -z "$TARGET_PID" ] || [ -z "$OUTDIR" ] && {
    echo "Usage: proc-monitor.sh <pid> <output_dir> [interval_sec]"
    exit 1
}

mkdir -p "$OUTDIR"
LOG="$OUTDIR/procmon.log"
SNAP=0

log() { echo "[procmon $(date -u +%H:%M:%S)] $1" >> "$LOG"; }

log "Monitoring PID $TARGET_PID (interval: ${INTERVAL}s)"

while kill -0 "$TARGET_PID" 2>/dev/null; do
    SNAP=$((SNAP + 1))
    PREFIX="$OUTDIR/snap_$(printf '%04d' $SNAP)"

    # Current syscall
    cat "/proc/$TARGET_PID/syscall" > "${PREFIX}_syscall" 2>/dev/null

    # File descriptors
    ls -la "/proc/$TARGET_PID/fd" > "${PREFIX}_fds" 2>/dev/null

    # Memory maps (detect injected code, anonymous mappings)
    cat "/proc/$TARGET_PID/maps" > "${PREFIX}_maps" 2>/dev/null

    # Status (threads, signals, memory)
    cat "/proc/$TARGET_PID/status" > "${PREFIX}_status" 2>/dev/null

    # Command line
    tr '\0' ' ' < "/proc/$TARGET_PID/cmdline" > "${PREFIX}_cmdline" 2>/dev/null

    # Environment (may reveal C2 config)
    tr '\0' '\n' < "/proc/$TARGET_PID/environ" > "${PREFIX}_environ" 2>/dev/null

    # Network sockets (TCP/UDP)
    cat /proc/net/tcp > "${PREFIX}_tcp" 2>/dev/null
    cat /proc/net/udp > "${PREFIX}_udp" 2>/dev/null
    cat /proc/net/tcp6 > "${PREFIX}_tcp6" 2>/dev/null
    cat /proc/net/udp6 > "${PREFIX}_udp6" 2>/dev/null

    # Child processes
    CHILDREN=""
    for child_dir in /proc/[0-9]*/status; do
        child_pid=$(echo "$child_dir" | cut -d/ -f3)
        ppid=$(grep '^PPid:' "$child_dir" 2>/dev/null | awk '{print $2}')
        if [ "$ppid" = "$TARGET_PID" ]; then
            child_name=$(grep '^Name:' "$child_dir" 2>/dev/null | awk '{print $2}')
            CHILDREN="$CHILDREN $child_pid($child_name)"
        fi
    done
    [ -n "$CHILDREN" ] && log "Children:$CHILDREN"

    # New files in /tmp (detect drops)
    ls -la /tmp/ > "${PREFIX}_tmp" 2>/dev/null

    sleep "$INTERVAL"
done

log "Target PID $TARGET_PID exited after $SNAP snapshots"

# Generate summary
log "=== Monitor Summary ==="
log "Snapshots taken: $SNAP"

# Count unique TCP connections
if [ -f "$OUTDIR/snap_0001_tcp" ]; then
    TCP_CONNS=$(cat "$OUTDIR"/snap_*_tcp 2>/dev/null | grep -v 'local_address' | sort -u | wc -l)
    log "Unique TCP entries: $TCP_CONNS"
fi

# Count unique FDs across all snapshots
FD_TOTAL=$(cat "$OUTDIR"/snap_*_fds 2>/dev/null | grep -v 'total' | wc -l)
log "Total FD observations: $FD_TOTAL"

# Detect new /tmp files
FIRST_TMP="$OUTDIR/snap_0001_tmp"
LAST_TMP="$OUTDIR/snap_$(printf '%04d' $SNAP)_tmp"
if [ -f "$FIRST_TMP" ] && [ -f "$LAST_TMP" ]; then
    NEW_FILES=$(diff "$FIRST_TMP" "$LAST_TMP" 2>/dev/null | grep '^>' | wc -l)
    log "New files in /tmp: $NEW_FILES"
fi

log "=== End Monitor ==="
