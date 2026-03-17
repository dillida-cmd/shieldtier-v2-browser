#!/bin/sh
# ShieldTier Sandbox Agent v2.0
# Runs inside Alpine Linux VM. Executes samples under /proc monitoring.
# No external dependencies (no strace/ltrace needed).

SHARE="/mnt/hostshare"
SAMPLE_DIR="$SHARE/samples"
RESULT_DIR="$SHARE/results"
MONITOR="$SHARE/agent-overlay/proc-monitor.sh"

log() { echo "[agent $(date -u +%H:%M:%S)] $1" | tee -a "$RESULT_DIR/agent.log"; }

mkdir -p "$RESULT_DIR" 2>/dev/null

log "========================================="
log "  ShieldTier Sandbox Agent v2.0"
log "========================================="
log "Hostname:  $(hostname)"
log "Kernel:    $(uname -r)"
log "Arch:      $(uname -m)"
log "Memory:    $(grep MemTotal /proc/meminfo | awk '{print $2 " " $3}')"
log "CPUs:      $(nproc 2>/dev/null || echo 1)"
log ""

# Baseline
ps aux > "$RESULT_DIR/baseline_ps.txt" 2>&1
ls -laR /tmp/ > "$RESULT_DIR/baseline_tmp.txt" 2>&1
cat /proc/net/tcp > "$RESULT_DIR/baseline_tcp.txt" 2>&1
log "Baseline captured"
log ""

SAMPLE_COUNT=0
for f in "$SAMPLE_DIR"/*; do
    [ -f "$f" ] || continue
    BASENAME=$(basename "$f")
    SAMPLE_COUNT=$((SAMPLE_COUNT + 1))
    SDIR="$RESULT_DIR/$BASENAME"
    mkdir -p "$SDIR"

    log "==========================================="
    log "  Sample $SAMPLE_COUNT: $BASENAME"
    log "==========================================="

    # Metadata
    ls -la "$f" >> "$RESULT_DIR/agent.log" 2>&1
    md5sum "$f" 2>/dev/null > "$SDIR/md5.txt"; cat "$SDIR/md5.txt" >> "$RESULT_DIR/agent.log"
    sha256sum "$f" 2>/dev/null > "$SDIR/sha256.txt"; cat "$SDIR/sha256.txt" >> "$RESULT_DIR/agent.log"

    # Strings + IOCs
    strings "$f" > "$SDIR/strings.txt" 2>&1
    grep -iE 'https?://' "$SDIR/strings.txt" > "$SDIR/ioc_urls.txt" 2>/dev/null
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$SDIR/strings.txt" | sort -u > "$SDIR/ioc_ips.txt" 2>/dev/null
    STR_N=$(wc -l < "$SDIR/strings.txt"); URL_N=$(wc -l < "$SDIR/ioc_urls.txt"); IP_N=$(wc -l < "$SDIR/ioc_ips.txt")
    log "Strings: $STR_N  URLs: $URL_N  IPs: $IP_N"

    # Prep
    cp "$f" /tmp/sample_exec; chmod +x /tmp/sample_exec
    ls -la /tmp/ > "$SDIR/pre_tmp.txt" 2>&1
    cat /proc/net/tcp > "$SDIR/pre_tcp.txt" 2>&1

    log ""
    log ">>> EXECUTING (20s timeout) <<<"

    # Run sample
    timeout 20 /tmp/sample_exec > "$SDIR/stdout.txt" 2>"$SDIR/stderr.txt" &
    PID=$!
    log "PID: $PID"

    # Start proc monitor
    if [ -f "$MONITOR" ]; then
        sh "$MONITOR" "$PID" "$SDIR/procmon" 1 &
        MON=$!
    fi

    # Periodic snapshots
    for t in 2 5 10 15 18; do
        sleep_dur=$((t - ${PREV:-0})); PREV=$t
        [ $sleep_dur -gt 0 ] && sleep $sleep_dur
        kill -0 "$PID" 2>/dev/null || break

        log "--- Snapshot @${t}s ---"
        ps auxf > "$SDIR/ps_${t}s.txt" 2>&1
        cat /proc/net/tcp > "$SDIR/tcp_${t}s.txt" 2>&1
        ls -la /tmp/ > "$SDIR/tmp_${t}s.txt" 2>&1

        # Log key changes
        PS_COUNT=$(wc -l < "$SDIR/ps_${t}s.txt")
        TMP_COUNT=$(ls /tmp/ 2>/dev/null | wc -l)
        TCP_COUNT=$(wc -l < "$SDIR/tcp_${t}s.txt")
        log "  Processes: $PS_COUNT  /tmp files: $TMP_COUNT  TCP entries: $TCP_COUNT"
    done
    unset PREV

    wait "$PID" 2>/dev/null
    EXIT=$?
    [ -n "$MON" ] && kill "$MON" 2>/dev/null; wait "$MON" 2>/dev/null

    log ""
    log "Exit code: $EXIT"

    # Post-exec diff
    ls -la /tmp/ > "$SDIR/post_tmp.txt" 2>&1
    cat /proc/net/tcp > "$SDIR/post_tcp.txt" 2>&1
    ps aux > "$SDIR/post_ps.txt" 2>&1

    # New files
    NEW=$(diff "$SDIR/pre_tmp.txt" "$SDIR/post_tmp.txt" 2>/dev/null | grep '^>' || true)
    if [ -n "$NEW" ]; then
        log "NEW FILES in /tmp:"
        echo "$NEW" | tee "$SDIR/new_files.txt" | while read l; do log "  $l"; done
    else
        log "No new files"
    fi

    # New TCP
    NTCP=$(diff "$SDIR/pre_tcp.txt" "$SDIR/post_tcp.txt" 2>/dev/null | grep '^>' || true)
    if [ -n "$NTCP" ]; then
        log "NEW TCP CONNECTIONS:"
        echo "$NTCP" | tee "$SDIR/new_tcp.txt" | while read l; do log "  $l"; done
    else
        log "No new TCP connections"
    fi

    # Stdout
    if [ -s "$SDIR/stdout.txt" ]; then
        OUT_N=$(wc -l < "$SDIR/stdout.txt")
        log ""
        log "STDOUT ($OUT_N lines):"
        head -50 "$SDIR/stdout.txt" | while read l; do log "  $l"; done
    fi

    # Cleanup sample
    rm -f /tmp/sample_exec /tmp/.mirai_persist /tmp/.cron_payload
    log ""
done

log "========================================="
log "  $SAMPLE_COUNT sample(s) analyzed"
log "========================================="
sync
poweroff -f
