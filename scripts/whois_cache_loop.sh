#!/bin/bash
# Re-run batch subnet conversion
F2B_DIR="${F2B_DIR:-/opt/f2b-subnet}"
LOCKFILE="/tmp/whois_cache_loop.lock"
CRON=0
QUIET=0
LOOP=0
EXTRA_ARGS=""

for arg in "$@"; do
    case "$arg" in
        --cron) CRON=1 ;;
        --quiet) QUIET=1 ;;
        --loop) LOOP=1 ;;
        --dry-run) EXTRA_ARGS="--dry-run" ;;
    esac
done

# Prevent stacking
if [[ -f "$LOCKFILE" ]]; then
    LOCK_PID=$(cat "$LOCKFILE" 2>/dev/null)
    if kill -0 "$LOCK_PID" 2>/dev/null; then
        exit 0
    fi
    rm -f "$LOCKFILE"
fi
echo $$ > "$LOCKFILE"
trap "rm -f '$LOCKFILE'" EXIT

run_batch() {
    if [[ "$CRON" -eq 1 ]]; then
        OUTPUT=$(python3 "${F2B_DIR}/batch_subnet_cached.py" $EXTRA_ARGS 2>&1)
        SKIPPED=$(echo "$OUTPUT" | grep -oP 'Skipped \K\d+' | head -1)
        SKIPPED=${SKIPPED:-0}
        PROCESSED=$(echo "$OUTPUT" | grep -oP 'Processed: \K\d+')
        FAILED=$(echo "$OUTPUT" | grep -oP 'Failed: \K\d+')
        TOTAL_IPS=$(/usr/bin/fail2ban-client get dovecot banip 2>/dev/null | wc -w)
        TOTAL_SUBNETS=$(/usr/bin/fail2ban-client get dovecot-subnet banip 2>/dev/null | wc -w)
        # Only log if something happened or there are failures
        if [[ "$PROCESSED" -gt 0 || "$SKIPPED" -gt 0 || "$FAILED" -gt 0 ]]; then
            echo "$(date): whois_cache_loop.sh: skipped=$SKIPPED new_subnets=$PROCESSED failed=$FAILED ips=$TOTAL_IPS subnets=$TOTAL_SUBNETS"
        fi
    elif [[ "$QUIET" -eq 1 ]]; then
        python3 "${F2B_DIR}/batch_subnet_cached.py" $EXTRA_ARGS >/dev/null 2>&1
    else
        echo "=== $(date) === Starting batch run ==="
        python3 "${F2B_DIR}/batch_subnet_cached.py" $EXTRA_ARGS
        TOTAL_IPS=$(/usr/bin/fail2ban-client get dovecot banip 2>/dev/null | wc -w)
        TOTAL_SUBNETS=$(/usr/bin/fail2ban-client get dovecot-subnet banip 2>/dev/null | wc -w)
        echo "$(date): $TOTAL_IPS IPs in dovecot, $TOTAL_SUBNETS subnets in dovecot-subnet"
    fi
}

if [[ "$LOOP" -eq 1 ]]; then
    while true; do
        OUTPUT=$(python3 "${F2B_DIR}/batch_subnet_cached.py" $EXTRA_ARGS 2>&1)
        echo "$OUTPUT"
        LOOP_PROCESSED=$(echo "$OUTPUT" | grep -oP 'Processed: \K\d+')
        LOOP_FAILED=$(echo "$OUTPUT" | grep -oP 'Failed: \K\d+')
        LOOP_PROCESSED=${LOOP_PROCESSED:-0}
        LOOP_FAILED=${LOOP_FAILED:-0}
        if [[ "$LOOP_PROCESSED" -eq 0 && "$LOOP_FAILED" -eq 0 ]]; then
            [[ "$QUIET" -eq 0 && "$CRON" -eq 0 ]] && echo "All done — no uncovered IPs to process!"
            break
        fi
        [[ "$QUIET" -eq 0 && "$CRON" -eq 0 ]] && echo "Cooling down 5 minutes before retry..."
        sleep 300
    done
else
    run_batch
fi
