#!/bin/bash
# Analyze f2b_subnet_ban.log for subnet banning activity
#
# Usage: nft_miss_report.sh [logfile]
#   Default logfile: /var/log/f2b_subnet_ban.log

LOG="${1:-/var/log/f2b_subnet_ban.log}"

if [[ ! -f "$LOG" ]]; then
    echo "ERROR: Log file not found: $LOG" >&2
    exit 1
fi

echo "=== Subnet Ban Activity Report ==="
echo "Log: $LOG"
echo ""

# Count from cron summary lines
TOTAL_RUNS=$(grep -c 'whois_cache_loop.sh' "$LOG")
TOTAL_NEW=$(grep -oP 'new_subnets=\K\d+' "$LOG" | awk '{s+=$1} END {print s+0}')
TOTAL_FAILED=$(grep -oP 'failed=\K\d+' "$LOG" | awk '{s+=$1} END {print s+0}')
TOTAL_SKIPPED=$(grep -oP 'skipped=\K\d+' "$LOG" | awk '{s+=$1} END {print s+0}')
RUNS_WITH_BANS=$(grep -oP 'new_subnets=\K\d+' "$LOG" | awk '$1 > 0 {n++} END {print n+0}')
RUNS_WITH_FAILURES=$(grep -oP 'failed=\K\d+' "$LOG" | awk '$1 > 0 {n++} END {print n+0}')

echo "Cron runs analyzed: $TOTAL_RUNS"
echo "New subnets banned: $TOTAL_NEW"
echo "Total skipped (already covered): $TOTAL_SKIPPED"
echo "Total failed lookups: $TOTAL_FAILED"
echo "Runs with new bans: $RUNS_WITH_BANS"
echo "Runs with failures: $RUNS_WITH_FAILURES"
echo ""

# Show recent activity
echo "--- Recent cron activity (last 20 entries with activity) ---"
grep 'whois_cache_loop.sh' "$LOG" | grep -v 'skipped=0 new_subnets=0 failed=0' | tail -20
echo ""

# Show recent subnet bans from the ban script
echo "--- Recent subnet bans (last 20) ---"
grep 'Banning.*in jail' "$LOG" | tail -20
echo ""

# Show failures
FAIL_COUNT=$(grep -c 'FAILED' "$LOG" 2>/dev/null)
if [[ "$FAIL_COUNT" -gt 0 ]]; then
    echo "--- Recent lookup failures (last 20) ---"
    grep 'FAILED' "$LOG" | tail -20
    echo ""
fi

# Show rate limiting events
RATELIMIT_COUNT=$(grep -c 'RATE-LIMITED\|Rate limited' "$LOG" 2>/dev/null)
if [[ "$RATELIMIT_COUNT" -gt 0 ]]; then
    echo "--- Rate limiting events: $RATELIMIT_COUNT ---"
    grep 'RATE-LIMITED\|Rate limited' "$LOG" | tail -10
fi
