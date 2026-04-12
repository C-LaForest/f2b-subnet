#!/bin/bash
# Analyze f2b_subnet_ban.log to find nft interval set misses
# An nft miss = an IP banned by fail2ban that was already covered
# by an existing subnet ban (i.e., nft should have blocked it)
#
# Usage: nft_miss_report.sh [logfile]
#   Default logfile: /var/log/f2b_subnet_ban.log

LOG="${1:-/var/log/f2b_subnet_ban.log}"

if [[ ! -f "$LOG" ]]; then
    echo "ERROR: Log file not found: $LOG" >&2
    exit 1
fi

echo "=== nft Interval Set Miss Report ==="
echo "Log: $LOG"
echo ""

# Count from cron summary lines: cleaned=N where N > 0
TOTAL_MISSES=$(grep -oP 'cleaned=\K\d+' "$LOG" | awk '{s+=$1} END {print s+0}')
TOTAL_RUNS=$(grep -c 'whois_cache_loop.sh' "$LOG")
RUNS_WITH_MISSES=$(grep -oP 'cleaned=\K\d+' "$LOG" | awk '$1 > 0 {n++} END {print n+0}')

echo "Cron runs analyzed: $TOTAL_RUNS"
echo "Total nft misses (cleaned IPs): $TOTAL_MISSES"
echo "Cron runs with misses: $RUNS_WITH_MISSES"
if [[ "$TOTAL_RUNS" -gt 0 ]]; then
    PCT=$(awk "BEGIN {printf \"%.1f\", ($RUNS_WITH_MISSES/$TOTAL_RUNS)*100}")
    echo "Miss rate: ${PCT}% of cron runs had leaked IPs"
fi
echo ""

# Show misses over time (daily summary)
echo "--- Daily breakdown ---"
grep -P 'cleaned=\d+' "$LOG" | while IFS= read -r line; do
    date=$(echo "$line" | grep -oP '^\w+ \w+ \d+ \d+:\d+:\d+ [AP]M \w+ \d+' 2>/dev/null)
    if [[ -z "$date" ]]; then
        # Try other date formats
        date=$(echo "$line" | grep -oP '^\S+ \S+ \d+' 2>/dev/null)
    fi
    cleaned=$(echo "$line" | grep -oP 'cleaned=\K\d+')
    if [[ "$cleaned" -gt 0 ]]; then
        echo "$line"
    fi
done | grep -oP '^\S+' | sort | uniq -c | sort -rn | head -20
echo ""

# Show specific cleaned-up IPs (the actual nft misses)
echo "--- Individual nft misses (IPs that leaked through) ---"
grep 'Cleaned up.*already covered' "$LOG" | tail -30
echo ""

# Show misses per hour (pattern detection)
echo "--- Misses by hour (last 7 days) ---"
grep 'Cleaned up.*already covered' "$LOG" | grep -oP '\d+:\d+:\d+' | cut -d: -f1 | sort | uniq -c | sort -rn
