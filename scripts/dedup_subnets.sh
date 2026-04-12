#!/bin/bash
# Remove redundant subnets from dovecot-subnet jail
# A subnet is redundant if a broader subnet already covers it
# Usage: dedup_subnets.sh [--dry-run]

JAIL="dovecot-subnet"
DRYRUN=0
[[ "$1" == "--dry-run" ]] && DRYRUN=1

REDUNDANT=$(/usr/bin/fail2ban-client get "$JAIL" banip | python3 -c '
import ipaddress, sys

subnets = []
for token in sys.stdin.read().split():
    token = token.strip()
    if "/" in token:
        try:
            subnets.append(ipaddress.IPv4Network(token))
        except ValueError:
            pass

# Sort broadest first (smallest prefix length)
subnets.sort(key=lambda n: n.prefixlen)

keep = []
redundant = []

for net in subnets:
    covered = False
    for broader in keep:
        if net != broader and net.subnet_of(broader):
            covered = True
            redundant.append((str(net), str(broader)))
            break
    if not covered:
        keep.append(net)

for narrow, broad in redundant:
    print(f"{narrow} covered_by {broad}")
')

if [[ -z "$REDUNDANT" ]]; then
    echo "No redundant subnets found."
    exit 0
fi

COUNT=$(echo "$REDUNDANT" | wc -l)
echo "Found $COUNT redundant subnet(s):"
echo ""

while IFS= read -r line; do
    NARROW=$(echo "$line" | awk '{print $1}')
    BROAD=$(echo "$line" | awk '{print $3}')

    if [[ "$DRYRUN" -eq 1 ]]; then
        echo "[DRY-RUN] Would remove $NARROW (covered by $BROAD)"
    else
        /usr/bin/fail2ban-client set "$JAIL" unbanip "$NARROW" >/dev/null 2>&1
        echo "Removed $NARROW (covered by $BROAD)"
    fi
done <<< "$REDUNDANT"

echo ""
if [[ "$DRYRUN" -eq 0 ]]; then
    REMAINING=$(/usr/bin/fail2ban-client get "$JAIL" banip | wc -w)
    echo "Done. $COUNT removed, $REMAINING subnets remaining."
else
    echo "Done. $COUNT would be removed."
fi
