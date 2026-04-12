#!/bin/bash
# Usage: ./check-f2b-nft-sync.sh jail1,jail2,... set1,set2,...
# Example: ./check-f2b-nft-sync.sh dovecot,dovecot-subnet,postfix addr-set-dovecot,addr-set-dovecot-subnet,addr-set-postfix
if [ $# -ne 2 ]; then
    echo "Usage: $0 jail1,jail2,... set1,set2,..."
    exit 3
fi
F2B_CLIENT="sudo /usr/bin/fail2ban-client"
NFT="sudo /usr/sbin/nft"
IFS=',' read -ra JAILS <<< "$1"
IFS=',' read -ra SETS <<< "$2"
if [ ${#JAILS[@]} -ne ${#SETS[@]} ]; then
    echo "CRITICAL: Number of jails and nft sets must match"
    exit 2
fi
status=0
msg=""
perfdata=""
for idx in "${!JAILS[@]}"; do
    jail="${JAILS[$idx]}"
    set="${SETS[$idx]}"
    # Snapshot nft
    NFT_DATA=$($NFT list set inet f2b-table "$set" 2>/dev/null)
    fw_ips=$(echo "$NFT_DATA" | grep -oP '(\d{1,3}\.){3}\d{1,3}\b(?!/)' | wc -l)
    fw_subnets=$(echo "$NFT_DATA" | grep -oP '(\d{1,3}\.){3}\d{1,3}/\d{1,2}' | wc -l)
    fw_count=$((fw_ips + fw_subnets))
    # Snapshot f2b
    F2B_DATA=$($F2B_CLIENT get "$jail" banip 2>/dev/null)
    f2b_ips=$(echo "$F2B_DATA" | grep -oP '(\d{1,3}\.){3}\d{1,3}\b(?!/)' | wc -l)
    f2b_subnets=$(echo "$F2B_DATA" | grep -oP '(\d{1,3}\.){3}\d{1,3}/\d{1,2}' | wc -l)
    f2b_count=$((f2b_ips + f2b_subnets))
    f2b_total_ips=$(echo "$F2B_DATA" | grep -oP '(\d{1,3}\.){3}\d{1,3}/\d{1,2}' | python3 -c "
import sys
total = 0
for line in sys.stdin:
    prefix = int(line.strip().split('/')[1])
    total += 2 ** (32 - prefix)
print(f'{total:,}')
")
    # Check sync
    if [ "$fw_count" -ne "$f2b_count" ]; then
        msg+="CRITICAL: $jail out of sync (f2b=$f2b_count, fw=$fw_count): "
        status=2
    else
        msg+="OK: $jail in sync (${f2b_ips} IPs & ${f2b_subnets} subnets blocked): "
    fi
    perfdata+="${jail}_f2b=${f2b_count} ${jail}_fw=${fw_count} ${jail}_ips=${f2b_ips} ${jail}_subnets=${f2b_subnets} "
    perfdata+="${jail}_blocked_addrs=${f2b_total_ips} "
done
echo "$msg|$perfdata"
exit $status
