#!/bin/bash
# Dovecot individual IPs
NFT_IP=$(nft list set inet f2b-table addr-set-dovecot)
fw_ips=$(echo "$NFT_IP" | grep -oP '(\d{1,3}\.){3}\d{1,3}\b(?!/)' | wc -l)
F2B_IP=$(fail2ban-client get dovecot banip)
f2b_ips=$(echo "$F2B_IP" | grep -oP '(\d{1,3}\.){3}\d{1,3}\b(?!/)' | wc -l)

# Dovecot subnets
NFT_SUB=$(nft list set inet f2b-table addr-set-dovecot-subnet)
fw_subnets=$(echo "$NFT_SUB" | grep -oP '(\d{1,3}\.){3}\d{1,3}/\d{1,2}' | wc -l)
F2B_SUB=$(fail2ban-client get dovecot-subnet banip)
f2b_subnets=$(echo "$F2B_SUB" | grep -oP '(\d{1,3}\.){3}\d{1,3}/\d{1,2}' | wc -l)

f2b_total_ips=$(echo "$F2B_SUB" | grep -oP '(\d{1,3}\.){3}\d{1,3}/\d{1,2}' | python3 -c "
import sys
total = 0
for line in sys.stdin:
    prefix = int(line.strip().split('/')[1])
    total += 2 ** (32 - prefix)
print(f'{total:,}')
")

# Postfix
fw_smtp=$(nft list set inet f2b-table addr-set-postfix | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | wc -l)
f2b_smtp=$(fail2ban-client get postfix banip | wc -w)

echo "dovecot IPs: nft=$fw_ips f2b=$f2b_ips"
echo "dovecot subnets: nft=$fw_subnets f2b=$f2b_subnets ($f2b_total_ips addresses)"
echo "postfix: nft=$fw_smtp f2b=$f2b_smtp"

SYNC=true
[[ "$fw_ips" -ne "$f2b_ips" ]] && echo "dovecot IPs: OUT OF SYNC" && SYNC=false
[[ "$fw_subnets" -ne "$f2b_subnets" ]] && echo "dovecot subnets: OUT OF SYNC" && SYNC=false
[[ "$fw_smtp" -ne "$f2b_smtp" ]] && echo "postfix: OUT OF SYNC" && SYNC=false
[[ "$SYNC" == "true" ]] && echo "ALL IN SYNC"
