#!/bin/bash
# Deploy f2b-subnet files to their target locations
# Run from the repo root: ./install.sh [--dry-run]

F2B_DIR="${F2B_DIR:-/opt/f2b-subnet}"
SE_DIR="${SE_DIR:-/opt/f2b-subnet/selinux}"

DRYRUN=0
[[ "$1" == "--dry-run" ]] && DRYRUN=1

deploy() {
    local src="$1" dst="$2" mode="${3:-0755}"
    if [[ "$DRYRUN" -eq 1 ]]; then
        echo "WOULD: $src → $dst (mode $mode)"
    else
        cp "$src" "$dst"
        chmod "$mode" "$dst"
        echo "DEPLOYED: $src → $dst (mode $mode)"
    fi
}

# Scripts
deploy scripts/f2b_subnet_ban.sh     /usr/local/bin/f2b_subnet_ban.sh
deploy scripts/check-f2b-nft-sync.sh /usr/local/bin/check-f2b-nft-sync.sh
mkdir -p "$F2B_DIR" "$SE_DIR"
deploy scripts/batch_subnet_cached.py "${F2B_DIR}/batch_subnet_cached.py"
deploy scripts/whois_cache_loop.sh    "${F2B_DIR}/whois_cache_loop.sh"
deploy scripts/get_f2b_stats.sh       "${F2B_DIR}/get_f2b_stats.sh"
deploy scripts/find_outOfSync.sh      "${F2B_DIR}/find_outOfSync.sh"
deploy scripts/backup_f2b_dovecot.sh  "${F2B_DIR}/backup_f2b_dovecot.sh"

# Config
deploy config/fail2ban/dovecot-subnet.conf /etc/fail2ban/filter.d/dovecot-subnet.conf 0644
deploy config/logrotate/f2b-subnet         /etc/logrotate.d/f2b-subnet                0644
deploy config/selinux/f2b-complete.te      "${SE_DIR}/f2b-complete.te"                  0644

echo ""
echo "NOTE: jail.local entries (config/fail2ban/jail-dovecot*.conf) are reference only."
echo "      Merge them into /etc/fail2ban/jail.local manually."
echo ""
if [[ "$DRYRUN" -eq 0 ]]; then
    echo "Reload fail2ban:"
    echo "  fail2ban-client reload dovecot"
    echo "  fail2ban-client reload dovecot-subnet"
fi
