#!/bin/bash
F2B_DIR="${F2B_DIR:-/opt/f2b-subnet}"
BACKUP="${F2B_DIR}/banned_ips_dovecot.txt"
TMPFILE="${F2B_DIR}/banned_ips_dovecot.tmp"
FORCE=0
DRYRUN=0

for arg in "$@"; do
    case "$arg" in
        --force) FORCE=1 ;;
        --dry-run) DRYRUN=1 ;;
    esac
done

# Combine both jails into one backup file
{
    /usr/bin/fail2ban-client status dovecot | grep -oP '(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?'
    /usr/bin/fail2ban-client status dovecot-subnet | grep -oP '(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?'
} | sort -u > "$TMPFILE"

NEW_COUNT=$(wc -l < "$TMPFILE")
OLD_COUNT=0
[[ -f "$BACKUP" ]] && OLD_COUNT=$(wc -l < "$BACKUP")

if [[ "$FORCE" -eq 1 ]] || [[ "$NEW_COUNT" -ge "$OLD_COUNT" ]]; then
    if [[ "$DRYRUN" -eq 1 ]]; then
        echo "DRY-RUN: Would write $NEW_COUNT entries (old: $OLD_COUNT)"
        [[ "$FORCE" -eq 1 && "$NEW_COUNT" -lt "$OLD_COUNT" ]] && echo "DRY-RUN: Force flag overriding count check"
        rm -f "$TMPFILE"
    else
        mv "$TMPFILE" "$BACKUP"
        echo "$(date): Backup updated - $NEW_COUNT entries (was $OLD_COUNT)"
    fi
else
    if [[ "$DRYRUN" -eq 1 ]]; then
        echo "DRY-RUN: Would NOT write - new count ($NEW_COUNT) < old count ($OLD_COUNT)"
    else
        echo "$(date): WARNING - New count ($NEW_COUNT) < old count ($OLD_COUNT), skipping overwrite" | tee -a /var/log/f2b_backup.log
    fi
    rm -f "$TMPFILE"
fi
