#!/bin/bash
# Backup fail2ban bans — separate files per jail
# Usage: backup_f2b_dovecot.sh [--force] [--dry-run]

F2B_DIR="${F2B_DIR:-/opt/f2b-subnet}"
FORCE=0
DRYRUN=0

for arg in "$@"; do
    case "$arg" in
        --force) FORCE=1 ;;
        --dry-run) DRYRUN=1 ;;
    esac
done

backup_jail() {
    local jail="$1" backup="$2" label="$3"
    local tmpfile="${backup}.tmp"

    /usr/bin/fail2ban-client get "$jail" banip 2>/dev/null | tr ' ' '\n' | grep -v '^$' | sort -u > "$tmpfile"

    local new_count old_count=0
    new_count=$(wc -l < "$tmpfile")
    [[ -f "$backup" ]] && old_count=$(wc -l < "$backup")

    if [[ "$FORCE" -eq 1 ]] || [[ "$new_count" -ge "$old_count" ]]; then
        if [[ "$DRYRUN" -eq 1 ]]; then
            echo "DRY-RUN [$label]: Would write $new_count entries (old: $old_count)"
            [[ "$FORCE" -eq 1 && "$new_count" -lt "$old_count" ]] && echo "DRY-RUN [$label]: Force flag overriding count check"
            rm -f "$tmpfile"
        else
            mv "$tmpfile" "$backup"
            echo "$(date): $label backup updated - $new_count entries (was $old_count)"
        fi
    else
        if [[ "$DRYRUN" -eq 1 ]]; then
            echo "DRY-RUN [$label]: Would NOT write - new count ($new_count) < old count ($old_count)"
        else
            echo "$(date): WARNING [$label] - New count ($new_count) < old count ($old_count), skipping overwrite" | tee -a /var/log/f2b_backup.log
        fi
        rm -f "$tmpfile"
    fi
}

backup_jail "dovecot"        "${F2B_DIR}/banned_ips_dovecot.txt"     "dovecot"
backup_jail "dovecot-subnet" "${F2B_DIR}/banned_subnets_dovecot.txt" "dovecot-subnet"
