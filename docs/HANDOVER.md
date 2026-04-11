# Fail2Ban Subnet Banning System — Operations Handover v3

## Host: mail.example.com (SMTP/IMAP Mail Server, Rocky Linux)

**Last updated:** 2026-04-05

---

## System Overview

The mail server runs fail2ban to protect Dovecot (IMAP) and Postfix (SMTP). The system uses a **dual-jail architecture** for Dovecot: one jail for individual IPs and a separate jail for subnet bans. A cron job runs every 10 minutes to escalate individual IP bans to their allocated subnet using RDAP/whois lookups.

### Dual-Jail Architecture

| Jail | nft Set | Contents | Managed by |
|------|---------|----------|------------|
| `dovecot` | `addr-set-dovecot` | Individual IPs only | fail2ban (automatic) |
| `dovecot-subnet` | `addr-set-dovecot-subnet` | Subnets only (CIDR) | Cron batch script |
| `postfix` | `addr-set-postfix` | Individual IPs only | fail2ban (automatic) |

**Why two jails?** A single nft interval set cannot hold both individual IPs and subnets without "interval overlaps" errors when a new IP falls within an existing subnet. Separating them into two sets eliminates this entirely — no more nft overlap errors, no ghost entries, clean restarts.

### Key Design Decisions

| Aspect | Dovecot | Postfix |
|--------|---------|---------|
| Purpose | IMAP authentication (private) | SMTP relay (public-facing) |
| Subnet banning | Yes (via cron every 10 min) | **No** — legitimate mail servers could be affected |
| Ban time | Permanent (`bantime = -1`) | Escalating (2d base, 10w max) |
| Max retry | 1 | 3 |
| Rationale | No legitimate users authenticate from random overseas ISPs | Must accept mail from anywhere |

### Data Flow

```
Bot hits Dovecot → fail2ban bans individual IP immediately
                 → nftables-multiport adds IP to addr-set-dovecot
                 → sendmail-whois-matches sends alert email
                 → IP is blocked on port 993

Every 10 minutes (cron):
  whois_cache_loop.sh runs
    → batch_subnet_cached.py reads individual IPs from dovecot jail
    → calls f2b_subnet_ban.sh for each uncovered IP
        → RDAP lookup (IPv4 forced) → whois fallback
        → unbans individual IP from dovecot jail / addr-set-dovecot
        → bans subnet in dovecot-subnet jail / addr-set-dovecot-subnet
        → sends subnet ban email
        → syncs backup file
    → subnet blocks port 993 via separate nft rule
```

### nft Firewall Structure

```
table inet f2b-table {
    set addr-set-dovecot {         # Individual IPs only
        type ipv4_addr
        flags interval
    }
    set addr-set-dovecot-subnet {  # Subnets only (CIDR)
        type ipv4_addr
        flags interval
    }
    set addr-set-postfix {         # Individual IPs only
        type ipv4_addr
        flags interval
    }
    chain input {
        type filter hook input priority filter - 1; policy accept;
        tcp dport 25  ip saddr @addr-set-postfix         counter reject
        tcp dport 993 ip saddr @addr-set-dovecot         counter reject
        tcp dport 993 ip saddr @addr-set-dovecot-subnet  counter reject
    }
}
```

The f2b-table chain runs at priority `filter - 1`, BEFORE firewalld's `filter_INPUT` at priority `filter + 10`.

---

## File Locations

### Scripts

| File | Purpose | Called by |
|------|---------|-----------|
| `/usr/local/bin/f2b_subnet_ban.sh` | Subnet escalation (IP→subnet lookup, unban from `dovecot`, ban into `dovecot-subnet`) | `whois_cache_loop.sh`, manual |
| `$F2B_DIR/batch_subnet_cached.py` | Batch convert individual IPs to subnets with caching | `whois_cache_loop.sh` |
| `$F2B_DIR/whois_cache_loop.sh` | Loop runner for batch conversion (retries until clean) | cron (every 10 min) |
| `$F2B_DIR/get_f2b_stats.sh` | Quick status check across all jails | manual |
| `$F2B_DIR/find_outOfSync.sh` | Diff f2b vs nft to find mismatches | manual |
| `$F2B_DIR/backup_f2b_dovecot.sh` | Daily backup of ban list (both jails) | cron (1:10 AM), manual |
| `/usr/local/bin/check-f2b-nft-sync.sh` | Nagios monitoring check | Nagios on Helm (~10 min) |

### Configuration

| File | Purpose |
|------|---------|
| `/etc/fail2ban/jail.local` | Jail configuration (dovecot, dovecot-subnet, postfix) |
| `/etc/fail2ban/filter.d/dovecot-subnet.conf` | Dummy filter for subnet jail (no log matching) |
| `/etc/fail2ban/action.d/nftables.local` | nftables action with `flags interval` for sets |
| `/etc/fail2ban/action.d/subnet-ban.local` | Old real-time action (EXISTS but NOT active) |
| `$SE_DIR/f2b-complete.te` | SELinux policy module source |

### Data Files

| File | Purpose |
|------|---------|
| `$F2B_DIR/banned_ips_dovecot.txt` | Backup of all banned entries (both jails combined) |
| `$F2B_DIR/whois_cache.json` | RDAP/whois lookup cache |
| `/var/log/f2b_subnet_ban.log` | Subnet ban script log |
| `/var/log/fail2ban.log` | Fail2ban main log |
| `/var/lib/fail2ban/fail2ban.sqlite3` | Fail2ban ban database |

---

## Cron Jobs

### Subnet Escalation (every 10 minutes)

```cron
*/10 * * * * $F2B_DIR/whois_cache_loop.sh >> /var/log/f2b_subnet_ban.log 2>&1
```

### Daily Ban Backup (1:10 AM)

```cron
10 1 * * * $F2B_DIR/backup_f2b_dovecot.sh
```

---

## Common Operations

### Check Current Status

```bash
sh ~/fail2-backup/get_f2b_stats.sh
```

**Expected output (healthy — just after cron run):**
```
dovecot IPs: nft=0 f2b=0
dovecot subnets: nft=1821 f2b=1821 (336,421,036 addresses)
postfix: nft=85 f2b=85
ALL IN SYNC
```

**Expected output (healthy — between cron runs, some new IPs pending):**
```
dovecot IPs: nft=3 f2b=3
dovecot subnets: nft=1821 f2b=1821 (336,421,036 addresses)
postfix: nft=87 f2b=87
ALL IN SYNC
```

**Expected output (problem — dovecot IPs out of sync):**
```
dovecot IPs: nft=2 f2b=5
dovecot subnets: nft=1821 f2b=1821 (336,421,036 addresses)
postfix: nft=85 f2b=85
dovecot IPs: OUT OF SYNC
```

**Expected output (problem — dovecot subnets out of sync):**
```
dovecot IPs: nft=0 f2b=0
dovecot subnets: nft=1820 f2b=1821 (336,421,036 addresses)
postfix: nft=85 f2b=85
dovecot subnets: OUT OF SYNC
```

**Key indicators:**
- `dovecot IPs` = 0 means all individual IPs have been consolidated (ideal state after cron)
- `dovecot IPs` = 1-9 is normal between cron runs
- `dovecot IPs` ≥ 10 means cron may be failing — investigate
- `ALL IN SYNC` means all jail databases match their nft sets
- Any `OUT OF SYNC` means ghost or orphan entries need cleanup

### Check for Out-of-Sync Entries

```bash
sh ~/fail2-backup/find_outOfSync.sh
```

**Expected output (clean):**
```
Now run:
fail2ban-client set dovecot unbanip [IP or Subnet}
fail2ban-client set dovecot banip {IP or Subnet}
```

**Expected output (out of sync):**
```
278d277
< 128.185.0.0/16
Now run:
fail2ban-client set dovecot unbanip [IP or Subnet}
fail2ban-client set dovecot banip {IP or Subnet}
```

- Lines with `<` = in fail2ban but NOT in nft (ghosts)
- Lines with `>` = in nft but NOT in fail2ban (orphans)

**NOTE:** `find_outOfSync.sh` currently checks the old single-jail layout. For the dual-jail architecture, use `get_f2b_stats.sh` to identify which jail is out of sync, then troubleshoot that specific jail (see Troubleshooting section).

### Watch Real-Time Activity

```bash
tail -F /var/log/fail2ban.log /var/log/f2b_subnet_ban.log | grep -Ev 'Ignore 198.51.100.8 by ip|Unable to find a corresponding IP address for unknown'
```

### Manual Subnet Ban (single IP → subnet lookup)

```bash
# ALWAYS dry-run first
/usr/local/bin/f2b_subnet_ban.sh --dry-run 192.168.1.1
```

**Expected dry-run output:**
```
[DRY-RUN] Banning 192.168.0.0/16 (source: 192.168.1.1)
[DRY-RUN] Would unban 192.168.1.1 from dovecot (covered by 192.168.0.0/16)
[DRY-RUN] Would ban subnet: 192.168.0.0/16 in jail: dovecot-subnet
[DRY-RUN] Would remove these entries from $F2B_DIR/banned_ips_dovecot.txt:
  - 192.168.1.1
Would add: 192.168.0.0/16
[DRY-RUN] Done - 192.168.1.1 → 192.168.0.0/16
```

```bash
# For real (after confirming dry-run)
/usr/local/bin/f2b_subnet_ban.sh 192.168.1.1
```

### Manual Subnet Ban (direct CIDR — skip RDAP/whois)

```bash
/usr/local/bin/f2b_subnet_ban.sh --dry-run 192.168.0.0/16
/usr/local/bin/f2b_subnet_ban.sh 192.168.0.0/16
```

### Run Batch Cleanup Manually

```bash
sh ~/fail2-backup/whois_cache_loop.sh
```

**Expected output (clean — no work to do):**
```
=== Sun Apr  5 09:25:17 AM EDT 2026 === Starting batch run ===
Individual IPs: 0
Existing subnets: 1821
Uncovered IPs to process: 0
Unique /16 groups: 0
Done. Processed: 0, Skipped (already banned): 0, Failed: 0
Cache saved to $F2B_DIR/whois_cache.json
Sun Apr  5 09:25:17 AM EDT 2026: 0 uncovered IPs remaining
All done!
```

**Expected output (work to do — IPs pending escalation):**
```
=== Sun Apr  5 11:00:01 AM EDT 2026 === Starting batch run ===
Individual IPs: 5
Existing subnets: 1821
Uncovered IPs to process: 5
Unique /16 groups: 3
[LOOKUP] 87.126.x.x (1 IPs) looking up 87.126.82.50... → 87.126.0.0/16
[CACHED] 182.95.x.x (2 IPs) → 182.95.128.0/17
[LOOKUP] 45.178.x.x (2 IPs) looking up 45.178.227.0... → 45.178.226.0/23
Done. Processed: 3, Skipped (already banned): 0, Failed: 0
Cache saved to $F2B_DIR/whois_cache.json
Sun Apr  5 11:00:05 AM EDT 2026: 0 uncovered IPs remaining
All done!
```

### Force Backup Update

```bash
# Dry-run first
sh ~/fail2-backup/backup_f2b_dovecot.sh --dry-run

# Force update (overrides count check)
sh ~/fail2-backup/backup_f2b_dovecot.sh --force
```

**Expected output:**
```
Sun Apr  5 01:41:25 PM EDT 2026: Backup updated - 1821 entries (was 1819)
```

### Count Total Blocked Addresses

```bash
F2B_DATA=$(fail2ban-client get dovecot-subnet banip)
echo "$F2B_DATA" | grep -oP '(\d{1,3}\.){3}\d{1,3}/\d{1,2}' | python3 -c "
import sys
total = 0
for line in sys.stdin:
    prefix = int(line.strip().split('/')[1])
    total += 2 ** (32 - prefix)
print(f'{total:,} addresses blocked')
"
```

**Expected output:**
```
336,421,036 addresses blocked
```

---

## Troubleshooting

### Problem: dovecot IPs OUT OF SYNC

**Meaning:** The number of individual IPs in fail2ban's `dovecot` jail doesn't match the number in `addr-set-dovecot` nft set.

**Diagnosis:**
```bash
# What does f2b think?
fail2ban-client status dovecot | grep 'Currently banned'

# What does nft have?
nft list set inet f2b-table addr-set-dovecot | grep -oP '(\d{1,3}\.){3}\d{1,3}\b(?!/)' | wc -l
```

**Expected output (healthy):**
```
   |- Currently banned: 3
3
```

**Expected output (problem — ghosts in f2b):**
```
   |- Currently banned: 5
2
```

**Fix — find and remove ghosts (entries in f2b but not nft):**
```bash
# Get the diff
diff <(fail2ban-client get dovecot banip | tr ' ' '\n' | sort) \
     <(nft list set inet f2b-table addr-set-dovecot | grep -oP '(\d{1,3}\.){3}\d{1,3}\b(?!/)' | sort)

# Lines with < are ghosts — remove them
diff <(fail2ban-client get dovecot banip | tr ' ' '\n' | sort) \
     <(nft list set inet f2b-table addr-set-dovecot | grep -oP '(\d{1,3}\.){3}\d{1,3}\b(?!/)' | sort) \
| grep '^< ' | sed 's/^< //' | while read -r entry; do
    echo "Purging ghost: $entry"
    fail2ban-client set dovecot unbanip "$entry" 2>/dev/null
done
```

**Fix — find and remove orphans (entries in nft but not f2b):**
```bash
diff <(fail2ban-client get dovecot banip | tr ' ' '\n' | sort) \
     <(nft list set inet f2b-table addr-set-dovecot | grep -oP '(\d{1,3}\.){3}\d{1,3}\b(?!/)' | sort) \
| grep '^> ' | sed 's/^> //' | while read -r entry; do
    echo "Removing orphan: $entry"
    nft delete element inet f2b-table addr-set-dovecot "{ $entry }"
done
```

**Verify:**
```bash
sh ~/fail2-backup/get_f2b_stats.sh
```

### Problem: dovecot subnets OUT OF SYNC

**Meaning:** The number of subnets in fail2ban's `dovecot-subnet` jail doesn't match the number in `addr-set-dovecot-subnet` nft set.

**Diagnosis:**
```bash
# What does f2b think?
fail2ban-client status dovecot-subnet | grep 'Currently banned'

# What does nft have?
nft list set inet f2b-table addr-set-dovecot-subnet | grep -oP '(\d{1,3}\.){3}\d{1,3}/\d{1,2}' | wc -l
```

**Fix — find and remove ghosts (subnets in f2b but not nft):**
```bash
diff <(fail2ban-client get dovecot-subnet banip | tr ' ' '\n' | grep '/' | sort) \
     <(nft list set inet f2b-table addr-set-dovecot-subnet | grep -oP '(\d{1,3}\.){3}\d{1,3}/\d{1,2}' | sort) \
| grep '^< ' | sed 's/^< //' | while read -r entry; do
    echo "Purging ghost subnet: $entry"
    fail2ban-client set dovecot-subnet unbanip "$entry" 2>/dev/null
done
```

**Fix — find and remove orphans (subnets in nft but not f2b):**
```bash
diff <(fail2ban-client get dovecot-subnet banip | tr ' ' '\n' | grep '/' | sort) \
     <(nft list set inet f2b-table addr-set-dovecot-subnet | grep -oP '(\d{1,3}\.){3}\d{1,3}/\d{1,2}' | sort) \
| grep '^> ' | sed 's/^> //' | while read -r entry; do
    echo "Removing orphan subnet: $entry"
    nft delete element inet f2b-table addr-set-dovecot-subnet "{ $entry }"
done
```

**Verify:**
```bash
sh ~/fail2-backup/get_f2b_stats.sh
```

### Problem: postfix OUT OF SYNC

**Same procedure as dovecot IPs**, but using `postfix` jail and `addr-set-postfix` set:

```bash
# Diagnosis
fail2ban-client status postfix | grep 'Currently banned'
nft list set inet f2b-table addr-set-postfix | grep -oP '(\d{1,3}\.){3}\d{1,3}\b(?!/)' | wc -l

# Fix ghosts
diff <(fail2ban-client get postfix banip | tr ' ' '\n' | sort) \
     <(nft list set inet f2b-table addr-set-postfix | grep -oP '(\d{1,3}\.){3}\d{1,3}\b(?!/)' | sort) \
| grep '^< ' | sed 's/^< //' | while read -r entry; do
    echo "Purging ghost: $entry"
    fail2ban-client set postfix unbanip "$entry" 2>/dev/null
done
```

### Problem: Individual IPs accumulating (IPs > 0 for extended time)

**Cause:** Cron job isn't running, or RDAP/whois lookups are failing.

**Diagnosis:**
```bash
# Check if cron is running
grep whois_cache /var/log/cron | tail -5

# Check for failures
grep -i "failed\|error\|WARN" /var/log/f2b_subnet_ban.log | tail -20

# Check for /32 entries stuck in cache
python3 -c "
import json
with open('$F2B_DIR/whois_cache.json') as f:
    cache = json.load(f)
for k, v in cache.items():
    if v and '/32' in str(v):
        print(f'{k} → {v}')
"
```

**Expected output (no stuck entries):**
```
(no output)
```

**Expected output (stuck /32 entries):**
```
124.107 → 124.107.185.138/32
178.124 → 178.124.218.103/32
```

**Fix — clear /32 cache entries:**
```bash
python3 -c "
import json
with open('$F2B_DIR/whois_cache.json') as f:
    cache = json.load(f)
to_remove = [k for k, v in cache.items() if v and '/32' in str(v)]
for k in to_remove:
    del cache[k]
with open('$F2B_DIR/whois_cache.json', 'w') as f:
    json.dump(cache, f, indent=2)
print(f'Removed {len(to_remove)} /32 entries')
"
```

**Fix — run batch manually:**
```bash
sh ~/fail2-backup/whois_cache_loop.sh
```

### Problem: RDAP Failing (all lookups falling through to whois)

**Cause:** The server has no IPv6. RDAP servers try IPv6 first. The script forces IPv4 via Python socket monkey-patching.

**Test:**
```bash
/usr/local/bin/f2b_subnet_ban.sh --dry-run 8.8.8.8
```

**Expected output (RDAP working):**
```
[DRY-RUN] Banning 8.8.8.0/24 (source: 8.8.8.8)
[DRY-RUN] Would ban subnet: 8.8.8.0/24 in jail: dovecot-subnet
...
```

**Expected output (RDAP failing):**
```
RDAP failed for 8.8.8.8, trying whois...
[DRY-RUN] Banning 8.8.8.0/24 (source: 8.8.8.8)
...
```

If RDAP is failing, check the `rdap_lookup()` function in `f2b_subnet_ban.sh` for the IPv4 socket override.

### Problem: Fail2ban Restart — Mass Re-processing

**Expected behavior:** Restarting fail2ban re-bans all entries from its database. With the dual-jail architecture, individual IPs reload into `addr-set-dovecot` (clean, no overlaps) and subnets reload into `addr-set-dovecot-subnet` (clean, no overlaps). No more interval overlap errors on restart.

**Best practice:**
```bash
# Preferred — no re-processing
fail2ban-client reload dovecot
fail2ban-client reload dovecot-subnet

# Full restart if necessary — now clean, no error spam
systemctl restart fail2ban
```

### Problem: SELinux Denials

**Note:** The cron-based approach runs as root (unconfined context). SELinux primarily affects fail2ban's own actions. The custom policy at `$SE_DIR/f2b-complete.te` handles known requirements.

**If SELinux issues arise:**
```bash
ausearch -m avc -ts recent | grep fail2ban
cd "$SE_DIR"
ausearch -m avc -ts boot | audit2allow -M f2b-complete
cat f2b-complete.te  # ALWAYS review before installing
semodule -X 300 -i f2b-complete.pp
```

---

## Nagios Monitoring

### Check Command (on Helm)

```
check-f2b-nft-sync.sh dovecot,dovecot-subnet,postfix addr-set-dovecot,addr-set-dovecot-subnet,addr-set-postfix
```

### Expected Healthy Output

```
OK: dovecot in sync (0 IPs & 0 subnets blocked): OK: dovecot-subnet in sync (0 IPs & 1821 subnets blocked): OK: postfix in sync (85 IPs & 0 subnets blocked):|dovecot_f2b=0 dovecot_fw=0 dovecot_ips=0 dovecot_subnets=0 dovecot_blocked_addrs=0 dovecot-subnet_f2b=1821 dovecot-subnet_fw=1821 dovecot-subnet_ips=0 dovecot-subnet_subnets=1821 dovecot-subnet_blocked_addrs=336,421,036 postfix_f2b=85 postfix_fw=85 postfix_ips=85 postfix_subnets=0 postfix_blocked_addrs=0
```

### Alert Conditions

| Condition | State | Meaning | Action |
|-----------|-------|---------|--------|
| f2b count ≠ nft count (any jail) | CRITICAL | Ghost or orphan entries | See OUT OF SYNC troubleshooting |
| dovecot IPs ≥ 10 | WARNING | Batch script may have missed a cycle | Check cron, run manually |
| dovecot IPs ≥ 25 | CRITICAL | Batch script is failing | Check logs, run manually |

---

## Script Reference

### f2b_subnet_ban.sh

**Usage:**
```bash
f2b_subnet_ban.sh [--dry-run] <ip|subnet>
```

**Jail routing:**
- Reads individual IPs from: `dovecot` jail
- Unbans individual IPs from: `dovecot` jail / `addr-set-dovecot`
- Bans subnets into: `dovecot-subnet` jail / `addr-set-dovecot-subnet`
- Checks existing coverage against: `addr-set-dovecot-subnet`

**Flow:**
1. **Startup grace check** — if fail2ban running < 120s, exit (avoids restart re-processing)
2. **CIDR detection** — if input contains `/`, treat as manual subnet (skip RDAP/whois)
3. **Dedup cache** — if same IP processed within 60s, exit silently (`/tmp/f2b_subnet_dedup/`)
4. **Subnet-only nft pre-check** — checks `addr-set-dovecot-subnet` for existing coverage
5. **RDAP lookup** — 5 RIR servers, 5s timeout each, IPv4 forced
6. **Whois fallback** — 2 retries if RDAP fails
7. **Sanity checks** — rejects broader than /8 or equal to /32
8. **Unban** — removes triggering IP from `dovecot` jail; removes narrower subnets from `dovecot-subnet` jail
9. **Ban** — adds subnet to `dovecot-subnet` jail
10. **Email** — sends notification
11. **Backup sync** — updates `banned_ips_dovecot.txt`

### batch_subnet_cached.py

**Usage:**
```bash
python3 $F2B_DIR/batch_subnet_cached.py [--dry-run]
```

**Reads from:** `dovecot` jail (individual IPs)
**Bans into:** `dovecot-subnet` jail (via `f2b_subnet_ban.sh`)

**Features:**
- Groups uncovered IPs by /16 for efficient lookups
- Caches RDAP/whois results to `whois_cache.json`
- RDAP primary (IPv4 forced), whois fallback

**Cache format:**
```json
{
  "87.236": "87.236.176.128/25",
  "87.236:87.236.176.68": "87.236.176.0/25",
  "41.139": "TOO_BROAD:41.139.0.0/10"
}
```

### backup_f2b_dovecot.sh

**Usage:**
```bash
sh ~/fail2-backup/backup_f2b_dovecot.sh [--force] [--dry-run]
```

**Combines both jails** (`dovecot` + `dovecot-subnet`) into a single sorted backup file.

| Flag | Behavior |
|------|----------|
| (none) | Only writes if new count ≥ old count |
| `--force` | Writes regardless of count comparison |
| `--dry-run` | Shows what would happen without writing |

### get_f2b_stats.sh

**Usage:**
```bash
sh ~/fail2-backup/get_f2b_stats.sh
```

**Checks three things independently:**
1. `dovecot` jail vs `addr-set-dovecot` (individual IPs)
2. `dovecot-subnet` jail vs `addr-set-dovecot-subnet` (subnets)
3. `postfix` jail vs `addr-set-postfix` (individual IPs)

### check-f2b-nft-sync.sh (Nagios)

**Usage:**
```bash
/usr/local/bin/check-f2b-nft-sync.sh dovecot,dovecot-subnet,postfix addr-set-dovecot,addr-set-dovecot-subnet,addr-set-postfix
```

**Loops over jail/set pairs.** Additional dovecot-specific threshold: alerts if individual IPs pending escalation exceed 10 (WARNING) or 25 (CRITICAL).

---

## Counting Methodology — CRITICAL

### Regex for IPs vs Subnets

```bash
# WRONG — matches partial IPs from subnet entries (e.g., 87.236.176.12 from 87.236.176.128/25)
grep -oP '(\d{1,3}\.){3}\d{1,3}(?!/)'

# CORRECT — word boundary prevents partial matches
grep -oP '(\d{1,3}\.){3}\d{1,3}\b(?!/)'
```

### Counting from fail2ban

`fail2ban-client get <jail> banip` outputs ALL entries on ONE line, space-separated:

```bash
# WRONG — always returns 1
fail2ban-client get dovecot banip | wc -l

# CORRECT
fail2ban-client get dovecot banip | wc -w
```

---

## Jail Configuration Reference

### /etc/fail2ban/jail.local

**Dovecot (individual IPs):**
```ini
[dovecot]
port    = imaps
logpath = %(dovecot_log)s
backend = %(dovecot_backend)s
enabled = true
mode    = aggressive
bantime = -1
maxretry = 1
findtime = 1y
action = %(action_mwl)s[_grep_logs='journalctl -u dovecot -n 1000 | grep -m 1000 -wF "<ip>"']
```

**Dovecot Subnet (CIDR bans — managed by cron):**
```ini
[dovecot-subnet]
enabled = true
filter = dovecot-subnet
logpath = /var/log/fail2ban.log
bantime = -1
maxretry = 1
findtime = 1y
banaction = nftables-multiport[blocktype=reject]
port = imaps
```

**Postfix (individual IPs with escalating bantimes):**
```ini
bantime.increment = true
bantime.rndtime = 3600
bantime.maxtime = 10w
bantime.factor = 1
bantime.multipliers = 1 1 2 4 8 16 32 64
bantime.overalljails = true
[postfix]
mode    = aggressive
port    = smtp
logpath = %(postfix_log)s
backend = %(postfix_backend)s
enabled  = true
maxretry = 3
findtime = 1y
bantime  = 2d
action = %(action_mwl)s
```

### /etc/fail2ban/filter.d/dovecot-subnet.conf

```ini
# Dummy filter for subnet bans - no log matching needed
# Subnets are added via fail2ban-client by the cron batch script
[Definition]
failregex =
ignoreregex =
```

---

## Guardrails

### DO NOT

- **Do not re-add `subnet-ban` to dovecot jail actions** — the old real-time approach caused race conditions
- **Do not ban subnets into the `dovecot` jail** — use `dovecot-subnet` for all CIDR bans
- **Do not ban individual IPs into `dovecot-subnet`** — use `dovecot` for individual IPs
- **Do not ban subnets broader than /8** — script enforces this, but manual bans bypass it
- **Do not modify nft directly** without updating fail2ban — causes sync issues
- **Do not ban subnets on the postfix jail** — public-facing, would block legitimate mail
- **Do not use `pip`** — use `dnf` for system packages
- **Do not suggest `nano`** — Craig uses `vim` exclusively

### ALWAYS

- **Always dry-run first** when testing subnet ban script manually
- **Always check sync** after manual intervention: `sh ~/fail2-backup/get_f2b_stats.sh`
- **Always use full paths** in scripts (`/usr/bin/fail2ban-client`, `/usr/bin/whois`, `/usr/sbin/sendmail`, `/usr/sbin/nft`)
- **Always reload, don't restart** fail2ban when possible
- **Always review SELinux policy** before installing
- **Always verify Rocky Linux version** before providing dnf commands
- **Always confirm subnet jail** — bans go to `dovecot-subnet`, unbans of IPs come from `dovecot`

### SAFE OPERATIONS (no confirmation needed)

- Running `get_f2b_stats.sh`
- Running `find_outOfSync.sh`
- Running `f2b_subnet_ban.sh --dry-run`
- Running `batch_subnet_cached.py --dry-run`
- Running `whois_cache_loop.sh` (this is what cron runs)
- Running `backup_f2b_dovecot.sh --dry-run`
- Tailing logs
- Checking Nagios status

### REQUIRES CONFIRMATION

- Running `f2b_subnet_ban.sh` without `--dry-run`
- Unbanning any entry from any jail
- Restarting fail2ban
- Installing SELinux policy modules
- Modifying jail.local or action/filter definitions
- Modifying cron jobs
- Running `backup_f2b_dovecot.sh --force`

---

## Known Behaviors (Not Bugs)

### Individual IPs between cron runs

Between cron cycles (up to 10 minutes), individual IPs accumulate in the `dovecot` jail. This is normal — the bot is blocked immediately by the individual IP ban in `addr-set-dovecot`. The cron job escalates to subnet.

### "already banned" on subnet re-ban

When the cron script bans a subnet that already exists in `dovecot-subnet`, fail2ban logs "already banned". This is harmless — indicates no change needed.

### Postfix bans from dovecot-banned IPs

Bots that hit dovecot also try postfix. The postfix ban uses escalating bantimes. This is the intended design — dovecot blocks immediately and permanently, postfix blocks temporarily with increasing severity.

### Repeated "Found" from same IP

A bot with an established TCP connection sends multiple auth attempts before nft blocks new SYN packets. Each generates a "Found" log entry. Normal.

---

## Lessons Learned

1. **Dual-jail architecture** — Separate nft sets for IPs and subnets eliminates interval overlap errors entirely.
2. **Cron over real-time** — Real-time subnet escalation from fail2ban actions is fragile (timeouts, SELinux, race conditions). Cron batch is robust.
3. **fail2ban-client output** — `get <jail> banip` outputs all on ONE line, space-separated. Use `wc -w` not `wc -l`.
4. **nft interval overlaps** — Cannot have individual IPs and subnets in the same interval set if the IP falls within the subnet.
5. **RDAP IPv6** — No IPv6 on the server. Force IPv4 via Python socket monkey-patching.
6. **Regex counting** — `(?!/)` matches partial IPs from subnet entries. Always use `\b(?!/)`.
7. **SELinux** — Custom policy at `$SE_DIR/f2b-complete.te`. Only affects fail2ban context, not cron.
8. **Full paths required** — Scripts called from fail2ban have minimal `$PATH`. Always use absolute paths.
9. **fail2ban restart** — With dual jails, restarts are now clean. No overlap errors since IPs and subnets are in separate sets.
10. **Backup script** — Combines both jails. Use `--force` when count drops (expected after jail migration). Use `--dry-run` to preview.
11. **Ghost entries** — Entries in f2b but not nft. Each jail/set pair must be checked independently.
12. **LACNIC rate limiting** — RDAP as primary avoids whois rate limits. Batch groups by /16 and caches.
