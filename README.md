# f2b-subnet — Fail2Ban Subnet Banning System

Automatically escalates individual fail2ban IP bans to their allocated subnet using RDAP/whois lookups. Designed for private services (Dovecot IMAP) where no legitimate users should be authenticating from foreign ISPs.

## Architecture

Uses a **dual-jail** approach to eliminate nft interval set overlap errors:

| Jail | nft Set | Contents | Managed by |
|------|---------|----------|------------|
| `dovecot` | `addr-set-dovecot` | Individual IPs only | fail2ban (automatic) |
| `dovecot-subnet` | `addr-set-dovecot-subnet` | Subnets only (CIDR) | Cron batch script |

Individual IPs are kept in the `dovecot` jail permanently as defense-in-depth against an [nft interval set lookup bug](https://lore.proxmox.com/all/20250911100555.63174-2-g.goller@proxmox.com/) in the pipapo backend (kernels < 6.17). The simple element set (`addr-set-dovecot`) uses the hash backend which is not affected.

A cron job runs every 10 minutes to:
1. Read individual IPs from the `dovecot` jail
2. Skip IPs already covered by existing subnet bans
3. Look up the allocated subnet via RDAP (primary) or whois (fallback)
4. Ban the subnet in the `dovecot-subnet` jail

## Files

### Scripts (`scripts/`)

| File | Install to | Purpose |
|------|-----------|---------|
| `f2b_subnet_ban.sh` | `/usr/local/bin/` | Single IP→subnet escalation |
| `batch_subnet_cached.py` | `$F2B_DIR/` | Batch converter with caching |
| `whois_cache_loop.sh` | `$F2B_DIR/` | Cron runner (lockfile, modes) |
| `get_f2b_stats.sh` | `$F2B_DIR/` | Quick status check |
| `find_outOfSync.sh` | `$F2B_DIR/` | Diff f2b vs nft |
| `backup_f2b_dovecot.sh` | `$F2B_DIR/` | Daily backup (both jails) |
| `dedup_subnets.sh` | `$F2B_DIR/` | Remove subnets covered by broader bans |
| `nft_miss_report.sh` | `$F2B_DIR/` | Subnet ban activity report (from logs) |
| `check-f2b-nft-sync.sh` | `/usr/local/bin/` | Nagios monitoring check |

### Configuration (`config/`)

| File | Install to | Purpose |
|------|-----------|---------|
| `fail2ban/nftables.local` | `/etc/fail2ban/action.d/` | Parameterized nft set flags (`addr_options`) |
| `fail2ban/dovecot-subnet.conf` | `/etc/fail2ban/filter.d/` | Dummy filter for subnet jail |
| `fail2ban/jail-dovecot.conf` | Reference only | Dovecot jail config for `jail.local` |
| `fail2ban/jail-dovecot-subnet.conf` | Reference only | Subnet jail config for `jail.local` |
| `logrotate/f2b-subnet` | `/etc/logrotate.d/` | Log rotation |
| `selinux/f2b-complete.te` | `$SE_DIR/` | SELinux policy source |

### Documentation (`docs/`)

| File | Purpose |
|------|---------|
| `HANDOVER.md` | Full operations handover for Claude Code / skill integration |

## Configuration

### Environment Variables

All scripts auto-detect their directory from their own filesystem location
(`dirname "$(readlink -f "$0")"` in bash, `os.path.dirname(os.path.abspath(__file__))` in Python).
No environment variables are needed for path configuration.

| Variable | Default | Used by | Description |
|----------|---------|---------|-------------|
| `F2B_DIR` | Auto-detected | All scripts, `install.sh` | Override base directory (optional — scripts self-locate) |
| `SE_DIR` | `$F2B_DIR/selinux` | `install.sh` | SELinux policy directory |
| `F2B_CACHE_TTL_SUCCESS` | `2592000` (30 days) | `batch_subnet_cached.py` | Seconds before successful cache entries are eligible for revalidation (with `--revalidate`) |
| `F2B_CACHE_TTL_FAILURE` | `86400` (24 hours) | `batch_subnet_cached.py` | Seconds before failed lookups are retried |
| `F2B_LOOKUP_TIMEOUT` | `15` | `batch_subnet_cached.py` | Hard timeout (seconds) per RDAP+whois lookup |
| `F2B_REVALIDATE_MAX` | `200` | `batch_subnet_cached.py` | Max cache entries to re-lookup per `--revalidate` run |
| `F2B_REVALIDATE_DELAY_MIN` | `1` | `batch_subnet_cached.py` | Min seconds between revalidation lookups (jitter floor) |
| `F2B_REVALIDATE_DELAY_MAX` | `5` | `batch_subnet_cached.py` | Max seconds between revalidation lookups (jitter ceiling) |
| `F2B_FROM` | `fail2ban@$(hostname -f)` | `f2b_subnet_ban.sh` | Sender address for subnet ban notification emails |

**Where to set overrides:** All variables have sensible defaults and most users
won't need to change anything. If you do need to override, set them in the
crontab — **never in `/etc/environment`**.

> **Lesson learned:** `/etc/environment` is parsed by `pam_env.so`, not the shell.
> It only accepts bare `KEY=VALUE` lines — `export`, quotes, variable expansion,
> and any other shell syntax will cause `pam_env.so` to return `PAM_ABORT`,
> which silently kills **all cron jobs** system-wide with a cryptic
> `"Critical error - immediate abort"` in `/var/log/cron`. The real error
> (`"Missing delimiter"`) only appears in the systemd journal (`journalctl -u crond`).

### Recommended: crontab environment block

Set variables at the top of root's crontab (`crontab -e`). These apply to all
cron jobs below them and are pure shell — `export`, quotes, and substitution all work.

```bash
# Override cache TTLs (optional — defaults are fine for most setups)
F2B_CACHE_TTL_SUCCESS=2592000
F2B_CACHE_TTL_FAILURE=86400
F2B_LOOKUP_TIMEOUT=15
F2B_FROM=fail2ban@mail.example.com

# Batch subnet escalation (every 10 min)
*/10 * * * * /root/fail2-backup/whois_cache_loop.sh --cron >> /var/log/f2b_subnet_ban.log 2>&1

# Weekly cache revalidation
0 3 * * 0 python3 /root/fail2-backup/batch_subnet_cached.py --revalidate >> /var/log/f2b_subnet_ban.log 2>&1
```

### Alternative: inline per-command

Useful when only one job needs a non-default value:

```bash
*/10 * * * * F2B_LOOKUP_TIMEOUT=30 /root/fail2-backup/whois_cache_loop.sh --cron >> /var/log/f2b_subnet_ban.log 2>&1
```

### Alternative: wrapper script

For complex overrides, wrap in a shell script:

```bash
#!/bin/bash
export F2B_CACHE_TTL_SUCCESS=604800   # 7 days
export F2B_CACHE_TTL_FAILURE=3600     # 1 hour
export F2B_LOOKUP_TIMEOUT=30
export F2B_REVALIDATE_MAX=500
exec /root/fail2-backup/whois_cache_loop.sh --cron
```

### Variable reference by context

| Variable | Where to set | Notes |
|----------|-------------|-------|
| `F2B_DIR` | Usually unnecessary | Scripts auto-detect from their own location |
| `F2B_CACHE_TTL_*` | Crontab or wrapper | Only needed if default TTLs don't suit your lookup volume |
| `F2B_LOOKUP_TIMEOUT` | Crontab or wrapper | Increase if RDAP servers are slow in your region |
| `F2B_REVALIDATE_*` | Crontab or wrapper | Tune for `--revalidate` runs only |
| `F2B_FROM` | Crontab or wrapper | Set to match your mail server's accepted sender addresses |
| `SE_DIR` | `install.sh` invocation only | `SE_DIR=/path install.sh` — not needed at runtime |

## Batch Script Usage

### Normal operation

```bash
# Automatic batch processing (used by cron via whois_cache_loop.sh)
batch_subnet_cached.py

# Dry-run — show what would happen without banning
batch_subnet_cached.py --dry-run

# Revalidate — re-lookup cached entries older than F2B_CACHE_TTL_SUCCESS
batch_subnet_cached.py --revalidate
```

### Manual injection

When RDAP/whois lookups fail (rate limiting, unreachable registries), you can manually inject subnet data from online whois tools.

```bash
# List IPs that have no subnet ban covering them
batch_subnet_cached.py --list-uncovered

# Inject a specific IP→subnet mapping (updates cache + bans)
batch_subnet_cached.py --inject 109.125.248.113 109.125.240.0/20

# Inject one or more CIDRs directly
batch_subnet_cached.py --inject-cidr 109.125.240.0/20 193.32.176.0/24

# Inject from a whois inetnum range (auto-converts to CIDRs)
batch_subnet_cached.py --inject-range 109.125.240.0 109.125.255.255
```

All inject modes support `--dry-run`. They update the whois cache, clear any
failed cache entries for IPs in the range, and ban the subnet(s).

**Typical workflow** when the batch script reports failures:

1. `batch_subnet_cached.py --list-uncovered` — see which IPs need subnets
2. Look up the IP on an online whois tool (e.g., RIPE, ARIN, APNIC)
3. `batch_subnet_cached.py --inject-cidr <cidr>` — inject and ban
4. `batch_subnet_cached.py --dry-run` — verify zero uncovered IPs

### Cache behavior

Lookups are cached in `$F2B_DIR/whois_cache.json` with timestamps:

- **Successful lookups** are used indefinitely during normal runs. They are
  only re-checked when `--revalidate` is passed and the entry is older than
  `F2B_CACHE_TTL_SUCCESS` (default: 30 days).
- **Failed lookups** are automatically retried after `F2B_CACHE_TTL_FAILURE`
  (default: 24 hours). Manual injection (`--inject*`) clears failed entries
  for IPs covered by the injected subnet.
- **Rate limiting** (HTTP 429) is detected and stops further lookups to that
  RIR immediately, rather than burning through all 5 RDAP servers.

## Postfix SASL Hardening

Brute-force attackers targeting SMTP port 25 with SASL AUTH attempts trigger
Dovecot auth failures even when the IMAP port is blocked. This happens because
Postfix delegates SASL authentication to Dovecot's auth daemon — the attacker
never touches IMAP, but the auth failure still shows up in Dovecot's logs and
triggers the `dovecot` fail2ban jail.

**Flow:** Attacker → SMTP (port 25) → `EHLO` / `AUTH` → Postfix asks Dovecot auth → auth fails → both `dovecot` and `postfix` jails fire.

**Fix:** Disable SASL on port 25 (server-to-server relay) and restrict it to
submission (587) and smtps (465) where legitimate clients connect:

```bash
# Disable SASL globally (affects port 25)
postconf -e 'smtpd_sasl_auth_enable=no'
```

Then in `/etc/postfix/master.cf`, override on submission/smtps services:

```
submission inet n       -       n       -       -       smtpd
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_security_level=encrypt

smtps     inet n       -       n       -       -       smtpd
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_wrappermode=yes
```

Verify with `postfix check`, then `postfix reload`. Confirm port 25 no longer
advertises AUTH:

```bash
# Port 25 — should NOT show 250-AUTH
(sleep 1; echo EHLO test; sleep 1; echo QUIT) | openssl s_client -connect localhost:25 -starttls smtp -quiet 2>/dev/null

# Port 587 — should show 250-AUTH PLAIN
(sleep 1; echo EHLO test; sleep 1; echo QUIT) | openssl s_client -connect localhost:587 -starttls smtp -quiet 2>/dev/null
```

## Requirements

- Rocky Linux / CentOS Stream / RHEL
- fail2ban with nftables backend
- Python 3 (stdlib only — no pip)
- whois (`dnf install whois`)
- SELinux enforcing (custom policy provided)

## Cron

```cron
# Batch subnet escalation (every 10 min)
*/10 * * * * /path/to/whois_cache_loop.sh --cron >> /var/log/f2b_subnet_ban.log 2>&1

# Daily backup (separate files per jail)
10 1 * * * /path/to/backup_f2b_dovecot.sh

# Weekly cache revalidation (re-check entries older than F2B_CACHE_TTL_SUCCESS)
0 3 * * 0 python3 /path/to/batch_subnet_cached.py --revalidate >> /var/log/f2b_subnet_ban.log 2>&1
```

### Cron log format

The cron runner (`whois_cache_loop.sh --cron`) logs a one-line summary per run:

```
whois_cache_loop.sh: skipped=7442 new_subnets=5 failed=2 ips=7446 subnets=2074
```

| Field | Meaning |
|-------|---------|
| `skipped` | IPs already covered by existing subnet bans |
| `new_subnets` | New subnet bans created this run |
| `failed` | RDAP/whois lookups that failed (retried after `F2B_CACHE_TTL_FAILURE`) |
| `ips` | Total individual IPs in the `dovecot` jail (kept permanently) |
| `subnets` | Total subnet bans in the `dovecot-subnet` jail |

### Activity report

`nft_miss_report.sh` parses the cron log to summarize banning activity,
lookup failures, and rate limiting events:

```bash
$F2B_DIR/nft_miss_report.sh [/var/log/f2b_subnet_ban.log]
```

## Nagios

```
check-f2b-nft-sync.sh dovecot,dovecot-subnet,postfix addr-set-dovecot,addr-set-dovecot-subnet,addr-set-postfix
```

## License

MIT — see [LICENSE](LICENSE).
