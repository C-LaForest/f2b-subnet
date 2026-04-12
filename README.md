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

| Variable | Default | Used by | Description |
|----------|---------|---------|-------------|
| `F2B_DIR` | `/opt/f2b-subnet` | All scripts, `install.sh` | Base directory for data files and scripts |
| `SE_DIR` | `$F2B_DIR/selinux` | `install.sh` | SELinux policy directory |
| `F2B_CACHE_TTL_SUCCESS` | `2592000` (30 days) | `batch_subnet_cached.py` | Seconds before successful cache entries are eligible for revalidation (with `--revalidate`) |
| `F2B_CACHE_TTL_FAILURE` | `86400` (24 hours) | `batch_subnet_cached.py` | Seconds before failed lookups are retried |
| `F2B_LOOKUP_TIMEOUT` | `15` | `batch_subnet_cached.py` | Hard timeout (seconds) per RDAP+whois lookup |
| `F2B_REVALIDATE_MAX` | `200` | `batch_subnet_cached.py` | Max cache entries to re-lookup per `--revalidate` run |
| `F2B_REVALIDATE_DELAY_MIN` | `1` | `batch_subnet_cached.py` | Min seconds between revalidation lookups (jitter floor) |
| `F2B_REVALIDATE_DELAY_MAX` | `5` | `batch_subnet_cached.py` | Max seconds between revalidation lookups (jitter ceiling) |
| `F2B_FROM` | `fail2ban@$(hostname -f)` | `f2b_subnet_ban.sh` | Sender address for subnet ban notification emails |

```bash
export F2B_DIR=/your/custom/path
./install.sh
```

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

## Requirements

- Rocky Linux / CentOS Stream / RHEL
- fail2ban with nftables backend
- Python 3 (stdlib only — no pip)
- whois (`dnf install whois`)
- SELinux enforcing (custom policy provided)

## Cron

```cron
# Batch subnet escalation (every 10 min)
*/10 * * * * $F2B_DIR/whois_cache_loop.sh --cron >> /var/log/f2b_subnet_ban.log 2>&1

# Daily backup (separate files per jail)
10 1 * * * $F2B_DIR/backup_f2b_dovecot.sh

# Weekly cache revalidation (re-check entries older than F2B_CACHE_TTL_SUCCESS)
0 3 * * 0 python3 $F2B_DIR/batch_subnet_cached.py --revalidate >> /var/log/f2b_subnet_ban.log 2>&1
```

## Nagios

```
check-f2b-nft-sync.sh dovecot,dovecot-subnet,postfix addr-set-dovecot,addr-set-dovecot-subnet,addr-set-postfix
```

## License

MIT — see [LICENSE](LICENSE).
