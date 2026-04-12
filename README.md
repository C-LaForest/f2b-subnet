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

```bash
export F2B_DIR=/your/custom/path
./install.sh
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
