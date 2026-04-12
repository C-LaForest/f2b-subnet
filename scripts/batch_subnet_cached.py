#!/usr/bin/env python3
"""Batch convert individual fail2ban bans to subnets using cached lookups"""

import bisect
import ipaddress
import random
import signal
import subprocess
import sys
import time
import re
import json
import os
import urllib.request

JAIL = "dovecot"
SUBNET_JAIL = "dovecot-subnet"
F2B_DIR = os.environ.get("F2B_DIR", "/opt/f2b-subnet")
CACHE_FILE = F2B_DIR + "/whois_cache.json"
SCRIPT = "/usr/local/bin/f2b_subnet_ban.sh"

DRY_RUN = "--dry-run" in sys.argv
REVALIDATE = "--revalidate" in sys.argv
INJECT = "--inject" in sys.argv
INJECT_CIDR = "--inject-cidr" in sys.argv
INJECT_RANGE = "--inject-range" in sys.argv
LIST_UNCOVERED = "--list-uncovered" in sys.argv

# Cache TTLs (seconds) — configurable via environment
CACHE_TTL_SUCCESS = int(os.environ.get("F2B_CACHE_TTL_SUCCESS", 30 * 86400))  # 30 days
CACHE_TTL_FAILURE = int(os.environ.get("F2B_CACHE_TTL_FAILURE", 24 * 3600))   # 24 hours
LOOKUP_TIMEOUT = int(os.environ.get("F2B_LOOKUP_TIMEOUT", 15))                # seconds per IP
REVALIDATE_MAX = int(os.environ.get("F2B_REVALIDATE_MAX", 200))              # max entries per revalidation run
REVALIDATE_DELAY_MIN = float(os.environ.get("F2B_REVALIDATE_DELAY_MIN", 1))  # min seconds between revalidation lookups
REVALIDATE_DELAY_MAX = float(os.environ.get("F2B_REVALIDATE_DELAY_MAX", 5))  # max seconds between revalidation lookups

class LookupTimeout(Exception):
    pass

class RateLimited(Exception):
    pass

_rate_limited = False

def _timeout_handler(signum, frame):
    raise LookupTimeout()

NOW = int(time.time())

# --- Cache management ---

def load_cache():
    if not os.path.exists(CACHE_FILE):
        return {}
    with open(CACHE_FILE) as f:
        raw = json.load(f)
    # Migrate old format: bare strings/None → timestamped entries
    migrated = {}
    for key, val in raw.items():
        if isinstance(val, dict) and "ts" in val:
            migrated[key] = val
        elif val is None:
            migrated[key] = {"subnet": None, "ts": 0}
        elif isinstance(val, str) and val.startswith("TOO_BROAD:"):
            migrated[key] = {"subnet": val, "ts": NOW}
        elif isinstance(val, str):
            migrated[key] = {"subnet": val, "ts": NOW}
        else:
            migrated[key] = {"subnet": val, "ts": 0}
    return migrated

cache = load_cache()

def save_cache():
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache, f, indent=2)

def _shutdown_handler(signum, frame):
    """Save cache on interrupt so partial progress isn't lost."""
    print(f"\nInterrupted — saving cache to {CACHE_FILE}")
    save_cache()
    sys.exit(1)

signal.signal(signal.SIGINT, _shutdown_handler)
signal.signal(signal.SIGTERM, _shutdown_handler)

def cache_set(key, subnet):
    cache[key] = {"subnet": subnet, "ts": NOW}

def cache_get(key):
    """Return (subnet_or_None, is_expired) or (None, True) if not in cache."""
    if key not in cache:
        return None, True
    entry = cache[key]
    subnet = entry.get("subnet")
    ts = entry.get("ts", 0)
    if subnet is None:
        # Failed lookup — expired after CACHE_TTL_FAILURE
        expired = (NOW - ts) >= CACHE_TTL_FAILURE
        return None, expired
    elif isinstance(subnet, str) and subnet.startswith("TOO_BROAD:"):
        expired = REVALIDATE and (NOW - ts) >= CACHE_TTL_SUCCESS
        return subnet, expired
    else:
        expired = REVALIDATE and (NOW - ts) >= CACHE_TTL_SUCCESS
        return subnet, expired


# --- Network lookups ---

class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject redirects — RDAP servers redirect to the authoritative RIR,
    but following the redirect often hangs on SSL. We try each RIR directly."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(newurl, code, msg, headers, fp)

_rdap_opener = urllib.request.build_opener(_NoRedirectHandler)

def rdap_lookup(ip):
    """RDAP lookup - structured JSON over HTTP"""
    import socket
    origgetaddrinfo = socket.getaddrinfo
    def getaddrinfo4(host, port, family=0, type=0, proto=0, flags=0):
        return origgetaddrinfo(host, port, socket.AF_INET, type, proto, flags)
    socket.getaddrinfo = getaddrinfo4

    urls = [
        f"https://rdap.db.ripe.net/ip/{ip}",
        f"https://rdap.apnic.net/ip/{ip}",
        f"https://rdap.arin.net/registry/ip/{ip}",
        f"https://rdap.lacnic.net/rdap/ip/{ip}",
        f"https://rdap.afrinic.net/rdap/ip/{ip}",
    ]
    if REVALIDATE:
        urls = urls[:]  # copy before shuffling
        random.shuffle(urls)
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'Accept': 'application/rdap+json'})
            with _rdap_opener.open(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())

                # Check for rate limiting (errorCode in response body)
                if data.get('errorCode') in (429, 503):
                    print("[RATE-LIMITED]", end=" ", flush=True)
                    socket.getaddrinfo = origgetaddrinfo
                    raise RateLimited()

                if 'cidr0_cidrs' in data:
                    for cidr in data['cidr0_cidrs']:
                        prefix = f"{cidr['v4prefix']}/{cidr['length']}"
                        net = ipaddress.IPv4Network(prefix)
                        if ipaddress.IPv4Address(ip) in net:
                            socket.getaddrinfo = origgetaddrinfo
                            return prefix

                if 'startAddress' in data and 'endAddress' in data:
                    start = ipaddress.IPv4Address(data['startAddress'])
                    end = ipaddress.IPv4Address(data['endAddress'])
                    ip_obj = ipaddress.IPv4Address(ip)
                    for net in ipaddress.summarize_address_range(start, end):
                        if ip_obj in net:
                            socket.getaddrinfo = origgetaddrinfo
                            return str(net)

                continue  # Got response but no match — try next RIR
        except urllib.error.HTTPError as e:
            if e.code == 429:
                print("[RATE-LIMITED]", end=" ", flush=True)
                socket.getaddrinfo = origgetaddrinfo
                raise RateLimited()
            continue
        except (urllib.error.URLError, json.JSONDecodeError, KeyError, OSError):
            continue

    socket.getaddrinfo = origgetaddrinfo
    return None

def whois_lookup(ip):
    """Whois lookup - legacy fallback"""
    for attempt in range(2):
        try:
            result = subprocess.run(['/usr/bin/whois', ip], capture_output=True,
                                    text=True, timeout=30)
            out = result.stdout

            m = re.search(
                r'(?i)^\s*CIDR:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})',
                out, re.M)
            if m:
                return m.group(1)

            m = re.search(
                r'(?i)^\s*inetnum:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})',
                out, re.M)
            if m:
                return m.group(1)

            m = re.search(
                r'(?i)^\s*inetnum:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*-\s*'
                r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                out, re.M)
            if m:
                start = ipaddress.IPv4Address(m.group(1))
                end = ipaddress.IPv4Address(m.group(2))
                ip_obj = ipaddress.IPv4Address(ip)
                for net in ipaddress.summarize_address_range(start, end):
                    if ip_obj in net:
                        return str(net)

            if not re.search(r'(?i)(inetnum|CIDR|NetRange)', out):
                time.sleep((attempt + 1) * 5)
                continue

            return None
        except subprocess.TimeoutExpired:
            time.sleep((attempt + 1) * 5)

    return None

def lookup_subnet(ip):
    """RDAP first, whois fallback. Hard timeout via SIGALRM."""
    global _rate_limited
    old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
    signal.alarm(LOOKUP_TIMEOUT)
    try:
        result = rdap_lookup(ip)
        if result:
            return result

        print("[whois fallback]", end=" ", flush=True)
        return whois_lookup(ip)
    except LookupTimeout:
        print("[TIMEOUT]", end=" ", flush=True)
        return None
    except RateLimited:
        _rate_limited = True
        return None
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


# --- Subnet management ---

def is_covered_by_broader(subnet_str):
    """Check if subnet is already covered by a broader existing ban"""
    net = ipaddress.IPv4Network(subnet_str)
    net_start = int(net.network_address)
    net_end = int(net.broadcast_address)
    idx = bisect.bisect_right(subnet_starts, net_start) - 1
    if idx >= 0 and net_start >= subnet_ranges[idx][0] and net_end <= subnet_ranges[idx][1]:
        existing = subnet_ranges[idx][2]
        if existing != net:
            return str(existing)
    return None

def ban_subnet(subnet):
    """Call f2b_subnet_ban.sh and track the subnet"""
    broader = is_covered_by_broader(subnet)
    if broader:
        print(f"  Skipping {subnet} (covered by existing {broader})")
        return
    cmd = [SCRIPT]
    if DRY_RUN:
        cmd.append("--dry-run")
    cmd.append(subnet)
    subprocess.run(cmd)
    existing_nets.add(subnet)


# --- Leftover processing ---

def process_leftovers(leftover_ips, prefix, label):
    """Process leftover IPs, caching discovered subnets to avoid repeat lookups"""
    global processed, skipped, failed
    discovered = {}  # subnet_str -> IPv4Network

    for leftover_ip in leftover_ips:
        lp = f"{prefix}:{leftover_ip}"
        ip_obj = ipaddress.IPv4Address(leftover_ip)

        # Check if covered by an already-discovered subnet in this batch
        already_covered = False
        for sub_str, sub_net in discovered.items():
            if ip_obj in sub_net:
                already_covered = True
                break
        if already_covered:
            continue

        # Check per-IP cache
        cached_val, expired = cache_get(lp)
        if not expired and lp in cache:
            if cached_val is None:
                failed += 1
                continue
            elif isinstance(cached_val, str) and cached_val.startswith("TOO_BROAD:"):
                continue
            elif cached_val in existing_nets:
                discovered[cached_val] = ipaddress.IPv4Network(cached_val)
                continue
            else:
                sub = cached_val
                print(f"[CACHED] {leftover_ip} → {sub}")
                ban_subnet(sub)
                discovered[sub] = ipaddress.IPv4Network(sub)
                processed += 1
                if not DRY_RUN:
                    time.sleep(0.5)
                continue

        print(f"[LOOKUP] {leftover_ip} ({label})...", end=" ", flush=True)
        sub = lookup_subnet(leftover_ip)
        if sub:
            net = ipaddress.IPv4Network(sub)
            if net.prefixlen < 8:
                print(f"too broad (/{net.prefixlen}), skipping")
                cache_set(lp, f"TOO_BROAD:{sub}")
                save_cache()
                continue
            cache_set(lp, sub)
            save_cache()
            discovered[sub] = net
            if sub in existing_nets:
                print(f"→ {sub} (already banned)")
                continue
            print(f"→ {sub}")
            ban_subnet(sub)
            processed += 1
            if not DRY_RUN:
                time.sleep(1)
        else:
            print("FAILED")
            cache_set(lp, None)
            save_cache()
            failed += 1
            time.sleep(3)


# --- Inject modes ---

def inject_for_cidrs(cidrs):
    """Update cache and ban for a list of CIDRs. Clears failed entries for covered IPs."""
    # Get current uncovered IPs to update their cache entries
    result = subprocess.run(['/usr/bin/fail2ban-client', 'get', JAIL, 'banip'],
                            capture_output=True, text=True)
    all_ips = [e for e in result.stdout.split() if '/' not in e and e]

    nets = [ipaddress.IPv4Network(c) for c in cidrs]
    updated = 0

    for ip in all_ips:
        ip_obj = ipaddress.IPv4Address(ip)
        for net in nets:
            if ip_obj in net:
                parts = ip.split('.')
                prefix = f"{parts[0]}.{parts[1]}"
                lp = f"{prefix}:{ip}"
                # Clear failed per-IP cache entry if it exists
                if lp in cache:
                    old = cache[lp].get("subnet") if isinstance(cache[lp], dict) else cache[lp]
                    if old is None:
                        cache_set(lp, str(net))
                        updated += 1
                break

    # Update group-level cache entries too
    for net in nets:
        parts = str(net.network_address).split('.')
        prefix = f"{parts[0]}.{parts[1]}"
        # Only set group cache if not already set to a valid subnet
        cached_val, _ = cache_get(prefix)
        if cached_val is None or prefix not in cache:
            cache_set(prefix, str(net))
            print(f"Cache: {prefix} → {net}")

    save_cache()
    print(f"Updated {updated} per-IP cache entries")

    # Ban each CIDR
    for cidr in cidrs:
        cmd = [SCRIPT]
        if DRY_RUN:
            cmd.append("--dry-run")
        cmd.append(cidr)
        print(f"Banning {cidr}...")
        subprocess.run(cmd)

def do_inject():
    """--inject <ip> <cidr> — map an IP to its subnet, update cache, ban."""
    args = [a for a in sys.argv[1:] if a not in ("--inject", "--dry-run")]
    if len(args) != 2:
        print("Usage: batch_subnet_cached.py --inject <ip> <cidr> [--dry-run]", file=sys.stderr)
        sys.exit(1)
    ip, cidr = args[0], args[1]
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        net = ipaddress.IPv4Network(cidr)
    except ValueError as e:
        print(f"Invalid input: {e}", file=sys.stderr)
        sys.exit(1)
    if ip_obj not in net:
        print(f"Warning: {ip} is not within {cidr} — proceeding anyway")
    inject_for_cidrs([cidr])

def do_inject_cidr():
    """--inject-cidr <cidr> [<cidr>...] — ban CIDRs and update cache."""
    args = [a for a in sys.argv[1:] if a not in ("--inject-cidr", "--dry-run")]
    if not args:
        print("Usage: batch_subnet_cached.py --inject-cidr <cidr> [<cidr>...] [--dry-run]", file=sys.stderr)
        sys.exit(1)
    cidrs = []
    for arg in args:
        try:
            ipaddress.IPv4Network(arg)
            cidrs.append(arg)
        except ValueError as e:
            print(f"Invalid CIDR '{arg}': {e}", file=sys.stderr)
            sys.exit(1)
    inject_for_cidrs(cidrs)

def do_inject_range():
    """--inject-range <start_ip> <end_ip> — convert range to CIDRs, ban, update cache."""
    args = [a for a in sys.argv[1:] if a not in ("--inject-range", "--dry-run")]
    if len(args) != 2:
        print("Usage: batch_subnet_cached.py --inject-range <start_ip> <end_ip> [--dry-run]", file=sys.stderr)
        sys.exit(1)
    try:
        start = ipaddress.IPv4Address(args[0])
        end = ipaddress.IPv4Address(args[1])
    except ValueError as e:
        print(f"Invalid IP: {e}", file=sys.stderr)
        sys.exit(1)
    cidrs = [str(net) for net in ipaddress.summarize_address_range(start, end)]
    print(f"Range {start} - {end} → {', '.join(cidrs)}")
    inject_for_cidrs(cidrs)

def do_list_uncovered():
    """--list-uncovered — show IPs not covered by any subnet ban."""
    result = subprocess.run(['/usr/bin/fail2ban-client', 'get', JAIL, 'banip'],
                            capture_output=True, text=True)
    ips = [e for e in result.stdout.split() if '/' not in e and e]

    result = subprocess.run(['/usr/bin/fail2ban-client', 'get', SUBNET_JAIL, 'banip'],
                            capture_output=True, text=True)
    subnets = [ipaddress.IPv4Network(e) for e in result.stdout.split() if '/' in e and e]

    ranges = sorted(
        (int(n.network_address), int(n.broadcast_address)) for n in subnets
    )
    starts = [r[0] for r in ranges]

    uncovered = []
    for ip in ips:
        ip_int = int(ipaddress.IPv4Address(ip))
        idx = bisect.bisect_right(starts, ip_int) - 1
        if idx < 0 or ip_int > ranges[idx][1]:
            uncovered.append(ip)

    for ip in sorted(uncovered, key=lambda x: int(ipaddress.IPv4Address(x))):
        print(ip)
    print(f"\nTotal: {len(uncovered)} uncovered out of {len(ips)} IPs")

# Dispatch inject/list modes (run and exit, skip batch processing)
if LIST_UNCOVERED:
    do_list_uncovered()
    sys.exit(0)
elif INJECT:
    do_inject()
    sys.exit(0)
elif INJECT_CIDR:
    do_inject_cidr()
    sys.exit(0)
elif INJECT_RANGE:
    do_inject_range()
    sys.exit(0)


# --- Main ---

def get_ban_state():
    """Get current ban state - IPs from dovecot, subnets from dovecot-subnet"""
    # Individual IPs from dovecot jail
    result = subprocess.run(['/usr/bin/fail2ban-client', 'get', JAIL, 'banip'],
                            capture_output=True, text=True)
    ips = [e for e in result.stdout.split() if '/' not in e and e]

    # Subnets from dovecot-subnet jail
    result = subprocess.run(['/usr/bin/fail2ban-client', 'get', SUBNET_JAIL, 'banip'],
                            capture_output=True, text=True)
    subnets = [e for e in result.stdout.split() if '/' in e and e]

    return ips, subnets

# Get current state
individual_ips, existing_subnets = get_ban_state()

print(f"Individual IPs: {len(individual_ips)}")
print(f"Existing subnets: {len(existing_subnets)}")

if REVALIDATE:
    print(f"Revalidation mode: entries older than {CACHE_TTL_SUCCESS // 86400}d will be re-looked up"
          f" (max {REVALIDATE_MAX}, delay {REVALIDATE_DELAY_MIN}-{REVALIDATE_DELAY_MAX}s)")

# Build set of existing subnet networks for fast lookup
existing_nets = set(existing_subnets)

# Build sorted integer ranges for O(log n) coverage checks
subnet_ranges = sorted(
    (int(net.network_address), int(net.broadcast_address), net)
    for net in (ipaddress.IPv4Network(s) for s in existing_subnets)
)
subnet_starts = [r[0] for r in subnet_ranges]

def is_covered(ip_int):
    idx = bisect.bisect_right(subnet_starts, ip_int) - 1
    return idx >= 0 and ip_int <= subnet_ranges[idx][1]

# Revalidation pass: re-lookup stale cache entries
if REVALIDATE:
    stale = [(k, v) for k, v in cache.items()
             if isinstance(v, dict)
             and v.get("subnet") is not None
             and not str(v.get("subnet", "")).startswith("TOO_BROAD:")
             and (NOW - v.get("ts", 0)) >= CACHE_TTL_SUCCESS]
    random.shuffle(stale)  # randomize order to spread across RIRs over multiple runs
    stale = stale[:REVALIDATE_MAX]

    if stale:
        print(f"\nRevalidating {len(stale)} stale cache entries...")
        revalidated = 0
        reval_failed = 0
        for key, entry in stale:
            if _rate_limited:
                print(f"Rate limited — stopping revalidation ({revalidated} done, "
                      f"{len(stale) - revalidated - reval_failed} deferred)")
                break

            old_subnet = entry["subnet"]
            # Extract a sample IP to look up — use first IP in the subnet
            try:
                sample_ip = str(next(ipaddress.IPv4Network(old_subnet).hosts()))
            except (StopIteration, ValueError):
                continue

            print(f"[REVAL] {key} (was {old_subnet})...", end=" ", flush=True)
            new_subnet = lookup_subnet(sample_ip)

            if _rate_limited:
                print("rate limited, deferring rest")
                break
            elif new_subnet:
                cache_set(key, new_subnet)
                if new_subnet != old_subnet:
                    print(f"→ {new_subnet} (CHANGED from {old_subnet})")
                else:
                    print(f"→ {new_subnet} (confirmed)")
                revalidated += 1
            else:
                print("FAILED (keeping old entry)")
                # Don't overwrite good data with a failure — just bump the timestamp
                # so we don't retry this one next run
                entry["ts"] = NOW
                reval_failed += 1

            delay = random.uniform(REVALIDATE_DELAY_MIN, REVALIDATE_DELAY_MAX)
            time.sleep(delay)

        save_cache()
        print(f"Revalidation: {revalidated} updated, {reval_failed} failed\n")

# Skip IPs already covered by existing subnets (no need to look them up again)
uncovered = []
covered_count = 0
for ip in individual_ips:
    if is_covered(int(ipaddress.IPv4Address(ip))):
        covered_count += 1
    else:
        uncovered.append(ip)

if covered_count:
    print(f"Skipped {covered_count} IPs (already covered by subnets)")

print(f"Uncovered IPs to process: {len(uncovered)}")

# Group by /16
groups = {}
for ip in uncovered:
    parts = ip.split('.')
    prefix = f"{parts[0]}.{parts[1]}"
    groups.setdefault(prefix, []).append(ip)

print(f"Unique /16 groups: {len(groups)}")
print()

# Process each group
processed = 0
skipped = 0
failed = 0

for prefix, ips in sorted(groups.items(), key=lambda x: -len(x[1])):
    if _rate_limited:
        print("Rate limited — stopping batch processing")
        break

    # Check cache first
    cached_val, expired = cache_get(prefix)
    if prefix in cache and not expired:
        if cached_val is None:
            skipped += 1
            continue

        elif isinstance(cached_val, str) and cached_val.startswith("TOO_BROAD:"):
            process_leftovers(ips, prefix, "group too broad")
            continue

        else:
            subnet = cached_val
            cached_net = ipaddress.IPv4Network(subnet)

            # Split IPs into those covered by cache and those not
            covered_by_cache = [ip for ip in ips if ipaddress.IPv4Address(ip) in cached_net]
            not_covered = [ip for ip in ips if ipaddress.IPv4Address(ip) not in cached_net]

            if covered_by_cache and subnet not in existing_nets:
                print(f"[CACHED] {prefix}.x.x ({len(covered_by_cache)} IPs) → {subnet}")
                ban_subnet(subnet)
                processed += 1
                if not DRY_RUN:
                    time.sleep(0.5)
            elif covered_by_cache:
                skipped += 1

            if not_covered:
                process_leftovers(not_covered, prefix, f"not in cached {subnet}")

            continue

    # Expired or not in cache - fresh lookup using first IP in group
    if expired and prefix in cache:
        print(f"[REVALIDATE] {prefix}.x.x (cached entry expired)...", end=" ", flush=True)
    else:
        print(f"[LOOKUP] {prefix}.x.x ({len(ips)} IPs) looking up {ips[0]}...",
              end=" ", flush=True)

    sample_ip = ips[0]
    subnet = lookup_subnet(sample_ip)
    if subnet:
        net = ipaddress.IPv4Network(subnet)
        if net.prefixlen < 8:
            print(f"too broad (/{net.prefixlen}), skipping")
            cache_set(prefix, f"TOO_BROAD:{subnet}")
            save_cache()
            process_leftovers(ips, prefix, "group too broad")
            continue

        cache_set(prefix, subnet)
        save_cache()

        if subnet in existing_nets:
            print(f"→ {subnet} (already banned)")
            skipped += 1
        else:
            print(f"→ {subnet}")
            ban_subnet(subnet)
            processed += 1
            if not DRY_RUN:
                time.sleep(1)

        # Check for IPs not covered by this subnet
        not_covered = [ip for ip in ips if ipaddress.IPv4Address(ip) not in net]
        if not_covered:
            process_leftovers(not_covered, prefix, f"not in {subnet}")
    else:
        print("FAILED (RDAP + whois)")
        cache_set(prefix, None)
        save_cache()
        failed += 1
        # Try remaining IPs individually
        if len(ips) > 1:
            process_leftovers(ips[1:], prefix, "group lookup failed")
        time.sleep(3)

print(f"\nDone. Processed: {processed}, Skipped (already banned): {skipped}, Failed: {failed}")
print(f"Cache saved to {CACHE_FILE}")
