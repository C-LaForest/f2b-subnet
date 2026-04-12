#!/usr/bin/env python3
"""Batch convert individual fail2ban bans to subnets using cached lookups"""

import ipaddress
import subprocess
import sys
import time
import re
import json
import os
import urllib.request

JAIL = "dovecot"
SUBNET_JAIL = "dovecot-subnet"
CACHE_FILE = os.environ.get("F2B_DIR", "/opt/f2b-subnet") + "/whois_cache.json"
SCRIPT = "/usr/local/bin/f2b_subnet_ban.sh"
DRY_RUN = "--dry-run" in sys.argv

# Load cache
cache = {}
if os.path.exists(CACHE_FILE):
    with open(CACHE_FILE) as f:
        cache = json.load(f)

def save_cache():
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache, f, indent=2)

def rdap_lookup(ip):
    """RDAP lookup - structured JSON over HTTP"""
    import socket
    origgetaddrinfo = socket.getaddrinfo
    def getaddrinfo4(host, port, family=0, type=0, proto=0, flags=0):
        return origgetaddrinfo(host, port, socket.AF_INET, type, proto, flags)
    socket.getaddrinfo = getaddrinfo4

    urls = [
        f"https://rdap.lacnic.net/rdap/ip/{ip}",
        f"https://rdap.arin.net/registry/ip/{ip}",
        f"https://rdap.db.ripe.net/ip/{ip}",
        f"https://rdap.afrinic.net/rdap/ip/{ip}",
        f"https://rdap.apnic.net/ip/{ip}",
    ]
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'Accept': 'application/rdap+json'})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())

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

                return None
        except (urllib.error.HTTPError, urllib.error.URLError,
                json.JSONDecodeError, KeyError, OSError):
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
    """RDAP first, whois fallback"""
    result = rdap_lookup(ip)
    if result:
        return result

    print("[whois fallback]", end=" ", flush=True)
    return whois_lookup(ip)

def is_covered_by_broader(subnet_str):
    """Check if subnet is already covered by a broader existing ban"""
    net = ipaddress.IPv4Network(subnet_str)
    for existing in subnet_nets:
        if net != existing and net.subnet_of(existing):
            return existing
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
    subnet_nets.append(ipaddress.IPv4Network(subnet))

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
        if lp in cache:
            if cache[lp] is None:
                del cache[lp]
                save_cache()
            elif str(cache[lp]).startswith("TOO_BROAD:"):
                continue
            elif cache[lp] in existing_nets:
                discovered[cache[lp]] = ipaddress.IPv4Network(cache[lp])
                continue
            else:
                sub = cache[lp]
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
                cache[lp] = f"TOO_BROAD:{sub}"
                save_cache()
                continue
            cache[lp] = sub
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
            cache[lp] = None
            save_cache()
            failed += 1
            time.sleep(3)

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

# Build set of existing subnet networks for fast lookup
existing_nets = set(existing_subnets)
subnet_nets = [ipaddress.IPv4Network(s) for s in existing_subnets]

# Clean up IPs already covered by existing subnets
uncovered = []
for ip in individual_ips:
    ip_obj = ipaddress.IPv4Address(ip)
    if any(ip_obj in net for net in subnet_nets):
        # Already covered — unban from dovecot jail
        if DRY_RUN:
            print(f"[DRY-RUN] Would clean up {ip} (already covered by subnet)")
        else:
            subprocess.run(['/usr/bin/fail2ban-client', 'set', JAIL, 'unbanip', ip],
                           capture_output=True)
            print(f"Cleaned up {ip} (already covered by subnet)")
    else:
        uncovered.append(ip)

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
    # Check cache first
    if prefix in cache:
        if cache[prefix] is None:
            del cache[prefix]
            save_cache()
            # Fall through to fresh lookup below

        elif str(cache[prefix]).startswith("TOO_BROAD:"):
            process_leftovers(ips, prefix, "group too broad")
            continue

        else:
            subnet = cache[prefix]
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

    # No cache - fresh lookup using first IP in group
    sample_ip = ips[0]
    print(f"[LOOKUP] {prefix}.x.x ({len(ips)} IPs) looking up {sample_ip}...",
          end=" ", flush=True)
    subnet = lookup_subnet(sample_ip)
    if subnet:
        net = ipaddress.IPv4Network(subnet)
        if net.prefixlen < 8:
            print(f"too broad (/{net.prefixlen}), skipping")
            cache[prefix] = f"TOO_BROAD:{subnet}"
            save_cache()
            process_leftovers(ips, prefix, "group too broad")
            continue

        cache[prefix] = subnet
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
        failed += 1
        # Try remaining IPs individually
        if len(ips) > 1:
            process_leftovers(ips[1:], prefix, "group lookup failed")
        time.sleep(3)

print(f"\nDone. Processed: {processed}, Skipped (already banned): {skipped}, Failed: {failed}")
print(f"Cache saved to {CACHE_FILE}")
