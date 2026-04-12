#!/bin/bash
# Escalate individual fail2ban bans to their allocated subnet
# Individual IPs: dovecot jail / addr-set-dovecot
# Subnets: dovecot-subnet jail / addr-set-dovecot-subnet

DRYRUN=0
IP=""
IP_JAIL="dovecot"
SUBNET_JAIL="dovecot-subnet"
MANUAL_SUBNET=""
F2B_DIR="${F2B_DIR:-/opt/f2b-subnet}"
F2B_FROM="${F2B_FROM:-fail2ban@$(hostname -f)}"
BACKUP="${F2B_DIR}/banned_subnets_dovecot.txt"
LOG="/var/log/f2b_subnet_ban.log"

# Parse arguments
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRYRUN=1 ;;
        -*) echo "Unknown option: $arg" >&2; exit 1 ;;
        *)
            if [[ -z "$IP" ]]; then
                IP="$arg"
            fi
            ;;
    esac
done

[[ -z "$IP" ]] && { echo "Usage: $0 [--dry-run] <ip|subnet>" >&2; exit 1; }

# Skip during fail2ban startup (re-processing existing bans)
if [[ "$DRYRUN" -eq 0 ]]; then
    F2B_PID=$(pgrep -f 'fail2ban-server')
    if [[ -n "$F2B_PID" ]]; then
        F2B_AGE=$(ps -o etimes= -p "$F2B_PID" 2>/dev/null | tr -d ' ')
        if [[ -n "$F2B_AGE" && "$F2B_AGE" -lt 120 ]]; then
            echo "$(date): Startup grace period (${F2B_AGE}s), skipping $IP" >> "$LOG"
            exit 0
        fi
    fi
fi

# If a CIDR was passed, use it directly (manual subnet mode)
if [[ "$IP" == */* ]]; then
    MANUAL_SUBNET="$IP"
    IP=""
fi

# Dedup: skip if we already processed this IP/subnet recently
if [[ "$DRYRUN" -eq 0 ]]; then
    DEDUP_DIR="/tmp/f2b_subnet_dedup"
    mkdir -p "$DEDUP_DIR"
    DEDUP_FILE="$DEDUP_DIR/${IP:-$MANUAL_SUBNET}"
    DEDUP_FILE="${DEDUP_FILE//[\.\/]/_}"
    if [[ -f "$DEDUP_FILE" ]]; then
        DEDUP_AGE=$(( $(date +%s) - $(stat -c %Y "$DEDUP_FILE") ))
        if [[ "$DEDUP_AGE" -lt 60 ]]; then
            exit 0
        fi
    fi
    touch "$DEDUP_FILE"
    find "$DEDUP_DIR" -mmin +5 -delete 2>/dev/null
fi

log_msg() {
    if [[ "$DRYRUN" -eq 1 ]]; then
        echo "[DRY-RUN] $1"
    else
        echo "$(date): $1" >> "$LOG"
    fi
}

whois_query() {
    local ip="$1"
    local attempt
    for attempt in 1 2; do
        local result
        result=$(/usr/bin/whois "$ip" 2>/dev/null)
        if echo "$result" | grep -qiE 'inetnum|CIDR|NetRange'; then
            echo "$result"
            return
        fi
        sleep $((attempt * 5))
    done
}

get_subnet() {
    local ip="$1"
    local whois_out
    whois_out=$(whois_query "$ip")

    local cidr
    cidr=$(echo "$whois_out" | grep -iP '^\s*CIDR:\s+' | head -1 | grep -oP '(\d{1,3}\.){3}\d{1,3}/\d{1,2}' | head -1)
    [[ -n "$cidr" ]] && { echo "$cidr"; return; }

    cidr=$(echo "$whois_out" | grep -iP '^\s*inetnum:\s+(\d{1,3}\.){3}\d{1,3}/' | head -1 | grep -oP '(\d{1,3}\.){3}\d{1,3}/\d{1,2}')
    [[ -n "$cidr" ]] && { echo "$cidr"; return; }

    local range start_ip end_ip
    range=$(echo "$whois_out" | grep -iP '^\s*inetnum:\s+(\d{1,3}\.){3}\d{1,3}\s*-\s*(\d{1,3}\.){3}\d{1,3}' | head -1)
    if [[ -n "$range" ]]; then
        start_ip=$(echo "$range" | grep -oP '(\d{1,3}\.){3}\d{1,3}' | head -1)
        end_ip=$(echo "$range" | grep -oP '(\d{1,3}\.){3}\d{1,3}' | tail -1)
        LOOKUP_IP="$ip" LOOKUP_START="$start_ip" LOOKUP_END="$end_ip" python3 -c '
import ipaddress, os
ip = ipaddress.IPv4Address(os.environ["LOOKUP_IP"])
nets = list(ipaddress.summarize_address_range(
    ipaddress.IPv4Address(os.environ["LOOKUP_START"]),
    ipaddress.IPv4Address(os.environ["LOOKUP_END"])
))
for n in nets:
    if ip in n:
        print(n)
        break
' 2>/dev/null
        return
    fi
}

rdap_lookup() {
    local ip="$1"
    LOOKUP_IP="$ip" python3 -c '
import urllib.request, json, ipaddress, os, socket

# Force IPv4
origgetaddrinfo = socket.getaddrinfo
def getaddrinfo4(host, port, family=0, type=0, proto=0, flags=0):
    return origgetaddrinfo(host, port, socket.AF_INET, type, proto, flags)
socket.getaddrinfo = getaddrinfo4

ip = os.environ["LOOKUP_IP"]
urls = [
    "https://rdap.lacnic.net/rdap/ip/" + ip,
    "https://rdap.arin.net/registry/ip/" + ip,
    "https://rdap.db.ripe.net/ip/" + ip,
    "https://rdap.afrinic.net/rdap/ip/" + ip,
    "https://rdap.apnic.net/ip/" + ip,
]
for url in urls:
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/rdap+json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            if "cidr0_cidrs" in data:
                for cidr in data["cidr0_cidrs"]:
                    prefix = cidr["v4prefix"] + "/" + str(cidr["length"])
                    if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(prefix):
                        print(prefix)
                        exit(0)
            if "startAddress" in data and "endAddress" in data:
                start = ipaddress.IPv4Address(data["startAddress"])
                end = ipaddress.IPv4Address(data["endAddress"])
                for net in ipaddress.summarize_address_range(start, end):
                    if ipaddress.IPv4Address(ip) in net:
                        print(net)
                        exit(0)
    except Exception:
        continue
' 2>/dev/null
}

# Determine subnet
if [[ -n "$MANUAL_SUBNET" ]]; then
    SUBNET="$MANUAL_SUBNET"
else
    SUBNET=$(rdap_lookup "$IP")
    if [[ -z "$SUBNET" ]]; then
        log_msg "RDAP failed for $IP, trying whois..."
        SUBNET=$(get_subnet "$IP")
    fi
fi

if [[ -z "$SUBNET" ]]; then
    log_msg "WARN - No subnet found for $IP, keeping individual ban"
    exit 0
fi

# Sanity check: don't ban anything broader than /8
PREFIX=${SUBNET#*/}
if [[ "$PREFIX" -lt 8 ]]; then
    log_msg "WARN - $SUBNET too broad (/$PREFIX) for ${IP:-manual}, skipping"
    exit 0
fi

# Skip /32 - same as individual IP, no point in subnet ban
if [[ "$PREFIX" -eq 32 ]]; then
    log_msg "WARN - $SUBNET is a /32 for ${IP:-manual}, keeping individual ban"
    exit 0
fi

# Skip if already covered by a broader existing subnet ban
BROADER=$(/usr/sbin/nft list set inet f2b-table addr-set-dovecot-subnet 2>/dev/null | \
    grep -oP '(\d{1,3}\.){3}\d{1,3}/\d{1,2}' | \
    LOOKUP_SUBNET="$SUBNET" python3 -c '
import ipaddress, sys, os
new = ipaddress.IPv4Network(os.environ["LOOKUP_SUBNET"])
for line in sys.stdin:
    existing = ipaddress.IPv4Network(line.strip())
    if new != existing and new.subnet_of(existing):
        print(existing)
        break
' 2>/dev/null)
if [[ -n "$BROADER" ]]; then
    log_msg "SKIP - $SUBNET already covered by broader $BROADER (source: ${IP:-manual})"
    exit 0
fi

log_msg "Banning $SUBNET (source: ${IP:-manual})"

# Unban narrower subnets from dovecot-subnet (individual IPs in dovecot are kept)
NARROW_LIST=$(LOOKUP_SUBNET="$SUBNET" python3 -c '
import ipaddress, subprocess, os

subnet = ipaddress.IPv4Network(os.environ["LOOKUP_SUBNET"])
result = subprocess.run(
    ["/usr/bin/fail2ban-client", "get", "dovecot-subnet", "banip"],
    capture_output=True, text=True
)
for token in result.stdout.split():
    entry = token.strip()
    if not entry or "/" not in entry:
        continue
    try:
        existing = ipaddress.IPv4Network(entry)
        if existing.subnet_of(subnet) and existing != subnet:
            print(entry)
    except ValueError:
        pass
' 2>/dev/null)
if [[ -n "$NARROW_LIST" ]]; then
    while IFS= read -r NARROW_ENTRY; do
        if [[ "$DRYRUN" -eq 1 ]]; then
            echo "[DRY-RUN] Would unban $NARROW_ENTRY from $SUBNET_JAIL (covered by $SUBNET)"
        else
            /usr/bin/fail2ban-client set "$SUBNET_JAIL" unbanip "$NARROW_ENTRY" >/dev/null 2>&1
            log_msg "  Unbanned $NARROW_ENTRY from $SUBNET_JAIL (covered by $SUBNET)"
        fi
    done <<< "$NARROW_LIST"
fi

# Now ban the subnet in the SUBNET jail
if [[ "$DRYRUN" -eq 1 ]]; then
    echo "[DRY-RUN] Would ban subnet: $SUBNET in jail: $SUBNET_JAIL"
else
    BANRESULT=$(/usr/bin/fail2ban-client set "$SUBNET_JAIL" banip "$SUBNET" 2>&1)
    log_msg "  Ban result: $BANRESULT"

    # Send notification email
    {
        echo "From: Fail2Ban <${F2B_FROM}>"
        echo "To: root"
        echo "Subject: [Fail2Ban] $SUBNET_JAIL: Subnet ban $SUBNET (source: ${IP:-manual})"
        echo ""
        echo "The subnet $SUBNET has been banned in jail $SUBNET_JAIL."
        if [[ -n "$IP" ]]; then
            echo "Triggered by individual IP: $IP"
        else
            echo "Manually applied subnet ban."
        fi
    } | /usr/sbin/sendmail -f ${F2B_FROM} root
fi

# Sync backup file
if [[ -f "$BACKUP" ]]; then
    if [[ "$DRYRUN" -eq 1 ]]; then
        echo "[DRY-RUN] Would remove these entries from $BACKUP:"
        LOOKUP_SUBNET="$SUBNET" python3 -c '
import ipaddress, os

subnet = ipaddress.IPv4Network(os.environ["LOOKUP_SUBNET"])
with open("'"$BACKUP"'") as f:
    lines = f.read().splitlines()
for line in lines:
    line = line.strip()
    if not line or "/" not in line:
        continue
    try:
        existing = ipaddress.IPv4Network(line)
        if existing.subnet_of(subnet) and existing != subnet:
            print("  - " + line)
    except ValueError:
        pass
subnet_str = os.environ["LOOKUP_SUBNET"]
if subnet_str not in [l.strip() for l in lines]:
    print("Would add: " + subnet_str)
' 2>/dev/null
    else
        LOOKUP_SUBNET="$SUBNET" python3 -c '
import ipaddress, os

subnet = ipaddress.IPv4Network(os.environ["LOOKUP_SUBNET"])
subnet_str = os.environ["LOOKUP_SUBNET"]
with open("'"$BACKUP"'") as f:
    lines = f.read().splitlines()
keep = []
for line in lines:
    line = line.strip()
    if not line or "/" not in line:
        continue
    try:
        existing = ipaddress.IPv4Network(line)
        if existing.subnet_of(subnet) and existing != subnet:
            continue
    except ValueError:
        pass
    keep.append(line)
if subnet_str not in keep:
    keep.append(subnet_str)
with open("'"$BACKUP"'", "w") as f:
    f.write("\n".join(keep) + "\n")
' 2>/dev/null
    fi
fi

log_msg "Done - ${IP:-$SUBNET} → $SUBNET"
