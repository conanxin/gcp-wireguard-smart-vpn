#!/usr/bin/env bash
set -euo pipefail

WG_IF="wg0"
CLIENT_NAME=""
CLIENT_ADDRESS=""
ENDPOINT=""
PRIVATE_DNS_IP=""
OUTPUT_DIR="${OUTPUT_DIR:-/root/wg-clients}"
CLIENT_ALLOWED_IPS="0.0.0.0/1, 128.0.0.0/1"
KEEPALIVE="25"
APPLY_PEER=1
SHOW_QR=1

usage() {
    cat <<'EOF'
Usage:

  sudo ./scripts/generate-client.sh \
    --name CLIENT_NAME \
    --address CLIENT_IP/32 \
    --endpoint SERVER_HOST_OR_IP:443

Options:

  --name NAME
      Client name used for output filenames and server comments.

  --address CIDR
      Client WireGuard address, for example:
      10.66.66.2/32

  --endpoint HOST:PORT
      Public WireGuard endpoint, for example:
      vpn.example.com:443
      203.0.113.10:443

  --wg-if NAME
      Server WireGuard interface.
      Default: wg0

  --dns IP
      DNS server written to the client configuration.
      Default: IPv4 address of the server WireGuard interface.

  --output-dir PATH
      Directory used for generated client configuration files.
      Default: /root/wg-clients

  --allowed-ips LIST
      Client AllowedIPs.
      Default:
      0.0.0.0/1, 128.0.0.0/1

  --keepalive SECONDS
      PersistentKeepalive.
      Default: 25

  --no-apply
      Generate the client configuration but do not add the peer
      to the running server or /etc/wireguard/WG_IF.conf.

  --no-qr
      Do not display a terminal QR code.

  -h, --help
      Show this help.

Example:

  sudo ./scripts/generate-client.sh \
    --name laptop \
    --address 10.66.66.2/32 \
    --endpoint 203.0.113.10:443
EOF
}

die() {
    printf '[generate-client] ERROR: %s\n' "$*" >&2
    exit 1
}

log() {
    printf '[generate-client] %s\n' "$*"
}

while [[ $# -gt 0 ]]; do

    case "$1" in

        --name)
            [[ $# -ge 2 ]] || die "--name requires a value"
            CLIENT_NAME="$2"
            shift 2
            ;;

        --address)
            [[ $# -ge 2 ]] || die "--address requires a value"
            CLIENT_ADDRESS="$2"
            shift 2
            ;;

        --endpoint)
            [[ $# -ge 2 ]] || die "--endpoint requires a value"
            ENDPOINT="$2"
            shift 2
            ;;

        --wg-if)
            [[ $# -ge 2 ]] || die "--wg-if requires a value"
            WG_IF="$2"
            shift 2
            ;;

        --dns)
            [[ $# -ge 2 ]] || die "--dns requires a value"
            PRIVATE_DNS_IP="$2"
            shift 2
            ;;

        --output-dir)
            [[ $# -ge 2 ]] || die "--output-dir requires a value"
            OUTPUT_DIR="$2"
            shift 2
            ;;

        --allowed-ips)
            [[ $# -ge 2 ]] || die "--allowed-ips requires a value"
            CLIENT_ALLOWED_IPS="$2"
            shift 2
            ;;

        --keepalive)
            [[ $# -ge 2 ]] || die "--keepalive requires a value"
            KEEPALIVE="$2"
            shift 2
            ;;

        --no-apply)
            APPLY_PEER=0
            shift
            ;;

        --no-qr)
            SHOW_QR=0
            shift
            ;;

        -h|--help)
            usage
            exit 0
            ;;

        *)
            die "Unknown argument: $1"
            ;;
    esac
done

if [[ "$EUID" -ne 0 ]]; then
    die "Run as root (sudo)."
fi

[[ -n "$CLIENT_NAME" ]] ||
    die "--name is required"

[[ -n "$CLIENT_ADDRESS" ]] ||
    die "--address is required"

[[ -n "$ENDPOINT" ]] ||
    die "--endpoint is required"

[[ "$CLIENT_NAME" =~ ^[A-Za-z0-9._-]+$ ]] ||
    die "Client name may contain only letters, numbers, dot, underscore and hyphen."

[[ "$KEEPALIVE" =~ ^[0-9]+$ ]] ||
    die "PersistentKeepalive must be an integer."

[[ "$ENDPOINT" == *:* ]] ||
    die "Endpoint must contain a port, for example SERVER:443."

for command_name in \
    wg \
    ip \
    python3 \
    sha256sum
do
    command -v "$command_name" >/dev/null 2>&1 ||
        die "Required command not found: $command_name"
done

WG_CONF="/etc/wireguard/${WG_IF}.conf"

[[ -f "$WG_CONF" ]] ||
    die "WireGuard configuration not found: $WG_CONF"

ip link show "$WG_IF" >/dev/null 2>&1 ||
    die "WireGuard interface is not active: $WG_IF"

python3 - "$CLIENT_ADDRESS" <<'PY'
import ipaddress
import sys

value = sys.argv[1]

try:
    interface = ipaddress.ip_interface(value)
except ValueError as exc:
    raise SystemExit(f"Invalid client address: {value}: {exc}")

if interface.version != 4:
    raise SystemExit("Only IPv4 client addresses are currently supported.")

if interface.network.prefixlen != 32:
    raise SystemExit("Client address must use /32.")
PY

CLIENT_IP="$(
    python3 - "$CLIENT_ADDRESS" <<'PY'
import ipaddress
import sys

print(ipaddress.ip_interface(sys.argv[1]).ip)
PY
)"

if [[ -z "$PRIVATE_DNS_IP" ]]; then

    PRIVATE_DNS_IP="$(
        ip -4 -o addr show dev "$WG_IF" |
        awk 'NR==1 {sub(/\/.*/, "", $4); print $4}'
    )"
fi

[[ -n "$PRIVATE_DNS_IP" ]] ||
    die "Could not determine the server WireGuard IPv4 address."

python3 - "$PRIVATE_DNS_IP" <<'PY'
import ipaddress
import sys

try:
    address = ipaddress.ip_address(sys.argv[1])
except ValueError as exc:
    raise SystemExit(f"Invalid DNS address: {exc}")

if address.version != 4:
    raise SystemExit("Only IPv4 private DNS is currently supported.")
PY

SERVER_PUBLIC_KEY="$(
    wg show "$WG_IF" public-key
)"

[[ "$SERVER_PUBLIC_KEY" =~ ^[A-Za-z0-9+/]{43}=$ ]] ||
    die "Could not read a valid server WireGuard public key."

#
# Prevent duplicate tunnel addresses.
#

if wg show "$WG_IF" allowed-ips |
   awk '{print $2}' |
   tr ',' '\n' |
   grep -Fxq "$CLIENT_ADDRESS"
then
    die "Client address is already assigned by the running interface: $CLIENT_ADDRESS"
fi

if grep -Eq \
    "^[[:space:]]*AllowedIPs[[:space:]]*=[[:space:]]*${CLIENT_IP}/32([[:space:]]*)$" \
    "$WG_CONF"
then
    die "Client address is already present in $WG_CONF: $CLIENT_ADDRESS"
fi

umask 077

install -d -m 0700 "$OUTPUT_DIR"

CLIENT_CONF="${OUTPUT_DIR}/client-${CLIENT_NAME}.conf"

if [[ -e "$CLIENT_CONF" ]]; then
    die "Output file already exists: $CLIENT_CONF"
fi

CLIENT_PRIVATE_KEY="$(
    wg genkey
)"

CLIENT_PUBLIC_KEY="$(
    printf '%s\n' "$CLIENT_PRIVATE_KEY" |
    wg pubkey
)"

[[ "$CLIENT_PUBLIC_KEY" =~ ^[A-Za-z0-9+/]{43}=$ ]] ||
    die "Generated client public key is invalid."

log "Generating client configuration..."

cat > "$CLIENT_CONF" <<EOF
[Interface]
PrivateKey = ${CLIENT_PRIVATE_KEY}
Address = ${CLIENT_ADDRESS}
DNS = ${PRIVATE_DNS_IP}

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${CLIENT_ALLOWED_IPS}
PersistentKeepalive = ${KEEPALIVE}
EOF

chmod 0600 "$CLIENT_CONF"

if [[ "$APPLY_PEER" -eq 1 ]]; then

    log "Persisting peer in ${WG_CONF}..."

    cat >> "$WG_CONF" <<EOF

# client:${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUBLIC_KEY}
AllowedIPs = ${CLIENT_ADDRESS}
EOF

    log "Adding peer to running interface ${WG_IF}..."

    wg set "$WG_IF" \
        peer "$CLIENT_PUBLIC_KEY" \
        allowed-ips "$CLIENT_ADDRESS"

    runtime_peer="$(
        wg show "$WG_IF" allowed-ips |
        awk -v key="$CLIENT_PUBLIC_KEY" '
            $1 == key {print $2}
        '
    )"

    if [[ "$runtime_peer" != "$CLIENT_ADDRESS" ]]; then
        die "Runtime peer verification failed."
    fi

    log "Peer added to server."
else
    log "Peer application skipped (--no-apply)."
fi

printf '\n=== CLIENT ===\n'
printf 'CLIENT_NAME=%s\n' "$CLIENT_NAME"
printf 'CLIENT_ADDRESS=%s\n' "$CLIENT_ADDRESS"
printf 'CLIENT_PUBLIC_KEY=%s\n' "$CLIENT_PUBLIC_KEY"
printf 'SERVER_PUBLIC_KEY=%s\n' "$SERVER_PUBLIC_KEY"
printf 'PRIVATE_DNS=%s\n' "$PRIVATE_DNS_IP"
printf 'ENDPOINT=%s\n' "$ENDPOINT"
printf 'CLIENT_CONFIG=%s\n' "$CLIENT_CONF"
printf 'CLIENT_CONFIG_SHA256=%s\n' "$(
    sha256sum "$CLIENT_CONF" |
    awk '{print toupper($1)}'
)"
printf 'PEER_APPLIED=%s\n' "$APPLY_PEER"

if [[ "$SHOW_QR" -eq 1 ]]; then

    printf '\n=== QR CODE ===\n'

    if command -v qrencode >/dev/null 2>&1; then
        qrencode -t ANSIUTF8 < "$CLIENT_CONF"
    else
        printf 'qrencode is not installed; QR display skipped.\n'
        printf 'Install with: apt-get install qrencode\n'
    fi
fi

printf '\nCLIENT_GENERATE=PASS\n'