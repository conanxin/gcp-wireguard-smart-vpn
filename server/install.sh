#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

WG_IF="wg0"
PRIVATE_DNS_IP="${PRIVATE_DNS_IP:-}"
UPLINK_IF="${UPLINK_IF:-}"
WG_PORT="${WG_PORT:-}"
ENABLE_TRAFFIC="${ENABLE_TRAFFIC:-0}"

log() {
    printf '[gcp-wg-smart] %s\n' "$*"
}

die() {
    printf '[gcp-wg-smart] ERROR: %s\n' "$*" >&2
    exit 1
}

require_file() {
    [[ -f "$1" ]] || die "Required repository file not found: $1"
}

if [[ "${EUID}" -ne 0 ]]; then
    die "Run this installer as root (sudo)."
fi

command -v apt-get >/dev/null 2>&1 ||
    die "This installer currently supports Debian/Ubuntu systems with apt-get."

log "Repository root: ${REPO_ROOT}"

#
# Repository artifacts
#

DNS_CONF_SRC="${REPO_ROOT}/server/dns/conan-wg-dns.conf.example"
DNS_SERVICE_SRC="${REPO_ROOT}/server/dns/conan-wg-dns.service"

UDP443_SERVICE_SRC="${REPO_ROOT}/server/udp443/wg-udp443.service"

TRAFFIC_COLLECT_SRC="${REPO_ROOT}/server/traffic/wg-traffic-collect.py"
WG_USAGE_SRC="${REPO_ROOT}/server/traffic/wg-usage.py"
TRAFFIC_SERVICE_SRC="${REPO_ROOT}/server/traffic/wg-traffic-collect.service"
TRAFFIC_TIMER_SRC="${REPO_ROOT}/server/traffic/wg-traffic-collect.timer"

for artifact in \
    "$DNS_CONF_SRC" \
    "$DNS_SERVICE_SRC" \
    "$UDP443_SERVICE_SRC" \
    "$TRAFFIC_COLLECT_SRC" \
    "$WG_USAGE_SRC" \
    "$TRAFFIC_SERVICE_SRC" \
    "$TRAFFIC_TIMER_SRC"
do
    require_file "$artifact"
done

#
# Packages
#

log "Installing server packages..."

apt-get update

DEBIAN_FRONTEND=noninteractive apt-get install -y \
    wireguard-tools \
    dnsmasq-base \
    iptables \
    python3

#
# WireGuard prerequisite
#

WG_CONF="/etc/wireguard/${WG_IF}.conf"

if [[ ! -f "$WG_CONF" ]]; then
    cat >&2 <<EOF
[gcp-wg-smart] WireGuard configuration is not present:

    ${WG_CONF}

Create the server WireGuard configuration first, then rerun this installer.

Private keys are intentionally not generated or stored by this repository installer.
EOF
    exit 1
fi

log "Enabling WireGuard interface ${WG_IF}..."

systemctl enable --now "wg-quick@${WG_IF}.service"

systemctl is-active --quiet "wg-quick@${WG_IF}.service" ||
    die "WireGuard service failed to become active."

#
# Detect runtime parameters
#

if [[ -z "$PRIVATE_DNS_IP" ]]; then
    PRIVATE_DNS_IP="$(
        ip -4 -o addr show dev "$WG_IF" |
        awk 'NR==1 {sub(/\/.*/, "", $4); print $4}'
    )"
fi

[[ -n "$PRIVATE_DNS_IP" ]] ||
    die "Could not determine the WireGuard IPv4 address."

if [[ -z "$UPLINK_IF" ]]; then
    UPLINK_IF="$(
        ip -4 route show default |
        awk 'NR==1 {print $5}'
    )"
fi

[[ -n "$UPLINK_IF" ]] ||
    die "Could not determine the external/uplink interface."

if [[ -z "$WG_PORT" ]]; then
    WG_PORT="$(wg show "$WG_IF" listen-port)"
fi

[[ "$WG_PORT" =~ ^[0-9]+$ ]] ||
    die "Could not determine the WireGuard UDP listening port."

log "WireGuard interface : ${WG_IF}"
log "Private DNS IP      : ${PRIVATE_DNS_IP}"
log "Uplink interface    : ${UPLINK_IF}"
log "WireGuard port      : ${WG_PORT}"

#
# Private DNS
#

log "Installing WireGuard private DNS..."

install -m 0644 \
    "$DNS_CONF_SRC" \
    /etc/conan-wg-dns.conf

install -m 0644 \
    "$DNS_SERVICE_SRC" \
    /etc/systemd/system/conan-wg-dns.service

sed -i \
    -e "s/^interface=.*/interface=${WG_IF}/" \
    -e "s/^listen-address=.*/listen-address=${PRIVATE_DNS_IP}/" \
    /etc/conan-wg-dns.conf

sed -i \
    "s/wg-quick@wg0\.service/wg-quick@${WG_IF}.service/g" \
    /etc/systemd/system/conan-wg-dns.service

/usr/sbin/dnsmasq \
    --test \
    --conf-file=/etc/conan-wg-dns.conf

#
# UDP/443 compatibility alias
#

log "Installing UDP/443 compatibility service..."

install -m 0644 \
    "$UDP443_SERVICE_SRC" \
    /etc/systemd/system/conan-wg-udp443.service

sed -i \
    -e "s/wg-quick@wg0\.service/wg-quick@${WG_IF}.service/g" \
    -e "s/-i ens4 /-i ${UPLINK_IF} /g" \
    -e "s/51820/${WG_PORT}/g" \
    /etc/systemd/system/conan-wg-udp443.service

#
# Persistent traffic accounting tools
#

log "Installing traffic accounting tools..."

install -d -m 0755 /usr/local/libexec
install -d -m 0755 /var/lib/wg-traffic

install -m 0755 \
    "$TRAFFIC_COLLECT_SRC" \
    /usr/local/libexec/wg-traffic-collect

install -m 0755 \
    "$WG_USAGE_SRC" \
    /usr/local/bin/wg-usage

install -m 0644 \
    "$TRAFFIC_SERVICE_SRC" \
    /etc/systemd/system/wg-traffic-collect.service

install -m 0644 \
    "$TRAFFIC_TIMER_SRC" \
    /etc/systemd/system/wg-traffic-collect.timer

#
# Static syntax checks
#

log "Checking installed Python tools..."

python3 -c '
import ast
from pathlib import Path

for path in (
    Path("/usr/local/libexec/wg-traffic-collect"),
    Path("/usr/local/bin/wg-usage"),
):
    ast.parse(path.read_text(encoding="utf-8"))
    print("PYTHON_SYNTAX_OK=" + str(path))
'

log "Reloading systemd..."

systemctl daemon-reload

systemd-analyze verify \
    /etc/systemd/system/conan-wg-dns.service \
    /etc/systemd/system/conan-wg-udp443.service \
    /etc/systemd/system/wg-traffic-collect.service \
    /etc/systemd/system/wg-traffic-collect.timer

#
# Enable tested runtime services
#

log "Enabling private DNS..."

systemctl enable --now conan-wg-dns.service

log "Enabling UDP/443 compatibility alias..."

systemctl enable --now conan-wg-udp443.service

#
# Traffic accounting is optional because peer naming/configuration may
# need to be reviewed for a new server first.
#

if [[ "$ENABLE_TRAFFIC" == "1" ]]; then
    log "Enabling WireGuard traffic accounting timer..."

    systemctl enable --now wg-traffic-collect.timer
else
    log "Traffic accounting installed but not enabled."
    log "Enable later with:"
    log "  sudo systemctl enable --now wg-traffic-collect.timer"
fi

#
# Runtime verification
#

log "Verifying WireGuard..."

systemctl is-active --quiet "wg-quick@${WG_IF}.service" ||
    die "WireGuard is not active."

log "Verifying private DNS service..."

systemctl is-active --quiet conan-wg-dns.service ||
    die "Private DNS service is not active."

ss -lntupH "sport = :53" |
grep -F "${PRIVATE_DNS_IP}:53" >/dev/null ||
    die "Private DNS is not listening on ${PRIVATE_DNS_IP}:53."

log "Verifying UDP/443 compatibility rule..."

systemctl is-active --quiet conan-wg-udp443.service ||
    die "UDP/443 compatibility service is not active."

iptables -t nat -C PREROUTING \
    -i "$UPLINK_IF" \
    -p udp \
    --dport 443 \
    -j REDIRECT \
    --to-ports "$WG_PORT" ||
    die "UDP/443 REDIRECT rule was not found."

RULE_COUNT="$(
    iptables -t nat -S PREROUTING |
    grep -c -- "--dport 443.*REDIRECT.*${WG_PORT}" ||
    true
)"

[[ "$RULE_COUNT" -eq 1 ]] ||
    die "Expected exactly one UDP/443 REDIRECT rule; found ${RULE_COUNT}."

log "Server installation complete."

cat <<EOF

WireGuard SMART server components are ready.

WireGuard:
    interface    ${WG_IF}
    private IP   ${PRIVATE_DNS_IP}
    listen port  ${WG_PORT}

Private DNS:
    ${PRIVATE_DNS_IP}:53

Compatibility ingress:
    UDP/443 -> UDP/${WG_PORT}

Important:
    The Google Cloud firewall must allow UDP/443
    to this VM for compatibility mode to work.

Traffic accounting:
    installed
    enabled = ${ENABLE_TRAFFIC}

SERVER_INSTALL=PASS
EOF