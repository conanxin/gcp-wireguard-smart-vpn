#!/usr/bin/env bash
set -euo pipefail

WG_IF="${WG_IF:-wg0}"
PRIVATE_DNS_IP="${PRIVATE_DNS_IP:-}"
UPLINK_IF="${UPLINK_IF:-}"
WG_PORT="${WG_PORT:-}"

failures=0
warnings=0

ok() {
    printf 'PASS=%s\n' "$1"
}

fail() {
    printf 'FAIL=%s\n' "$1"
    failures=$((failures + 1))
}

warn() {
    printf 'WARNING=%s\n' "$1"
    warnings=$((warnings + 1))
}

section() {
    printf '\n=== %s ===\n' "$1"
}

section "WIREGUARD SERVICE"

if systemctl is-active --quiet "wg-quick@${WG_IF}.service"; then
    printf 'WG_SERVICE=active\n'
    ok "WG_SERVICE"
else
    printf 'WG_SERVICE=inactive\n'
    fail "WG_SERVICE"
fi

section "WIREGUARD INTERFACE"

if ip link show "$WG_IF" >/dev/null 2>&1; then
    printf 'WG_INTERFACE=%s\n' "$WG_IF"
    ok "WG_INTERFACE"
else
    printf 'WG_INTERFACE_MISSING=%s\n' "$WG_IF"
    fail "WG_INTERFACE"
fi

if [[ -z "$PRIVATE_DNS_IP" ]]; then
    PRIVATE_DNS_IP="$(
        ip -4 -o addr show dev "$WG_IF" 2>/dev/null |
        awk 'NR==1 {sub(/\/.*/, "", $4); print $4}'
    )"
fi

if [[ -n "$PRIVATE_DNS_IP" ]]; then
    printf 'WG_IPV4=%s\n' "$PRIVATE_DNS_IP"
    ok "WG_IPV4"
else
    printf 'WG_IPV4=NOT_FOUND\n'
    fail "WG_IPV4"
fi

section "WIREGUARD PORT"

if [[ -z "$WG_PORT" ]]; then
    WG_PORT="$(wg show "$WG_IF" listen-port 2>/dev/null || true)"
fi

if [[ "$WG_PORT" =~ ^[0-9]+$ ]] && [[ "$WG_PORT" -gt 0 ]]; then
    printf 'WG_PORT=%s\n' "$WG_PORT"
    ok "WG_PORT"
else
    printf 'WG_PORT=INVALID\n'
    fail "WG_PORT"
fi

if [[ "$WG_PORT" =~ ^[0-9]+$ ]] &&
   ss -lunH |
   awk '{print $4}' |
   grep -Eq "(^|:)${WG_PORT}$"
then
    printf 'WG_UDP_LISTENER=yes\n'
    ok "WG_UDP_LISTENER"
else
    printf 'WG_UDP_LISTENER=no\n'
    fail "WG_UDP_LISTENER"
fi

section "IP FORWARD"

ip_forward="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || true)"

printf 'IP_FORWARD=%s\n' "${ip_forward:-unknown}"

if [[ "$ip_forward" == "1" ]]; then
    ok "IP_FORWARD"
else
    fail "IP_FORWARD"
fi

section "UPLINK"

if [[ -z "$UPLINK_IF" ]]; then
    UPLINK_IF="$(
        ip -4 route show default |
        awk 'NR==1 {print $5}'
    )"
fi

if [[ -n "$UPLINK_IF" ]]; then
    printf 'UPLINK_IF=%s\n' "$UPLINK_IF"
    ok "UPLINK_INTERFACE"
else
    printf 'UPLINK_IF=NOT_FOUND\n'
    fail "UPLINK_INTERFACE"
fi

section "PRIVATE DNS SERVICE"

if systemctl is-active --quiet conan-wg-dns.service; then
    printf 'PRIVATE_DNS_SERVICE=active\n'
    ok "PRIVATE_DNS_SERVICE"
else
    printf 'PRIVATE_DNS_SERVICE=inactive\n'
    fail "PRIVATE_DNS_SERVICE"
fi

section "PRIVATE DNS LISTENERS"

dns_udp=0
dns_tcp=0

if [[ -n "$PRIVATE_DNS_IP" ]]; then

    if ss -lunH "sport = :53" |
       awk '{print $4}' |
       grep -Fq "${PRIVATE_DNS_IP}:53"
    then
        dns_udp=1
    fi

    if ss -ltnH "sport = :53" |
       awk '{print $4}' |
       grep -Fq "${PRIVATE_DNS_IP}:53"
    then
        dns_tcp=1
    fi
fi

printf 'PRIVATE_DNS_UDP53=%s\n' "$dns_udp"
printf 'PRIVATE_DNS_TCP53=%s\n' "$dns_tcp"

if [[ "$dns_udp" -eq 1 ]]; then
    ok "PRIVATE_DNS_UDP53"
else
    fail "PRIVATE_DNS_UDP53"
fi

if [[ "$dns_tcp" -eq 1 ]]; then
    ok "PRIVATE_DNS_TCP53"
else
    fail "PRIVATE_DNS_TCP53"
fi

section "PUBLIC DNS EXPOSURE"

public_dns=0

while IFS= read -r line; do

    [[ -n "$line" ]] || continue

    local_address="$(
        awk '{print $4}' <<<"$line"
    )"

    case "$local_address" in
        "${PRIVATE_DNS_IP}:53"|"127.0.0.1:53"|"127.0.0.53:53"|"127.0.0.54:53"|"[::1]:53")
            ;;
        "0.0.0.0:53"|"*:53"|"[::]:53")
            public_dns=1
            ;;
    esac

done < <(
    {
        ss -lunH "sport = :53" || true
        ss -ltnH "sport = :53" || true
    }
)

printf 'PUBLIC_DNS_LISTENER=%s\n' "$public_dns"

if [[ "$public_dns" -eq 0 ]]; then
    ok "NO_PUBLIC_DNS_LISTENER"
else
    fail "PUBLIC_DNS_LISTENER"
fi

section "UDP443 COMPATIBILITY SERVICE"

if systemctl is-active --quiet conan-wg-udp443.service; then
    printf 'UDP443_SERVICE=active\n'
    ok "UDP443_SERVICE"
else
    printf 'UDP443_SERVICE=inactive\n'
    fail "UDP443_SERVICE"
fi

section "UDP443 NAT RULE"

rule_count=0

if [[ -n "$UPLINK_IF" ]] &&
   [[ "$WG_PORT" =~ ^[0-9]+$ ]]
then

    if iptables -t nat -C PREROUTING \
        -i "$UPLINK_IF" \
        -p udp \
        --dport 443 \
        -j REDIRECT \
        --to-ports "$WG_PORT" \
        2>/dev/null
    then
        ok "UDP443_REDIRECT_PRESENT"
    else
        fail "UDP443_REDIRECT_PRESENT"
    fi

    rule_count="$(
        iptables -t nat -S PREROUTING |
        grep -E -- "-i ${UPLINK_IF} .*--dport 443 .*REDIRECT .*--to-ports ${WG_PORT}" |
        wc -l
    )"

else
    fail "UDP443_REDIRECT_PARAMETERS"
fi

printf 'UDP443_RULE_COUNT=%s\n' "$rule_count"

if [[ "$rule_count" -eq 1 ]]; then
    ok "UDP443_RULE_COUNT"
else
    fail "UDP443_RULE_COUNT"
fi

section "PRIVATE DNS LOCAL QUERY"

if command -v resolvectl >/dev/null 2>&1; then

    if resolvectl query www.google.com --type=A --legend=no >/dev/null 2>&1; then
        printf 'LOCAL_DNS_QUERY=success\n'
        ok "LOCAL_DNS_QUERY"
    else
        printf 'LOCAL_DNS_QUERY=failed\n'
        warn "LOCAL_DNS_QUERY"
    fi

else
    printf 'LOCAL_DNS_QUERY=skipped_no_resolvectl\n'
    warn "RESOLVECTL_NOT_FOUND"
fi

section "TRAFFIC ACCOUNTING"

if systemctl list-unit-files wg-traffic-collect.timer >/dev/null 2>&1; then

    timer_enabled="$(
        systemctl is-enabled wg-traffic-collect.timer 2>/dev/null || true
    )"

    timer_active="$(
        systemctl is-active wg-traffic-collect.timer 2>/dev/null || true
    )"

    printf 'TRAFFIC_TIMER_ENABLED=%s\n' "$timer_enabled"
    printf 'TRAFFIC_TIMER_ACTIVE=%s\n' "$timer_active"

    if [[ "$timer_enabled" == "enabled" ]] &&
       [[ "$timer_active" == "active" ]]
    then
        ok "TRAFFIC_TIMER"
    else
        warn "TRAFFIC_TIMER_NOT_ENABLED"
    fi

else
    printf 'TRAFFIC_TIMER=not-installed\n'
    warn "TRAFFIC_TIMER_NOT_INSTALLED"
fi

if [[ -x /usr/local/bin/wg-usage ]]; then
    printf 'WG_USAGE_TOOL=present\n'
    ok "WG_USAGE_TOOL"
else
    printf 'WG_USAGE_TOOL=missing\n'
    warn "WG_USAGE_TOOL_MISSING"
fi

section "WIREGUARD RUNTIME"

wg show "$WG_IF" || fail "WG_SHOW"

section "SUMMARY"

printf 'FAILURE_COUNT=%s\n' "$failures"
printf 'WARNING_COUNT=%s\n' "$warnings"

if [[ "$failures" -eq 0 ]]; then
    printf 'SERVER_VERIFY=PASS\n'
    exit 0
else
    printf 'SERVER_VERIFY=FAIL\n'
    exit 2
fi