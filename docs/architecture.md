# Architecture

## Overview

GCP WireGuard SMART VPN separates two independent decisions on Windows:

1. **where an IP packet should go**
2. **which DNS resolver should answer a domain**

This avoids relying on an application-layer proxy for normal SMART routing.

The resulting model is:

```text
                          Windows
                             |
               +-------------+-------------+
               |                           |
              CN                          Other
               |                           |
        +------+-------+                   |
        |              |                   |
      Domain          IPv4                  |
        |              |                    |
       NRPT       CN static routes           |
        |              |                    |
    China DNS      physical gateway          |
        |              |                    |
        +---- DIRECT --+                    |
                                            |
                                      WireGuard
                                            |
                                         UDP/443
                                            |
                                       Google Cloud
                                            |
                                          wg0
                                            |
                       +--------------------+--------------------+
                       |                                         |
                   Internet NAT                            Private DNS
                                                                 |
                                                               dnsmasq
                                                                 |
                                                         GCP DNS upstream
```

## Design goals

The tested design targets the following behavior:

```text
China IPv4       -> physical network
China domains    -> China DNS -> physical network

Other IPv4       -> WireGuard
Other domains    -> WireGuard private DNS
```

The SMART layer is implemented with native Windows routing and DNS-policy mechanisms.

No browser extension or local HTTP/SOCKS proxy is required for the split-routing decision itself.

---

## WireGuard transport

The Windows client uses two half-default IPv4 routes:

```text
0.0.0.0/1
128.0.0.0/1
```

Together they cover the IPv4 address space while allowing more-specific routes to override them.

Reference peer configuration:

```ini
[Interface]
Address = 10.66.66.2/32
DNS = 10.66.66.1

[Peer]
AllowedIPs = 0.0.0.0/1, 128.0.0.0/1
Endpoint = YOUR_SERVER_IP:443
PersistentKeepalive = 25
```

The tested server-side WireGuard listener remains on:

```text
UDP/51820
```

UDP/443 is implemented as a compatibility ingress path rather than changing WireGuard's internal listener.

---

## Why half-default routes are used

A conventional full-tunnel configuration often uses:

```text
0.0.0.0/0
```

This project instead uses:

```text
0.0.0.0/1
128.0.0.0/1
```

China routes can then be installed with more-specific prefixes.

For example:

```text
223.0.0.0/12 -> physical gateway
```

wins over:

```text
128.0.0.0/1 -> WireGuard
```

because longest-prefix matching chooses the more-specific route.

This creates the SMART IPv4 split without requiring packet interception by an application proxy.

---

## China IPv4 routing

The dataset:

```text
data/cn-ipv4-cidrs.txt
```

is generated from APNIC delegated IPv4 data.

The verified snapshot contains:

```text
5494 CIDRs
342938880 IPv4 addresses
```

`smart-on.ps1` installs these prefixes through the currently detected physical IPv4 gateway.

Example:

```text
223.5.5.5
  -> CN CIDR
  -> WLAN
  -> physical gateway
```

while:

```text
8.8.8.8
  -> no CN CIDR override
  -> 0.0.0.0/1
  -> WireGuard
```

The routes are installed in the Windows ActiveStore.

`smart-off.ps1` removes only the routes represented by the project's CN dataset.

It does not disable WireGuard.

---

## DNS architecture

IP routing alone is insufficient for geographically appropriate DNS answers.

A public resolver reached through the foreign tunnel may return CDN addresses that are inappropriate for China-direct routing.

The project therefore uses a separate DNS split.

### China domains

The dataset:

```text
data/cn-nrpt-namespaces.txt
```

is installed through Windows Name Resolution Policy Table (NRPT).

Reference China resolver:

```text
223.5.5.5
```

The resolver itself is contained in the CN IPv4 route set, so it travels through the physical gateway.

Flow:

```text
CN domain
   |
Windows NRPT
   |
China DNS
   |
physical route
```

### Other domains

Domains not matched by the CN NRPT rules use the DNS configured on the WireGuard interface:

```text
10.66.66.1
```

Flow:

```text
non-CN domain
     |
Windows default DNS
     |
10.66.66.1
     |
WireGuard
     |
GCP private DNS
```

---

## Private DNS on GCP

The tested reference server runs `dnsmasq`.

It listens on the WireGuard private address:

```text
10.66.66.1:53
```

for both UDP and TCP DNS.

Reference configuration:

```text
server/dns/conan-wg-dns.conf.example
```

The GCP upstream is:

```text
169.254.169.254
```

The intended exposure boundary is:

```text
WireGuard clients -> 10.66.66.1:53
```

not:

```text
Internet -> VM_PUBLIC_IP:53
```

The tested deployment verified that there was no public DNS/53 listener.

---

## UDP/443 compatibility ingress

During real network testing, WireGuard over UDP/51820 repeatedly failed to complete handshakes on the tested access paths.

Packet-level diagnostics established the sequence:

```text
client -> server
148-byte WireGuard handshake initiation

server -> client
92-byte WireGuard handshake response
```

yet the session did not complete over the original transport path.

An A/B test was then performed using UDP/443.

The server kept WireGuard listening on:

```text
51820/udp
```

and added:

```text
443/udp -> REDIRECT -> 51820/udp
```

The UDP/443 test subsequently produced:

```text
fresh handshake
bidirectional WireGuard traffic
private address reachability
private DNS reachability
normal Internet traffic
```

on both phone and Windows test clients.

The reference systemd unit is:

```text
server/udp443/wg-udp443.service
```

A corresponding cloud firewall ingress rule for UDP/443 is also required.

---

## Server packet path

Conceptually:

```text
Internet
   |
GCP external IPv4
   |
VPC firewall
   |
VM ens4
   |
iptables PREROUTING
   |
UDP/443
   |
REDIRECT
   |
UDP/51820
   |
WireGuard wg0
   |
10.66.66.0/24
```

Normal tunnel traffic then follows:

```text
wg0
 |
IP forwarding
 |
ens4
 |
GCP external NAT
 |
Internet
```

---

## SMART ON state

SMART ON means:

```text
CN IPv4:
    physical network

CN DNS:
    NRPT -> China DNS -> physical network

Other IPv4:
    WireGuard

Other DNS:
    10.66.66.1 -> WireGuard
```

The verified reference state contained:

```text
CN routes            5494
NRPT rules              25
NRPT namespaces      12160
WireGuard DNS     10.66.66.1
Half-default routes       2
```

`smart-on.ps1` is idempotent.

If the required state already exists, the tested behavior is:

```text
ROUTES_TO_ADD=0
NRPT_REBUILD=False

CN_ROUTES_ALREADY_COMPLETE
CN_NRPT_ALREADY_EXACT
```

---

## SMART OFF state

SMART OFF does **not** mean WireGuard OFF.

It means:

```text
remove CN direct routes
remove CN NRPT rules
keep WireGuard active
keep Private DNS
keep /1 + /1 routes
```

Therefore the resulting IPv4 state is:

```text
all IPv4 -> WireGuard
```

and normal DNS is:

```text
10.66.66.1 -> WireGuard
```

This definition makes SMART ON and SMART OFF independently testable without repeatedly destroying and rebuilding the base VPN tunnel.

---

## Verified lifecycle

The implementation has been tested through:

```text
ON
 |
 | smart-on.ps1
 v
ON
 |
 | smart-off.ps1
 v
OFF
 |
 | smart-on.ps1
 v
ON
```

The OFF -> ON test began with:

```text
CN routes        0
NRPT rules       0
NRPT namespaces  0
```

and reconstructed:

```text
CN routes        5494
NRPT rules       25
NRPT namespaces  12160
```

The reference rebuild completed in approximately:

```text
11.8 seconds
```

The restored system was independently checked using:

```text
CN IP route decisions
foreign IP route decisions
CN DNS results
foreign DNS results
WireGuard public egress
```

---

## Dataset architecture

Two generated inputs drive SMART mode.

### IPv4 dataset

```text
APNIC
 |
update-cn-ip.ps1
 |
data/cn-ipv4-cidrs.txt
 |
smart-on.ps1
 |
Windows route table
```

The generator validates:

```text
IPv4 parsing
range merging
CIDR alignment
duplicates
address conservation
semantic sanity
```

### Domain dataset

```text
domain-list-community
 |
dlc.dat_plain.yml
 |
update-cn-domains.ps1
 |
domain/full rule minimization
 |
data/cn-nrpt-namespaces.txt
 |
smart-on.ps1
 |
Windows NRPT
```

The generator validates:

```text
release SHA256
declared source-rule count
rule types
domain redundancy
generic-TLD risk
CN semantic sanity
foreign-domain semantic sanity
```

Regexp rules that cannot currently be expressed by the static NRPT model are retained in:

```text
data/cn-nrpt-unsupported-regexp.txt
```

rather than silently discarded.

---

## Proxy coexistence

A local proxy process merely running does not necessarily conflict with SMART WireGuard.

Two actual conflict states identified during testing were:

```text
xray_tun active
WinINET system proxy enabled
```

For example:

```text
v2rayN.exe running
xray.exe running
xray_tun OFF
ProxyEnable = 0
```

can coexist with SMART WireGuard.

By contrast, if WinINET system proxy remains enabled, applications honoring the proxy may leave through a different proxy egress even though Windows IP routing is correct.

This is why:

```text
windows/detect-conflicts.ps1
```

checks routing-layer and application-proxy state separately.

---

## Traffic accounting

WireGuard's counters are cumulative per peer but reset with interface/runtime state.

The server-side collector converts those counters into persistent usage data.

Components:

```text
wg show
   |
wg-traffic-collect.py
   |
SQLite
   |
wg-usage.py
```

Persistent runtime data is intentionally excluded from Git.

See:

```text
docs/traffic-accounting.md
```

for details.

---

## Operational boundaries

The architecture intentionally separates:

```text
Base VPN layer
    WireGuard
    GCP firewall
    forwarding/NAT
    UDP/443 compatibility
    private DNS

SMART layer
    CN IPv4 routes
    NRPT CN namespaces

Observability layer
    status
    conflict detection
    traffic accounting

Data layer
    APNIC generator
    domain-list-community generator
```

This separation allows each layer to be tested without unnecessarily rebuilding the others.

---

## Reference verification

The working reference environment has verified:

```text
WireGuard UDP/443 transport
Private DNS over WireGuard
CN IPv4 direct routing
CN DNS direct resolution
Foreign IPv4 through WireGuard
Foreign DNS through Private DNS
GCP public egress
SMART ON idempotency
SMART OFF
OFF -> ON reconstruction
Dataset reproducibility
```

See `docs/troubleshooting.md` for the packet-level diagnostic path used to reach the final transport design.
