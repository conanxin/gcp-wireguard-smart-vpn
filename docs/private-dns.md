# Private DNS

## Overview

The SMART VPN uses a private DNS resolver on the WireGuard server for domains that are not handled by the China-domain NRPT policy.

The reference architecture is:

```text
Windows
   |
   +-- CN domain
   |      |
   |     NRPT
   |      |
   |   China DNS
   |      |
   |    DIRECT
   |
   +-- Other domain
          |
      10.66.66.1
          |
      WireGuard
          |
       GCP VM
          |
       dnsmasq
          |
   169.254.169.254
          |
      GCP DNS
```

The important design property is that the foreign/default resolver is not exposed publicly.

It is reachable through the WireGuard private network.

---

## Why split DNS is required

IP split routing alone is not enough.

If a China-hosted service is resolved using a foreign DNS resolver, the resolver may return a CDN or edge address that is not part of the China IPv4 routing dataset.

The resulting flow can become:

```text
China website
   |
foreign DNS answer
   |
foreign/non-CN IP
   |
WireGuard
```

even though the desired behavior is:

```text
China website
   |
China DNS answer
   |
CN IP
   |
physical network
```

Therefore the project separates:

```text
domain classification
```

from:

```text
IP classification
```

Windows NRPT handles the first.

The Windows routing table handles the second.

---

## Windows DNS model

The WireGuard interface uses:

```ini
DNS = 10.66.66.1
```

That is the default resolver for domains not matched by the project's CN NRPT rules.

China domains are overridden through Windows NRPT and sent to the configured China resolver.

Reference values:

```text
Private DNS    10.66.66.1
China DNS      223.5.5.5
```

Therefore:

```text
www.baidu.com
    |
NRPT match
    |
223.5.5.5
    |
CN route
    |
WLAN
```

while:

```text
www.google.com
    |
no CN NRPT match
    |
10.66.66.1
    |
WireGuard
    |
GCP
```

---

## Server resolver

The tested server implementation uses `dnsmasq`.

Reference repository files:

```text
server/dns/conan-wg-dns.conf.example
server/dns/conan-wg-dns.service
```

The tested configuration contains the equivalent of:

```text
port=53
interface=wg0
listen-address=10.66.66.1
bind-interfaces

no-resolv
server=169.254.169.254

cache-size=1000
domain-needed
bogus-priv
```

The exact WireGuard interface and private address can be adapted by the installer.

---

## GCP upstream resolver

The tested GCP resolver upstream is:

```text
169.254.169.254
```

This address is available from inside the Google Cloud VM.

WireGuard clients do not query it directly.

Instead:

```text
WireGuard client
    |
10.66.66.1:53
    |
dnsmasq on GCP VM
    |
169.254.169.254
```

This turns the VM into the DNS bridge between the WireGuard private network and the GCP-local resolver.

---

## Exposure boundary

The resolver is intended to serve WireGuard clients.

Expected listener:

```text
10.66.66.1:53
```

for:

```text
UDP
TCP
```

The design does not require:

```text
0.0.0.0:53
[::]:53
PUBLIC_VM_IP:53
```

A wildcard/public DNS listener is treated as a verification failure.

Loopback listeners can exist depending on the host resolver configuration and do not by themselves represent public exposure.

---

## GCP firewall

The project does not require a public GCP firewall rule for DNS/53.

Clients reach:

```text
10.66.66.1
```

inside WireGuard.

The public ingress requirements are for the WireGuard transport, such as:

```text
UDP/51820
UDP/443
```

not public DNS.

Do not solve a WireGuard-private DNS problem by opening:

```text
0.0.0.0/0 -> UDP/53
0.0.0.0/0 -> TCP/53
```

on the VM.

---

## systemd service

The reference service is:

```text
conan-wg-dns.service
```

It depends on the WireGuard interface.

Typical lifecycle:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now conan-wg-dns.service
```

Verify:

```bash
systemctl is-enabled conan-wg-dns.service
systemctl is-active conan-wg-dns.service
```

Expected:

```text
enabled
active
```

---

## dnsmasq syntax validation

Before starting the service:

```bash
sudo dnsmasq \
  --test \
  --conf-file=/etc/conan-wg-dns.conf
```

A valid configuration should report a successful syntax check.

This is also performed by the repository server installer.

---

## Listener verification

Inspect port 53:

```bash
sudo ss -lntupH "sport = :53"
```

Expected private listeners include:

```text
10.66.66.1:53 UDP
10.66.66.1:53 TCP
```

The server verifier checks these explicitly.

It also checks for wildcard/public listeners.

---

## Direct Windows private-DNS test

Before making `10.66.66.1` the normal WireGuard DNS resolver, test it explicitly from Windows.

Example:

```powershell
Resolve-DnsName `
    -Name www.google.com `
    -Type A `
    -Server 10.66.66.1 `
    -DnsOnly
```

Also confirm routing:

```powershell
Find-NetRoute -RemoteIPAddress 10.66.66.1
```

Expected interface:

```text
client1-cndirect
```

TCP/53 can also be checked with:

```powershell
Test-NetConnection 10.66.66.1 -Port 53
```

Expected:

```text
TcpTestSucceeded : True
```

---

## Reference performance observation

Before the private DNS path was used, several foreign-domain lookups through a public resolver on the tested tunnel path took roughly:

```text
12 seconds
```

and behaved like timeout/fallback cases.

After switching to:

```text
10.66.66.1
```

the reference tests resolved foreign domains in approximately:

```text
190-255 ms
```

Examples included:

```text
Google
GitHub
OpenAI
YouTube
```

These values describe the tested environment, not a universal latency guarantee.

---

## China DNS runtime behavior

With the CN NRPT policy active, reference lookups were approximately:

```text
Baidu       low tens of ms
Bilibili    low tens of ms
JD          low tens of ms
Taobao      low tens of ms
QQ          low tens of ms
```

and the resulting CN addresses selected the physical network route.

Example:

```text
www.baidu.com
    |
110.242.x.x
    |
WLAN
```

---

## Foreign DNS runtime behavior

Non-CN domains use the WireGuard private resolver.

Example:

```text
www.google.com
    |
10.66.66.1
    |
GCP DNS
    |
142.251.x.x
    |
client1-cndirect
```

Other tested examples:

```text
github.com
openai.com
www.youtube.com
```

all resolved to addresses subsequently routed through WireGuard.

---

## Relationship with NRPT

The current checked-in namespace dataset is:

```text
data/cn-nrpt-namespaces.txt
```

It is generated by:

```text
windows/update-cn-domains.ps1
```

and applied by:

```text
windows/smart-on.ps1
```

The tested snapshot contains:

```text
12160 namespaces
25 NRPT rules
```

The exact count can change when the upstream domain list changes.

The invariant is:

```text
every generated namespace is present
no unexpected project namespace exists
```

---

## SMART ON

In SMART ON:

```text
CN domain
    -> CN NRPT
    -> China DNS
    -> physical network

Other domain
    -> 10.66.66.1
    -> WireGuard
```

The WireGuard interface remains configured with:

```text
DNS = 10.66.66.1
```

---

## SMART OFF

SMART OFF removes the project CN NRPT rules.

It does not change the WireGuard DNS configuration.

Therefore after SMART OFF:

```text
all normal domains
    ->
10.66.66.1
    ->
WireGuard
```

This is intentional.

SMART OFF means:

```text
disable smart split
```

not:

```text
disable VPN
```

---

## Why `1.1.1.1` is not the default project DNS

The project does not depend on a public resolver such as:

```text
1.1.1.1
```

as the WireGuard interface DNS.

A public DNS server still has to traverse the same network path as other Internet traffic and may be affected by the path being diagnosed.

The private resolver creates a controlled endpoint:

```text
Windows
    ->
WireGuard private IP
    ->
server-local DNS forwarding
```

which is easier to verify independently.

---

## Troubleshooting DNS timeouts

If DNS fails, diagnose in layers.

### 1. Verify WireGuard

```powershell
& 'C:\Program Files\WireGuard\wg.exe' show client1-cndirect
```

Check for:

```text
recent handshake
received bytes
sent bytes
```

### 2. Verify the private DNS route

```powershell
Find-NetRoute -RemoteIPAddress 10.66.66.1
```

Expected:

```text
client1-cndirect
```

### 3. Verify private port 53

```powershell
Test-NetConnection 10.66.66.1 -Port 53
```

### 4. Query explicitly

```powershell
Resolve-DnsName `
    www.google.com `
    -Server 10.66.66.1 `
    -Type A `
    -DnsOnly
```

### 5. Verify server listener

```bash
sudo ss -lntupH "sport = :53"
```

### 6. Verify service

```bash
sudo systemctl status conan-wg-dns.service
```

If server-local DNS works but the client cannot reach:

```text
10.66.66.1:53
```

investigate WireGuard transport before rewriting the DNS configuration.

See:

```text
docs/troubleshooting.md
```

---

## Resolver security boundary

The intended model is:

```text
trusted WireGuard peer
    ->
private resolver
```

not:

```text
arbitrary Internet client
    ->
open recursive resolver
```

The runtime verifier therefore treats wildcard public DNS listeners as failures.

---

## Verification tools

### Server

```bash
sudo ./scripts/verify-server.sh
```

The tested verifier checks:

```text
PRIVATE_DNS_SERVICE
PRIVATE_DNS_UDP53
PRIVATE_DNS_TCP53
NO_PUBLIC_DNS_LISTENER
```

### Windows

```powershell
powershell.exe -ExecutionPolicy Bypass `
    -File .\windows\status.ps1
```

Important fields include:

```text
WG_DNS
WG_DNS_IS_PRIVATE
route to 10.66.66.1
```

---

## Reference healthy state

A healthy tested private-DNS state looked like:

```text
Server:
    conan-wg-dns.service active
    UDP 10.66.66.1:53 listening
    TCP 10.66.66.1:53 listening
    no wildcard public DNS listener

Windows:
    WireGuard DNS = 10.66.66.1
    route to 10.66.66.1 = client1-cndirect
    TCP/53 reachable
    foreign DNS queries succeed
```

This state is independent from the CN-domain NRPT policy.

NRPT changes which resolver a matched China domain uses; it does not replace the default private resolver.