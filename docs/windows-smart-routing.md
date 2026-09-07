# Windows SMART routing

## Overview

The Windows SMART layer turns a normal WireGuard full-tunnel client into a split-routing system with two independent classification mechanisms:

```text
IP classification
    CN IPv4
        -> physical network
    other IPv4
        -> WireGuard

Domain classification
    CN domain
        -> China DNS
    other domain
        -> WireGuard private DNS
```

The tested reference architecture is:

```text
Windows
    |
    +-- CN IPv4
    |      |
    |   explicit route
    |      |
    |    WLAN
    |
    +-- CN domain
    |      |
    |     NRPT
    |      |
    |   223.5.5.5
    |      |
    |    WLAN
    |
    +-- other IPv4
    |      |
    |   WireGuard
    |
    +-- other domain
           |
       10.66.66.1
           |
       WireGuard
```

The VPN itself remains active while SMART routing selectively sends China traffic around it.

---

## Core design

The Windows client uses WireGuard as the default path.

Instead of installing a traditional single:

```text
0.0.0.0/0
```

route, the tested WireGuard client exposes two half-default routes:

```text
0.0.0.0/1
128.0.0.0/1
```

Together they cover the IPv4 Internet.

SMART then adds more-specific CN IPv4 routes through the physical interface.

Because a more-specific prefix wins over a less-specific prefix, the result is:

```text
CN destination
    -> CN route
    -> physical network

other IPv4 destination
    -> /1 WireGuard route
    -> WireGuard
```

This avoids replacing the WireGuard default-route model.

---

## Reference WireGuard client

The tested client structure is equivalent to:

```ini
[Interface]
Address = 10.66.66.2/32
DNS = 10.66.66.1

[Peer]
PublicKey = SERVER_PUBLIC_KEY
Endpoint = YOUR_SERVER_IP:443
AllowedIPs = 0.0.0.0/1, 128.0.0.0/1
PersistentKeepalive = 25
```

The exact client address, server public key, and endpoint are environment-specific.

Do not commit real client private keys or production client `.conf` files.

---

## Repository files

The Windows implementation is contained in:

```text
windows/status.ps1
windows/detect-conflicts.ps1
windows/smart-on.ps1
windows/smart-off.ps1
windows/update-cn-ip.ps1
windows/update-cn-domains.ps1
```

Generated datasets are stored in:

```text
data/cn-ipv4-cidrs.txt
data/cn-nrpt-namespaces.txt
data/cn-nrpt-unsupported-regexp.txt
```

---

## CN IPv4 routing

The CN IPv4 dataset is generated from APNIC delegated address data.

Generator:

```text
windows/update-cn-ip.ps1
```

Output:

```text
data/cn-ipv4-cidrs.txt
```

A tested snapshot contained:

```text
5494 IPv4 CIDRs
```

representing:

```text
342,938,880 IPv4 addresses
```

The exact number can change when APNIC allocation data changes.

Therefore scripts should validate the generated dataset rather than assume that `5494` is permanent.

---

## CN IPv4 route behavior

When SMART is enabled, every CN IPv4 prefix is installed as an explicit route through the physical network.

Conceptually:

```text
CN prefix
    |
more-specific route
    |
physical interface
```

Examples of expected behavior:

```text
223.5.5.5
    -> physical network

114.114.114.114
    -> physical network
```

while non-CN addresses such as:

```text
8.8.8.8
1.1.1.1
```

continue through WireGuard.

---

## Why explicit routes work

Suppose WireGuard provides:

```text
0.0.0.0/1
128.0.0.0/1
```

and SMART installs:

```text
223.0.0.0/12
```

through WLAN.

For destination:

```text
223.5.5.5
```

Windows chooses:

```text
223.0.0.0/12
```

because `/12` is more specific than `/1`.

The WireGuard route remains installed but loses this route selection.

---

## Route store

The tested implementation installs SMART CN routes into the Windows active routing state.

SMART ON creates the project routes.

SMART OFF removes them.

The physical interface and gateway are detected at runtime rather than being permanently embedded as environment-specific constants in the public repository.

---

## Route batching

Installing thousands of routes one command at a time is unnecessarily slow.

The tested implementation uses batched Windows route operations to handle the full CN dataset efficiently.

This makes a full SMART rebuild practical even with several thousand prefixes.

---

## CN domain classification

IP routing cannot by itself guarantee that a China service resolves to an address inside the CN IPv4 dataset.

Therefore the project also maintains a CN domain policy.

Source generator:

```text
windows/update-cn-domains.ps1
```

Output:

```text
data/cn-nrpt-namespaces.txt
```

The generated namespaces are applied with Windows NRPT.

---

## NRPT

NRPT means:

```text
Name Resolution Policy Table
```

The project uses NRPT to send matched China domains to a China DNS resolver.

Reference resolver:

```text
223.5.5.5
```

Conceptually:

```text
www.baidu.com
    |
CN NRPT match
    |
223.5.5.5
    |
CN IP route
    |
physical network
```

A domain that does not match the CN policy uses the WireGuard interface DNS instead:

```text
10.66.66.1
```

---

## Domain dataset

The domain dataset is generated from the upstream domain-list-community source.

The project extracts supported rule types and produces Windows NRPT namespaces.

A tested snapshot contained:

```text
12160 namespaces
```

distributed across:

```text
25 project NRPT rules
```

The exact counts can change with upstream data.

They are reference snapshot values, not permanent constants.

---

## NRPT rule chunking

Windows NRPT rules can contain many namespaces.

The implementation groups the generated namespace set into manageable chunks instead of creating one Windows rule per domain.

The tested full deployment used:

```text
25 rules
```

for:

```text
12160 namespaces
```

Project rule names use a dedicated prefix so that SMART OFF can remove only project-managed NRPT state.

---

## Unsupported regexp rules

The upstream domain source can contain rules that are not directly representable as Windows NRPT namespaces.

Those are written to:

```text
data/cn-nrpt-unsupported-regexp.txt
```

A tested snapshot contained three such regexp rules.

They are preserved explicitly rather than silently pretending that Windows NRPT supports them.

This makes the transformation auditable.

---

## Domain minimization

The generator removes namespace entries that are already covered by a broader included namespace.

For example, if:

```text
.example.cn
```

already covers:

```text
.sub.example.cn
```

the redundant child does not need to remain as a separate NRPT namespace.

This reduces the final Windows policy size without changing intended coverage.

---

## Dataset semantic checks

The domain generator performs semantic sanity checks.

Representative CN cases should classify as CN, for example:

```text
baidu.com
bilibili.com
jd.com
taobao.com
qq.com
```

Representative foreign cases should remain outside the CN namespace set, for example:

```text
google.com
github.com
openai.com
youtube.com
x.com
```

The goal is not to hard-code these as the whole policy.

They are sanity examples used to detect obviously broken transformations.

---

## Generic TLD risk

A malformed transformation could accidentally create an over-broad namespace such as a generic top-level domain.

That would redirect a huge unrelated domain space to the China resolver.

The generator therefore checks for this class of risk.

The tested dataset had:

```text
generic-TLD risk = 0
```

---

## SMART ON

Enable SMART routing with:

```powershell
powershell.exe -ExecutionPolicy Bypass `
    -File .\windows\smart-on.ps1
```

SMART ON is responsible for converging the machine to the desired state.

Conceptually it performs:

```text
verify WireGuard
verify source datasets
determine physical interface
install missing CN IPv4 routes
construct project NRPT policy
verify resulting route and NRPT state
```

---

## Idempotency

`smart-on.ps1` is designed to be idempotent.

If SMART is already fully enabled:

```text
CN routes already present
NRPT already exact
```

then running SMART ON again should not rebuild everything unnecessarily.

The tested implementation successfully completed an idempotent real run without changing an already-correct state.

---

## Full rebuild

The implementation was also tested from a fully removed SMART state.

Starting from:

```text
project CN routes = 0
project NRPT rules = 0
```

SMART ON rebuilt:

```text
the complete CN route set
the complete CN namespace set
```

and restored correct route selection.

This verifies both:

```text
idempotent convergence
```

and:

```text
cold rebuild
```

paths.

---

## SMART OFF

Disable SMART routing with:

```powershell
powershell.exe -ExecutionPolicy Bypass `
    -File .\windows\smart-off.ps1
```

SMART OFF removes:

```text
project CN IPv4 routes
project CN NRPT rules
```

It intentionally preserves:

```text
WireGuard tunnel
WireGuard DNS
WireGuard /1 + /1 routes
```

Therefore:

```text
SMART OFF
```

means:

```text
disable China split routing
```

not:

```text
disconnect VPN
```

---

## SMART OFF traffic behavior

After SMART OFF:

```text
CN IPv4
    -> WireGuard

foreign IPv4
    -> WireGuard

normal DNS
    -> 10.66.66.1
    -> WireGuard
```

This is expected.

To disable the VPN itself, disable the WireGuard tunnel separately.

---

## Lifecycle verification

The tested lifecycle was:

```text
SMART ON
    |
SMART OFF
    |
SMART ON
```

The implementation successfully:

```text
removed all project CN routes
removed all project NRPT rules
preserved WireGuard
restored all project CN routes
restored all project NRPT namespaces
```

This is an important operational property because SMART state is reversible without rebuilding the WireGuard client.

---

## Status

Use:

```powershell
powershell.exe -ExecutionPolicy Bypass `
    -File .\windows\status.ps1
```

The status tool reports the current SMART and WireGuard state without enabling or disabling SMART.

Useful checks include:

```text
WireGuard interface present
WireGuard DNS
half-default WireGuard routes
CN route count
CN route completeness
NRPT rule count
NRPT namespace count
proxy state
xray TUN state
```

---

## Conflict detection

Use:

```powershell
powershell.exe -ExecutionPolicy Bypass `
    -File .\windows\detect-conflicts.ps1
```

The goal is to distinguish:

```text
process exists
```

from:

```text
process is actually intercepting traffic
```

That distinction proved important during development.

---

## xray and v2rayN

The presence of:

```text
v2rayN.exe
xray.exe
```

does not automatically mean SMART routing is broken.

They may remain running for local proxy functions.

The important conflict condition is whether another TUN layer is taking over system traffic.

For the tested environment:

```text
xray_tun = OFF
```

is required for the native WireGuard SMART routing model.

Therefore:

```text
v2rayN/xray process present
```

can be a warning,

while:

```text
xray TUN active
```

is a routing conflict.

---

## WinINET system proxy

A separate issue is Windows WinINET System Proxy.

Check:

```powershell
Get-ItemProperty `
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' `
    -Name ProxyEnable,ProxyServer
```

The native SMART reference state requires:

```text
ProxyEnable = 0
```

A stored:

```text
ProxyServer
```

value is not by itself a problem when:

```text
ProxyEnable = 0
```

---

## Why proxy state matters

During testing, command-line and browser-visible public IP results initially appeared inconsistent with the route table.

The cause was not WireGuard routing.

WinINET System Proxy was still enabled, so some user-level requests were being forwarded through the proxy.

A direct no-proxy request showed the actual WireGuard GCP egress.

This demonstrates that route verification and application proxy verification are different layers.

---

## Native routing versus proxy routing

The project distinguishes:

```text
native IP routing
```

from:

```text
application proxy
```

A valid native SMART state can still appear wrong if an application is configured to use:

```text
HTTP proxy
SOCKS proxy
WinINET proxy
browser-specific proxy
```

When debugging, verify these separately.

---

## Recommended conflict-free state

For the native WireGuard SMART model:

```text
WireGuard tunnel        ON
WireGuard /1 routes     present
WireGuard DNS           private DNS

SMART CN routes         ON
SMART CN NRPT           ON

xray TUN                OFF
WinINET ProxyEnable     0
```

v2rayN/xray processes may remain running if they are not installing a conflicting TUN or active system proxy path.

---

## Updating the CN IPv4 dataset

Run:

```powershell
powershell.exe -ExecutionPolicy Bypass `
    -File .\windows\update-cn-ip.ps1
```

The generator:

```text
downloads APNIC delegated data
extracts CN IPv4 allocations
merges address ranges
converts ranges to CIDRs
verifies address conservation
performs sanity checks
writes data/cn-ipv4-cidrs.txt
```

Use its DryRun mode first when evaluating an upstream update.

Generating the file does not itself require changing the live Windows route table.

---

## Updating the CN domain dataset

Run:

```powershell
powershell.exe -ExecutionPolicy Bypass `
    -File .\windows\update-cn-domains.ps1
```

The generator:

```text
downloads the upstream domain source
verifies the source artifact
extracts supported domain rules
preserves unsupported regexp rules separately
minimizes redundant namespaces
checks semantic examples
checks over-broad TLD risk
writes the repository datasets
```

Updating the file does not itself require applying the new NRPT state.

---

## DryRun

The update and SMART tooling supports safe validation paths where appropriate.

A DryRun should be used to inspect:

```text
source download
generated counts
sanity checks
planned route changes
planned NRPT changes
```

before applying state changes when diagnosing or updating the project.

---

## Dataset versus live-state verification

A correct dataset file does not prove the live machine matches it.

The project verifies both:

```text
desired dataset
```

and:

```text
installed Windows state
```

For example:

```text
5494 CIDRs in file
```

must correspond to:

```text
5494 expected project CN routes
```

for that exact dataset snapshot.

Likewise:

```text
12160 generated namespaces
```

must correspond to the project NRPT namespace set for that snapshot.

---

## Example route checks

Inspect a CN DNS destination:

```powershell
Find-NetRoute -RemoteIPAddress 223.5.5.5
```

Expected with SMART ON:

```text
physical interface
```

Inspect a foreign destination:

```powershell
Find-NetRoute -RemoteIPAddress 8.8.8.8
```

Expected:

```text
WireGuard interface
```

Another foreign example:

```powershell
Find-NetRoute -RemoteIPAddress 1.1.1.1
```

Expected:

```text
WireGuard interface
```

---

## Example DNS checks

China domain:

```powershell
Resolve-DnsName `
    -Name www.baidu.com `
    -Type A `
    -DnsOnly
```

Foreign domain:

```powershell
Resolve-DnsName `
    -Name www.google.com `
    -Type A `
    -DnsOnly
```

When diagnosing the resolver path explicitly, specify the server:

```powershell
Resolve-DnsName `
    -Name www.google.com `
    -Server 10.66.66.1 `
    -Type A `
    -DnsOnly
```

---

## Public egress verification

When checking the actual WireGuard egress, avoid accidentally testing through an application proxy.

For example, with `curl.exe`:

```powershell
curl.exe --noproxy "*" https://api.ipify.org
```

The resulting public address should correspond to the VPN server egress when the target is routed through WireGuard.

A proxy-derived public IP does not prove the Windows IP route is wrong.

---

## Private DNS dependency

The foreign/default DNS design depends on:

```text
10.66.66.1
```

being reachable through WireGuard.

Therefore a DNS failure can originate from:

```text
WireGuard handshake failure
WireGuard route failure
private DNS service failure
UDP/TCP port 53 failure
resolver upstream failure
```

Do not assume every failed DNS lookup is an NRPT problem.

See:

```text
docs/private-dns.md
docs/troubleshooting.md
```

---

## UDP/443 compatibility dependency

The tested Windows client uses the server compatibility endpoint:

```text
SERVER:443/udp
```

The server then redirects it to the actual WireGuard listener.

This is independent from SMART CN routing.

The layers are:

```text
WireGuard transport
    |
SMART IP/domain split
```

SMART should only be debugged after the WireGuard transport itself works.

---

## Troubleshooting order

Use this order:

```text
1. WireGuard tunnel exists
2. handshake is recent
3. private address is reachable
4. private DNS is reachable
5. /1 + /1 WireGuard routes exist
6. xray TUN is off
7. WinINET system proxy is off
8. CN IPv4 dataset is valid
9. CN routes match dataset
10. CN domain dataset is valid
11. NRPT matches dataset
12. CN test route selects physical interface
13. foreign test route selects WireGuard
14. CN DNS behavior is correct
15. foreign DNS behavior is correct
16. public egress is correct
```

This prevents debugging the SMART layer when the underlying WireGuard transport is actually the failing layer.

---

## Known-good logical state

A healthy SMART ON state is:

```text
WireGuard:
    tunnel active
    recent handshake
    private DNS = 10.66.66.1
    /1 + /1 routes present

CN IPv4:
    generated dataset valid
    project routes complete
    CN test IP -> physical network

CN domains:
    generated namespace dataset valid
    project NRPT complete
    CN domain -> China DNS

Foreign:
    foreign IP -> WireGuard
    foreign domain -> 10.66.66.1

Conflicts:
    xray TUN off
    WinINET ProxyEnable = 0
```

---

## Reference tested snapshot

One fully verified snapshot contained:

```text
CN IPv4 CIDRs:
    5494

CN domain namespaces:
    12160

NRPT project rules:
    25

unsupported regexp rules:
    3
```

These values document a known-good test snapshot.

They are not version-independent requirements.

After an upstream data update, the correct count is whatever the validated generator produces.

---

## Security and privacy

The checked-in Windows scripts and generated public datasets should not contain:

```text
WireGuard private keys
production client configuration
personal filesystem paths
production peer public keys
environment-specific external IP addresses
```

Generated route/domain datasets are public classification data and are suitable for version control.

Runtime client keys and configuration remain local to the systems using them.

---

## Summary

The SMART routing model is based on four independent building blocks:

```text
1. WireGuard default path
2. CN IPv4 route overrides
3. CN domain NRPT overrides
4. private WireGuard DNS for everything else
```

The result is:

```text
China traffic
    -> direct

other traffic
    -> WireGuard
```

without requiring a second Windows TUN implementation or a permanently enabled system proxy.