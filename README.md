# GCP WireGuard SMART VPN

A WireGuard-based split-routing VPN for Windows with:

- direct routing for China IPv4 networks
- split DNS for China domains
- private DNS for non-China domains
- WireGuard over UDP/443 compatibility mode
- GCP-hosted WireGuard server
- persistent per-peer traffic accounting
- repeatable SMART ON / OFF lifecycle
- reproducible APNIC and domain-list-community datasets

The project grew from a working GCP deployment and was then converted into reproducible scripts and checked against the live system.

## Architecture

```text
                           Windows
                              |
                +-------------+-------------+
                |                           |
             CN traffic                 Other traffic
                |                           |
        +-------+-------+                   |
        |               |                   |
     CN domain       CN IPv4                |
        |               |                   |
       NRPT       static CN routes           |
        |               |                   |
   China DNS          WLAN                   |
        |               |                   |
        +------ DIRECT --+                   |
                                            |
                                      WireGuard
                                            |
                                     UDP / 443
                                            |
                                    Google Cloud
                                            |
                                      conan-vpn
                                            |
                         +------------------+------------------+
                         |                                     |
                    Internet NAT                        Private DNS
                                                               |
                                                            dnsmasq
                                                               |
                                                     GCP metadata DNS
```

The WireGuard server itself listens on UDP/51820.

For networks where UDP/51820 is unreliable, the tested GCP deployment accepts UDP/443 and redirects it internally to the WireGuard listener.

## Windows routing model

SMART mode uses two independent classification layers.

### IPv4 routing

China IPv4 CIDRs are installed as more-specific routes through the physical gateway.

Everything else matches the WireGuard half-default routes:

```text
0.0.0.0/1
128.0.0.0/1
```

Result:

```text
CN IPv4     -> WLAN / physical gateway
Other IPv4  -> WireGuard
```

### DNS routing

China domains are installed in Windows NRPT and resolved with the configured China DNS resolver.

Other domains use the DNS server configured on the WireGuard interface.

Reference configuration:

```text
China DNS       223.5.5.5
Private DNS     10.66.66.1
Windows peer    10.66.66.2
Phone peer      10.66.66.3
```

Result:

```text
CN domain       -> NRPT -> China DNS -> DIRECT
Other domain    -> Private DNS -> WireGuard -> GCP
```

## Tested Windows lifecycle

The Windows SMART layer has been tested through the complete lifecycle:

```text
SMART ON
   |
   | smart-on.ps1 again
   v
SMART ON            idempotency verified
   |
   | smart-off.ps1
   v
SMART OFF           all IPv4 remains on WireGuard
   |
   | smart-on.ps1
   v
SMART ON            routes and NRPT rebuilt from zero
```

Verified rebuild state:

```text
CN IPv4 routes        5494 / 5494
NRPT rules             25
NRPT namespaces        12160
Private DNS            10.66.66.1
WireGuard half routes  2
```

A full OFF -> ON rebuild of the SMART layer completed in approximately 12 seconds on the tested Windows system.

## Repository layout

```text
gcp-wireguard-smart-vpn/
├── README.md
├── LICENSE
├── .gitignore
│
├── data/
│   ├── README.md
│   ├── cn-ipv4-cidrs.txt
│   ├── cn-nrpt-namespaces.txt
│   └── cn-nrpt-unsupported-regexp.txt
│
├── windows/
│   ├── status.ps1
│   ├── detect-conflicts.ps1
│   ├── smart-on.ps1
│   ├── smart-off.ps1
│   ├── update-cn-ip.ps1
│   └── update-cn-domains.ps1
│
├── server/
│   ├── install.sh
│   ├── dns/
│   │   ├── conan-wg-dns.conf.example
│   │   └── conan-wg-dns.service
│   ├── udp443/
│   │   └── wg-udp443.service
│   └── traffic/
│       ├── wg-traffic-collect.py
│       ├── wg-usage.py
│       ├── wg-traffic-collect.service
│       └── wg-traffic-collect.timer
│
├── scripts/
│   ├── generate-client.sh
│   └── verify-server.sh
│
└── docs/
    ├── architecture.md
    ├── google-cloud.md
    ├── windows-smart-routing.md
    ├── private-dns.md
    ├── traffic-accounting.md
    └── troubleshooting.md
```

## Windows requirements

The tested client environment uses:

- Windows 11
- official WireGuard for Windows
- administrator PowerShell
- IPv4 WireGuard tunnel
- a physical IPv4 default gateway
- Windows NRPT support

The default example tunnel name used by the scripts is:

```text
client1-cndirect
```

Important tunnel settings in the tested configuration:

```ini
[Interface]
Address = 10.66.66.2/32
DNS = 10.66.66.1

[Peer]
AllowedIPs = 0.0.0.0/1, 128.0.0.0/1
Endpoint = YOUR_SERVER_IP:443
PersistentKeepalive = 25
```

Keys are intentionally not included in this repository.

## Status

Run from an administrator PowerShell:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\windows\status.ps1
```

To verify the public WireGuard egress IP as well:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\windows\status.ps1 `
    -ExpectedPublicIp YOUR_SERVER_IP
```

The status script checks:

- WireGuard interface presence
- WireGuard DNS
- half-default routes
- physical gateway
- CN route completeness
- NRPT state
- system proxy state
- routing decisions
- optional public egress

## Conflict detection

Run:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\windows\detect-conflicts.ps1 `
    -ExpectedPublicIp YOUR_SERVER_IP
```

The detector distinguishes between a process merely existing and an actual network conflict.

For example:

```text
v2rayN / xray process running        warning only

xray_tun active                      conflict
WinINET system proxy enabled         conflict
WireGuard missing                    conflict
Private DNS routed incorrectly       conflict
Foreign traffic not using WG         conflict
Wrong public egress                  conflict
```

This distinction came directly from testing coexistence with v2rayN.

## Enable SMART routing

First preview the operation:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\windows\smart-on.ps1 -DryRun
```

Enable:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\windows\smart-on.ps1
```

When the machine is already correctly configured, the script is idempotent:

```text
ROUTES_TO_ADD=0
NRPT_REBUILD=False

CN_ROUTES_ALREADY_COMPLETE
CN_NRPT_ALREADY_EXACT
```

## Disable SMART split routing

Preview:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\windows\smart-off.ps1 -DryRun
```

Disable only the SMART split layer:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\windows\smart-off.ps1
```

SMART OFF does not disable WireGuard.

Instead it removes:

```text
CN direct routes
CN NRPT rules
```

while preserving:

```text
WireGuard tunnel
WireGuard private DNS
0.0.0.0/1
128.0.0.0/1
```

The resulting state is a normal full IPv4 WireGuard tunnel.

## Updating China IPv4 data

Source:

```text
APNIC delegated statistics
```

Dry run:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\windows\update-cn-ip.ps1 -DryRun
```

Update:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\windows\update-cn-ip.ps1
```

The generator checks:

- APNIC row structure
- merged address ranges
- CIDR alignment
- duplicate CIDRs
- address conservation
- CN sanity address
- foreign sanity address

The current checked-in snapshot contains:

```text
5494 CIDRs
342938880 IPv4 addresses
```

See `data/README.md` for verification details.

## Updating China domain data

Source:

```text
v2fly/domain-list-community
dlc.dat_plain.yml
```

Dry run:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\windows\update-cn-domains.ps1 -DryRun
```

Update:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\windows\update-cn-domains.ps1
```

The generator:

1. downloads the current release
2. verifies the published SHA256
3. extracts the `cn` section
4. separates domain, full, regexp, keyword and unknown rule types
5. minimizes redundant domain rules
6. removes full rules already covered by parent domains
7. creates Windows NRPT namespaces
8. checks generic-TLD risk
9. runs direct/VPN semantic sanity tests
10. stores unsupported regexp rules separately for audit

Current verified snapshot:

```text
CN source rules          6555
Final NRPT namespaces   12160
Unsupported regexps         3
```

## Private DNS

The GCP server exposes a DNS resolver only on the WireGuard private address:

```text
10.66.66.1:53
```

The tested implementation uses `dnsmasq`.

Its upstream on GCP is:

```text
169.254.169.254
```

The resolver is not intended to listen publicly on the VM external address.

Reference files:

```text
server/dns/conan-wg-dns.conf.example
server/dns/conan-wg-dns.service
```

## UDP/443 compatibility mode

The tested environment showed a clear difference between:

```text
UDP/51820   handshake failure on the tested access paths
UDP/443     working WireGuard transport
```

The server continues to run WireGuard on UDP/51820.

A systemd-managed iptables rule redirects:

```text
UDP/443 -> UDP/51820
```

Reference unit:

```text
server/udp443/wg-udp443.service
```

A corresponding GCP ingress firewall rule for UDP/443 is required.

## Traffic accounting

The server includes persistent per-peer traffic accounting.

Files:

```text
server/traffic/wg-traffic-collect.py
server/traffic/wg-usage.py
server/traffic/wg-traffic-collect.service
server/traffic/wg-traffic-collect.timer
```

The collector stores persistent counters in SQLite.

Example:

```bash
sudo /usr/local/bin/wg-usage
```

The tested implementation reports:

```text
per-client usage
today
current month
all-time totals
online status
latest handshake
upload/download totals
```

Runtime databases are not stored in Git.

## Data and generated files

The repository includes verified snapshots:

```text
data/cn-ipv4-cidrs.txt
data/cn-nrpt-namespaces.txt
data/cn-nrpt-unsupported-regexp.txt
```

The corresponding updater scripts can reproduce them from upstream sources.

See:

```text
data/README.md
```

for provenance and validation details.

## Notes on proxies

A running proxy process is not automatically a conflict.

For example, v2rayN may remain open while SMART WireGuard is active.

The important states are:

```text
xray_tun              OFF
WinINET ProxyEnable   0
```

If a Windows system proxy remains enabled, browser/application traffic may use that proxy even when the IP routing table correctly points to WireGuard.

Use:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\windows\detect-conflicts.ps1
```

to detect this condition.

## Current project status

The following components have been exercised against the working reference environment:

```text
WireGuard server                         verified
UDP/443 compatibility path              verified
Windows private DNS                     verified
CN IPv4 split routing                   verified
CN domain split DNS                     verified
status.ps1                              runtime verified
detect-conflicts.ps1                    runtime verified
smart-on.ps1                            dry-run verified
smart-on.ps1                            idempotency verified
smart-off.ps1                           dry-run verified
smart-off.ps1                           runtime verified
SMART ON -> OFF -> ON lifecycle         verified
update-cn-ip.ps1                        generation verified
update-cn-domains.ps1                   generation verified
traffic collector                       runtime artifact imported
wg-usage                                runtime artifact imported
```

The remaining repository work is primarily packaging, documentation, and clean-server installation automation.

## Private material

Do not commit real WireGuard client or server private keys.

The repository `.gitignore` excludes common runtime material including:

```text
*.key
wg0.conf
client*.conf
*.db
*.db-wal
*.db-shm
```

Use example configuration files for documentation and generate real client keys locally.

## License

See `LICENSE`.

<!-- release-reference:start -->

## Repository guide

The repository is organized around the tested WireGuard transport, Windows SMART routing layer, generated China routing/domain datasets, private DNS, and server-side operational tooling.

### Documentation

- [Architecture](docs/architecture.md)
- [Google Cloud deployment](docs/google-cloud.md)
- [Windows SMART routing](docs/windows-smart-routing.md)
- [Private DNS](docs/private-dns.md)
- [Traffic accounting](docs/traffic-accounting.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Dataset documentation](data/README.md)

### Server and utility scripts

- [Server installer](server/install.sh)
- [Server runtime verifier](scripts/verify-server.sh)
- [Client generator](scripts/generate-client.sh)

### Windows SMART scripts

- [Status](windows/status.ps1)
- [Conflict detection](windows/detect-conflicts.ps1)
- [SMART ON](windows/smart-on.ps1)
- [SMART OFF](windows/smart-off.ps1)
- [Update CN IPv4 dataset](windows/update-cn-ip.ps1)
- [Update CN domain dataset](windows/update-cn-domains.ps1)

<!-- release-reference:end -->
