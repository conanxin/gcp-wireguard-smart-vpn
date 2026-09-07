# Google Cloud deployment

This document describes the Google Cloud side of the WireGuard SMART VPN architecture.

It intentionally uses placeholders instead of environment-specific project IDs, addresses, peer keys, or credentials.

## Components

A minimal deployment requires:

```text
Google Compute Engine VM
    |
    +-- external IPv4
    +-- WireGuard
    +-- IPv4 forwarding
    +-- outbound Internet access
    +-- UDP/51820 ingress
    +-- UDP/443 ingress for compatibility mode
    +-- private DNS on the WireGuard address
```

The Windows SMART layer is configured separately.

---

## Example variables

Replace these values with your own environment:

```bash
PROJECT_ID="your-project-id"
INSTANCE="wireguard-vpn"
ZONE="us-west1-b"
NETWORK="default"
TAG="wireguard"
```

The examples below assume the VM has the network tag:

```text
wireguard
```

---

## VM operating system

The current server installer targets Debian/Ubuntu-style systems with:

```text
apt-get
systemd
iptables
python3
```

The repository installer currently checks for `apt-get` before proceeding.

Required packages include:

```text
wireguard-tools
dnsmasq-base
iptables
python3
```

---

## External IPv4

The WireGuard clients need a stable endpoint.

Read the VM external address with:

```bash
gcloud compute instances describe "$INSTANCE" \
  --project="$PROJECT_ID" \
  --zone="$ZONE" \
  --format='get(networkInterfaces[0].accessConfigs[0].natIP)'
```

Use that address, or a DNS name pointing to it, in client configurations.

Example:

```ini
Endpoint = YOUR_SERVER_IP:443
```

For a long-lived deployment, use an address allocation strategy appropriate for your Google Cloud setup rather than assuming an ephemeral address will never change.

---

## Network tag

The firewall examples in this project target a VM network tag.

Example:

```bash
gcloud compute instances add-tags "$INSTANCE" \
  --project="$PROJECT_ID" \
  --zone="$ZONE" \
  --tags="$TAG"
```

Confirm:

```bash
gcloud compute instances describe "$INSTANCE" \
  --project="$PROJECT_ID" \
  --zone="$ZONE" \
  --format='yaml(tags.items)'
```

---

## WireGuard UDP/51820 firewall

The server-side WireGuard interface uses UDP/51820 by default.

Example firewall rule:

```bash
gcloud compute firewall-rules create allow-wireguard-51820 \
  --project="$PROJECT_ID" \
  --network="$NETWORK" \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=udp:51820 \
  --source-ranges=0.0.0.0/0 \
  --target-tags="$TAG"
```

Inspect the rule:

```bash
gcloud compute firewall-rules describe allow-wireguard-51820 \
  --project="$PROJECT_ID"
```

---

## UDP/443 compatibility firewall

The tested architecture also provides a compatibility endpoint on:

```text
UDP/443
```

The VM redirects:

```text
UDP/443 -> UDP/51820
```

while WireGuard itself continues listening on UDP/51820.

Create an ingress rule:

```bash
gcloud compute firewall-rules create allow-wireguard-443 \
  --project="$PROJECT_ID" \
  --network="$NETWORK" \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=udp:443 \
  --source-ranges=0.0.0.0/0 \
  --target-tags="$TAG"
```

This is UDP/443, not TCP/443.

It does not require changing the WireGuard server listen port.

The repository service responsible for the redirect is:

```text
server/udp443/wg-udp443.service
```

---

## Effective firewall inspection

When diagnosing connectivity, do not inspect only the firewall rule you remember creating.

Inspect the firewall configuration that is actually effective for the VM network interface.

Example:

```bash
gcloud compute instances network-interfaces get-effective-firewalls \
  "$INSTANCE" \
  --project="$PROJECT_ID" \
  --zone="$ZONE" \
  --network-interface=nic0
```

This was useful during development because it separates:

```text
configured intention
```

from:

```text
effective VM firewall state
```

---

## WireGuard server configuration prerequisite

The current:

```text
server/install.sh
```

does not generate the server private key or `/etc/wireguard/wg0.conf`.

This is intentional.

Before running the installer, create:

```text
/etc/wireguard/wg0.conf
```

with your own private key and desired private subnet.

A minimal conceptual structure is:

```ini
[Interface]
PrivateKey = YOUR_SERVER_PRIVATE_KEY
Address = 10.66.66.1/24
ListenPort = 51820
```

Add forwarding/NAT behavior appropriate for your server.

Do not commit this real configuration to Git.

The repository `.gitignore` excludes common WireGuard private configuration material.

---

## IPv4 forwarding

The VPN server must forward IPv4 packets.

Check:

```bash
sysctl net.ipv4.ip_forward
```

Expected:

```text
net.ipv4.ip_forward = 1
```

The runtime verifier treats another value as a failure.

---

## Repository installation

After cloning the repository to the server, run:

```bash
sudo ./server/install.sh
```

The installer expects the base WireGuard configuration to already exist.

It then installs and configures the repository-managed server components:

```text
private DNS
UDP/443 compatibility service
traffic accounting tools
systemd units
```

The installer auto-detects, unless explicitly overridden:

```text
WireGuard private IPv4
uplink interface
WireGuard listening port
```

Supported environment overrides include:

```bash
PRIVATE_DNS_IP=10.66.66.1
UPLINK_IF=ens4
WG_PORT=51820
ENABLE_TRAFFIC=1
```

Example:

```bash
sudo \
  PRIVATE_DNS_IP=10.66.66.1 \
  UPLINK_IF=ens4 \
  WG_PORT=51820 \
  ENABLE_TRAFFIC=1 \
  ./server/install.sh
```

---

## Private DNS

The tested architecture uses the WireGuard server private address as the client DNS server.

Reference:

```text
10.66.66.1:53
```

The repository files are:

```text
server/dns/conan-wg-dns.conf.example
server/dns/conan-wg-dns.service
```

The tested GCP upstream is:

```text
169.254.169.254
```

The resolver is intended to be reachable from WireGuard clients.

It is not intended to expose an open DNS resolver on the VM external IPv4.

---

## Verify DNS exposure

After installation:

```bash
sudo ss -lntupH "sport = :53"
```

Expected private listener:

```text
10.66.66.1:53
```

The repository verifier checks both UDP and TCP port 53.

It also checks for wildcard/public exposure such as:

```text
0.0.0.0:53
[::]:53
```

---

## Verify WireGuard

Check:

```bash
sudo systemctl is-active wg-quick@wg0
sudo wg show wg0
sudo ss -lunp
```

Expected properties include:

```text
wg0 active
WireGuard IPv4 present
UDP listen port present
recent handshakes when clients are active
```

---

## Verify UDP/443 redirect

Check:

```bash
sudo iptables -t nat -S PREROUTING
```

The tested design expects exactly one rule equivalent to:

```text
uplink UDP/443
    -> REDIRECT
    -> WireGuard UDP/51820
```

The systemd service is idempotent and checks for the rule before inserting another copy.

For:

```text
Type=oneshot
RemainAfterExit=yes
```

this state is normal:

```text
ActiveState=active
SubState=exited
```

---

## Server runtime verifier

Use:

```bash
sudo ./scripts/verify-server.sh
```

It is designed as a read-only runtime verifier.

It checks:

```text
WireGuard service
WireGuard interface
WireGuard IPv4
WireGuard UDP listener
IPv4 forwarding
uplink interface

private DNS service
private UDP/53
private TCP/53
public DNS exposure

UDP/443 compatibility service
UDP/443 redirect rule count

traffic timer
wg-usage tool

WireGuard runtime state
```

A successful tested result ends with:

```text
FAILURE_COUNT=0
SERVER_VERIFY=PASS
```

Warnings do not automatically fail verification.

---

## Generate a client

Use:

```bash
sudo ./scripts/generate-client.sh \
  --name laptop \
  --address 10.66.66.2/32 \
  --endpoint YOUR_SERVER_IP:443
```

The generated client configuration uses the server WireGuard public key and creates a new client key pair locally.

By default, it can also add the new peer to:

```text
/etc/wireguard/wg0.conf
```

and the running WireGuard interface.

For a non-mutating preview/test of the generation path:

```bash
sudo ./scripts/generate-client.sh \
  --name test \
  --address 10.66.66.250/32 \
  --endpoint YOUR_SERVER_IP:443 \
  --no-apply \
  --no-qr
```

`--no-apply` does not add the generated peer to the running server.

Treat the resulting client `.conf` file as private material because it contains the client private key.

---

## Windows client reference

The tested Windows client uses:

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

Then run the Windows SMART layer from the repository.

Status:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\windows\status.ps1
```

Enable SMART:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\windows\smart-on.ps1
```

---

## Recommended deployment verification order

Use this order:

```text
1. VM running
2. external IPv4 correct
3. network tag present
4. UDP/51820 effective firewall
5. UDP/443 effective firewall
6. wg0 active
7. WireGuard UDP listener
8. IPv4 forwarding
9. private DNS
10. no public DNS exposure
11. UDP/443 redirect
12. generate client
13. client handshake
14. private address reachability
15. private DNS query
16. public egress
17. Windows SMART routing
```

This makes failures easier to localize.

---

## Runtime versus repository data

Do not store these in Git:

```text
server private key
client private keys
wg0.conf
client*.conf
traffic SQLite database
```

The repository contains:

```text
scripts
example configuration
systemd units
generated public routing/domain datasets
documentation
```

Runtime secrets remain on the systems that use them.

---

## Troubleshooting

For packet-level diagnosis, see:

```text
docs/troubleshooting.md
```

In particular, that document records the tested UDP/51820 versus UDP/443 A/B path and the distinction between:

```text
route exists
```

and:

```text
WireGuard transport actually works
```