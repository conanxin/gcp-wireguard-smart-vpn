# Troubleshooting

This document records the diagnostic method used while building and validating the reference deployment.

The most important principle is:

> diagnose the failing layer before changing configuration.

The working system contains several independent layers:

```text
Application proxy
Windows DNS policy
Windows IP routing
WireGuard tunnel
UDP transport
Local access network
Internet path
GCP firewall
Linux packet filtering
WireGuard server
Private DNS
Internet forwarding/NAT
```

A failure at one layer can look like a failure at another.

---

## Quick triage

Start with:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\windows\status.ps1 `
    -ExpectedPublicIp YOUR_SERVER_IP
```

Then:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\windows\detect-conflicts.ps1 `
    -ExpectedPublicIp YOUR_SERVER_IP
```

A healthy SMART configuration should normally show:

```text
XRAY_TUN_UP=0

WG_PRESENT=True
WG_DNS_IS_PRIVATE=True
WG_HALF_ROUTES=2

CN_MISSING=0

PILOT_RULES=0

WININET_PROXY_ENABLE=0

LOCAL_FOUNDATION_PASS=True
CN_ROUTE_PASS=True
PUBLIC_EGRESS_PASS=True
```

---

# 1. WireGuard interface exists but nothing works

Check:

```powershell
& 'C:\Program Files\WireGuard\wg.exe' show
```

Important fields:

```text
endpoint
latest handshake
transfer
persistent keepalive
```

A working peer should have a recent:

```text
latest handshake
```

and both transfer directions should normally increase.

A failure observed during development looked like:

```text
transfer: 0 B received, xxx B sent
```

with no fresh handshake.

That means the interface and routes can exist even though the actual WireGuard transport is not established.

Do not treat the presence of the virtual interface alone as proof that the VPN is working.

---

# 2. Route points to WireGuard but private address is unreachable

Example symptom:

```text
10.66.66.1 -> client1-cndirect
```

but:

```text
ping 10.66.66.1      fails
TCP 10.66.66.1:53    fails
DNS 10.66.66.1       times out
```

This means the Windows route decision is correct, but does not prove the encrypted transport is working.

Check WireGuard runtime next:

```powershell
& 'C:\Program Files\WireGuard\wg.exe' show client1-cndirect
```

If the client sends bytes but receives zero bytes, move down to UDP transport diagnostics.

---

# 3. Distinguish DNS failure from WireGuard failure

The tested private DNS server uses:

```text
10.66.66.1:53
```

Before debugging Windows DNS policy, verify the DNS service locally on the server.

Check listener:

```bash
sudo ss -lntupH "sport = :53"
```

Expected private listener:

```text
10.66.66.1:53
```

Test locally from the server using TCP and UDP.

If local DNS succeeds but the Windows client cannot reach `10.66.66.1:53`, the DNS resolver itself is probably not the failing layer.

In the reference incident:

```text
LOCAL_TCP53=PASS
LOCAL_UDP53=PASS
```

while the Windows client still timed out.

That moved the diagnosis from DNS to WireGuard transport.

---

# 4. Check the server-side WireGuard listener

On the server:

```bash
sudo wg show wg0
sudo ss -lunp | grep 51820
sudo systemctl is-active wg-quick@wg0
```

Expected:

```text
wg0 active
UDP/51820 listening
```

Also check forwarding:

```bash
sysctl net.ipv4.ip_forward
```

Expected:

```text
net.ipv4.ip_forward = 1
```

---

# 5. Check GCP address and firewall

Confirm the current external address:

```bash
gcloud compute instances describe INSTANCE `
  --zone=ZONE `
  --format='get(networkInterfaces[0].accessConfigs[0].natIP)'
```

The client Endpoint must match the VM's current external IP.

Check the effective firewall rather than only one manually created rule:

```bash
gcloud compute instances network-interfaces get-effective-firewalls \
  INSTANCE \
  --zone=ZONE \
  --network-interface=nic0
```

For the standard listener, verify ingress permits:

```text
UDP/51820
```

For compatibility mode, also verify:

```text
UDP/443
```

---

# 6. Windows WireGuard logs

WireGuard for Windows can expose its ring-buffer diagnostic log.

Example:

```powershell
& 'C:\Program Files\WireGuard\wireguard.exe' /dumplog
```

During the failing transport test, the client repeatedly reported behavior equivalent to:

```text
Sending handshake initiation
Handshake did not complete after 5 seconds, retrying
```

This is useful, but:

> a log entry saying "Sending handshake initiation" does not prove the packet reached the physical network.

Packet capture is the next step.

---

# 7. Windows packet capture with Pktmon

Windows `Pktmon` can show whether a WireGuard UDP packet travels through the Windows networking stack to the physical adapter.

The diagnostic filter used during testing targeted:

```text
protocol = UDP
remote IP = GCP server IP
port = 51820
```

A captured WireGuard handshake initiation appeared as:

```text
client-ip:source-port
    ->
server-ip:51820

UDP payload length: 148 bytes
```

The packet was observed through the Windows stack down to the physical Wi-Fi adapter.

This established that the packet was not merely trapped inside the WireGuard virtual interface.

Important:

> seeing the packet at the Windows physical-adapter software observation point does not prove that the router or remote server received it.

Use server-side capture for the other end of the path.

---

# 8. Server packet capture

Use:

```bash
sudo tcpdump -ni ens4 -nn -vv 'udp port 51820'
```

or during UDP/443 testing:

```bash
sudo tcpdump -ni ens4 -nn -vv 'udp port 443'
```

A WireGuard handshake initiation has an expected UDP payload size of:

```text
148 bytes
```

A handshake response has an expected payload size of:

```text
92 bytes
```

During the reference investigation, synchronized testing eventually showed:

```text
client -> server
UDP payload 148

server -> client
UDP payload 92
```

repeated approximately every five seconds.

This was a major diagnostic boundary:

```text
client initiation reached VM       verified
server generated response          verified
session still did not complete     observed
```

Do not infer the behavior of one time window from a different packet-capture window.

An earlier capture with zero packets only proved that no matching packets were observed during that particular capture interval.

---

# 9. Use a second client and second network

A powerful diagnostic technique is to vary one layer at a time.

The reference deployment used a phone peer on cellular data.

That removed several Windows-specific variables:

```text
Windows host
Windows firewall stack
USB Wi-Fi adapter
Windows WireGuard implementation state
home Wi-Fi path
```

The server can distinguish peers using their WireGuard public keys and configured private tunnel addresses.

Example reference addresses:

```text
Windows  10.66.66.2
Phone    10.66.66.3
```

Do not reuse one client's private key on another device for this test.

---

# 10. UDP/51820 versus UDP/443 A/B test

The most important transport finding in the reference environment came from an A/B test.

Initial transport:

```text
client
  ->
server:51820/udp
```

failed to complete the WireGuard session on the tested access paths.

The server was then configured with a temporary compatibility path:

```text
UDP/443
  ->
iptables REDIRECT
  ->
UDP/51820
```

WireGuard itself remained listening on:

```text
UDP/51820
```

Only the external transport port changed.

The client Endpoint became:

```text
SERVER_IP:443
```

---

# 11. What proved UDP/443 worked

The UDP/443 experiment produced several independent signals.

## Fresh handshake

Windows showed:

```text
endpoint: SERVER_IP:443
latest handshake: seconds ago
```

## Bidirectional byte counters

Both:

```text
received
sent
```

increased.

## Private tunnel address

The client could reach:

```text
10.66.66.1
```

## Private DNS TCP

The client successfully connected to:

```text
10.66.66.1:53
```

## Private DNS query

Queries to:

```text
10.66.66.1
```

returned valid foreign-domain answers.

## Normal Internet traffic

Server capture showed decrypted tunnel traffic such as:

```text
10.66.66.x -> Internet
Internet -> 10.66.66.x
```

Together these are much stronger evidence than merely observing a handshake.

---

# 12. Persist UDP/443 correctly

The tested compatibility path is represented by:

```text
server/udp443/wg-udp443.service
```

The service checks whether the REDIRECT rule already exists before inserting it.

This prevents repeated starts from creating duplicate rules.

Verify:

```bash
iptables -t nat -S PREROUTING
```

Expected:

```text
UDP443_RULE_COUNT=1
```

The systemd unit is:

```text
Type=oneshot
RemainAfterExit=yes
```

Therefore:

```text
ActiveState=active
SubState=exited
```

is normal.

---

# 13. Private DNS timeout through public resolvers

Before the private DNS path was completed, public DNS queries routed through the tunnel showed delays of roughly:

```text
12 seconds
```

for several foreign domains.

Direct querying of the new private resolver:

```text
10.66.66.1
```

reduced tested resolution latency to roughly:

```text
190-255 ms
```

for domains such as:

```text
google.com
github.com
openai.com
youtube.com
```

This is why the Windows WireGuard configuration uses:

```ini
DNS = 10.66.66.1
```

instead of depending on a public DNS server reached through the tunnel.

---

# 14. Wrong CDN answers for CN domains

Another important issue appeared when CN domains were resolved using a foreign resolver.

Examples included CN services resolving to addresses that were not in the APNIC CN IPv4 set.

That caused those services to follow WireGuard even though the desired behavior was direct access.

The solution was DNS split using Windows NRPT.

Example:

```text
www.baidu.com
   ->
223.5.5.5
   ->
CN address
   ->
WLAN
```

while:

```text
www.google.com
   ->
10.66.66.1
   ->
foreign address
   ->
WireGuard
```

SMART routing therefore requires both:

```text
IP classification
DNS classification
```

not just one of them.

---

# 15. NRPT effective-policy performance

The reference dataset contains:

```text
12160 namespaces
```

stored in:

```text
25 NRPT rules
```

with chunks of up to:

```text
500 namespaces
```

Reading the complete Windows effective NRPT policy can take several seconds.

This does not necessarily imply DNS queries themselves are slow.

During runtime tests:

```text
CN DNS queries      approximately 10-25 ms
foreign DNS queries approximately 190-205 ms
```

while enumerating the entire effective policy was much slower.

Do not use full policy enumeration latency as a direct proxy for DNS lookup latency.

---

# 16. System proxy can hide the real WireGuard egress

One of the most misleading observations during testing was:

```text
Find-NetRoute
    ->
WireGuard
```

while an application-level public-IP test returned an unexpected address.

The cause was:

```text
WinINET ProxyEnable = 1
ProxyServer = 127.0.0.1:7897
```

v2rayN TUN was off, but its Windows system proxy was still enabled.

Therefore:

```text
normal application request
    ->
127.0.0.1 proxy
    ->
different proxy egress
```

while the native routing path was actually:

```text
Windows
    ->
WireGuard
    ->
GCP
```

The decisive comparison was:

```powershell
Invoke-RestMethod https://api.ipify.org
```

versus:

```powershell
curl.exe --noproxy "*" https://api.ipify.org
```

Observed pattern:

```text
normal request       -> proxy IP
forced no-proxy      -> GCP WireGuard IP
```

After disabling the WinINET system proxy:

```text
ProxyEnable = 0
```

the normal public egress matched the GCP VM.

Note:

```text
ProxyServer = 127.0.0.1:7897
```

may remain stored in the registry even when:

```text
ProxyEnable = 0
```

The latter is the important active-state flag.

---

# 17. v2rayN process versus actual conflict

A running process is not automatically a conflict.

The following can coexist:

```text
v2rayN.exe running
xray.exe running

xray_tun OFF
WinINET system proxy OFF
```

Therefore `detect-conflicts.ps1` reports the process itself as a warning.

Actual conflict conditions include:

```text
xray_tun UP
WinINET ProxyEnable = 1
```

This distinction prevents unnecessary process termination.

---

# 18. CN route completeness

The current checked-in APNIC dataset contains:

```text
5494 CIDRs
```

A healthy SMART ON state should report:

```text
CN_EXPECTED=5494
CN_PRESENT=5494
CN_MISSING=0
```

The exact count can change when APNIC publishes new allocations.

Future validation should prioritize:

```text
dataset expected count
installed matching count
missing count = 0
```

rather than permanently hard-coding 5494 as a universal constant.

---

# 19. Domain dataset completeness

The verified domain snapshot contains:

```text
12160 NRPT namespaces
```

with:

```text
3 unsupported regexp rules
```

The generator stores unsupported regexp rules separately:

```text
data/cn-nrpt-unsupported-regexp.txt
```

They should not be silently discarded.

If upstream introduces:

```text
keyword rules
unknown rule types
generic top-level-domain matches
```

the updater intentionally stops rather than silently broadening Windows DNS policy.

---

# 20. SMART OFF behavior

`smart-off.ps1` removes:

```text
CN routes
CN NRPT rules
```

but keeps:

```text
WireGuard
Private DNS
0.0.0.0/1
128.0.0.0/1
```

After a verified SMART OFF:

```text
223.5.5.5
114.114.114.114
8.8.8.8
1.1.1.1
```

all routed through:

```text
client1-cndirect
```

The GCP public egress remained correct.

This is expected.

---

# 21. OFF -> ON recovery

A real OFF -> ON test started from:

```text
CN routes        0
NRPT rules       0
NRPT namespaces  0
```

`smart-on.ps1` then rebuilt:

```text
5494 CN routes
25 NRPT rules
12160 namespaces
```

The reference rebuild took approximately:

```text
11.8 seconds
```

Final runtime tests confirmed:

```text
Baidu      -> WLAN
Bilibili   -> WLAN
Google     -> WireGuard
GitHub     -> WireGuard
```

and public egress returned the GCP VM external IP.

---

# 22. Useful evidence hierarchy

When debugging, prefer evidence in approximately this order:

```text
1. actual application result
2. WireGuard latest handshake / counters
3. route decision
4. DNS answer
5. Windows packet capture
6. server packet capture
7. server listener
8. effective cloud firewall
9. configuration file contents
```

Configuration that looks correct is weaker evidence than packets and successful runtime traffic.

---

# 23. Avoid broad changes during diagnosis

During a failure, do not immediately change all of:

```text
WireGuard keys
Endpoint
firewall
DNS
routing
NRPT
server service
```

Change one layer at a time.

The reference troubleshooting process eventually isolated the transport issue because:

```text
keys stayed constant
server stayed constant
client stayed constant
only external UDP port changed
```

and:

```text
51820 failed
443 succeeded
```

This made the A/B result much more informative.

---

# 24. Recommended diagnostic sequence

For a future incident:

```text
1. Run status.ps1
2. Run detect-conflicts.ps1
3. Check wg.exe show
4. Check private address reachability
5. Check 10.66.66.1:53
6. Verify server wg0 and listener
7. Verify effective cloud firewall
8. Capture Windows outbound UDP
9. Capture server UDP simultaneously
10. Test a second client/network
11. Test UDP/443 compatibility path
12. Re-test private DNS
13. Verify public IP with --noproxy
```

This sequence minimizes speculative configuration changes.

---

# 25. Known working reference state

A healthy tested Windows state looked like:

```text
xray_tun                   OFF
WinINET ProxyEnable        0

WireGuard endpoint         SERVER_IP:443
WireGuard DNS              10.66.66.1
WireGuard half routes      2

CN routes                  complete
CN NRPT                    complete

CN domain DNS latency      low tens of ms
foreign DNS latency        ~200 ms

CN traffic                 physical network
foreign traffic            WireGuard

no-proxy public egress     GCP VM external IP
```

Use the current dataset counts reported by the repository scripts rather than assuming historical snapshot counts forever.
