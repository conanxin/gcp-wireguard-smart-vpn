# Traffic accounting

## Overview

The server includes lightweight WireGuard traffic accounting.

The reference flow is:

```text
WireGuard wg0
    |
wg show transfer counters
    |
wg-traffic-collect
    |
SQLite
    |
+-- peer_state
+-- daily_usage
+-- total_usage
    |
wg-usage
    |
human-readable usage report
```

The accounting layer is intentionally separate from WireGuard itself.

WireGuard remains responsible for:

```text
encryption
peer state
handshakes
runtime byte counters
```

The accounting tools periodically sample those counters and persist usage history.

---

## Repository files

The repository contains:

```text
server/traffic/wg-traffic-collect.py
server/traffic/wg-usage.py
server/traffic/wg-traffic-collect.service
server/traffic/wg-traffic-collect.timer
```

The server installer deploys these to runtime locations equivalent to:

```text
/usr/local/libexec/wg-traffic-collect
/usr/local/bin/wg-usage

/etc/systemd/system/wg-traffic-collect.service
/etc/systemd/system/wg-traffic-collect.timer
```

The SQLite database is stored at:

```text
/var/lib/wg-traffic/usage.db
```

The database is runtime state and should not be committed to Git.

---

## Why a collector is required

WireGuard exposes cumulative runtime transfer counters.

For each peer, `wg show` can report values equivalent to:

```text
received bytes
sent bytes
latest handshake
endpoint
allowed IPs
```

Those counters alone do not provide durable historical reporting.

For example, they do not directly answer:

```text
How much traffic did this peer use today?
How much this month?
How much has been recorded over time?
```

The collector converts runtime counters into persistent usage records.

---

## Runtime counters versus historical usage

It is important to distinguish:

```text
WireGuard runtime counter
```

from:

```text
accounting database
```

The runtime counter represents the current WireGuard interface state.

The SQLite database stores historical observations across collector runs.

The collector maintains enough state to calculate new usage between observations instead of repeatedly counting the entire cumulative runtime value.

---

## Database

The tested database path is:

```text
/var/lib/wg-traffic/usage.db
```

The verified schema contains these logical tables:

```text
peer_state
daily_usage
total_usage
```

Their responsibilities are:

```text
peer_state
    latest observed WireGuard counters used as the accounting baseline

daily_usage
    usage accumulated by peer and date

total_usage
    durable accumulated usage totals by peer
```

This division allows the project to produce both period-specific and all-time reports.

---

## `peer_state`

`peer_state` is the collector's runtime accounting checkpoint.

Conceptually:

```text
previous observation
    received = A
    sent     = B

current WireGuard observation
    received = C
    sent     = D

new usage
    received delta = C - A
    sent delta     = D - B
```

The new delta is written to the historical usage tables and the current values become the next checkpoint.

This prevents every timer run from re-counting all bytes reported by WireGuard.

---

## Counter resets

WireGuard runtime counters can reset when runtime state changes, for example after interface or peer recreation.

An accounting implementation must therefore not assume that every newly observed counter is always greater than the previous stored value.

The checked-in collector contains the reset-handling logic used by the tested deployment.

Do not replace it with a simple unconditional:

```text
current - previous
```

calculation without considering counter resets.

---

## `daily_usage`

The daily table provides the basis for reports such as:

```text
today
specific day
current month
```

Monthly usage can be derived by aggregating the daily rows belonging to the requested calendar month.

This keeps detailed period history without requiring a separate table for every reporting window.

---

## `total_usage`

The total table keeps durable accumulated usage by peer.

It provides the basis for:

```text
all-time received
all-time sent
all-time combined traffic
```

The persisted total is different from simply displaying the current `wg show` transfer counter.

---

## Collector

The collector executable is deployed as:

```text
/usr/local/libexec/wg-traffic-collect
```

Repository source:

```text
server/traffic/wg-traffic-collect.py
```

It is a Python program.

The server installer validates the Python source before deploying the service.

---

## Manual collector run

A server administrator can invoke the collector manually when diagnosing the accounting layer.

Reference:

```bash
sudo /usr/local/libexec/wg-traffic-collect
```

A normal production deployment primarily runs it through systemd rather than relying on manual execution.

---

## systemd service

The reference service is:

```text
wg-traffic-collect.service
```

Inspect it with:

```bash
systemctl status wg-traffic-collect.service
```

Because the collector is a periodic job, the service does not need to remain continuously running between collection events.

Its execution is driven by the timer.

---

## systemd timer

The reference timer is:

```text
wg-traffic-collect.timer
```

Enable it with:

```bash
sudo systemctl enable --now wg-traffic-collect.timer
```

Check:

```bash
systemctl is-enabled wg-traffic-collect.timer
systemctl is-active wg-traffic-collect.timer
```

Expected healthy state:

```text
enabled
active
```

Inspect scheduling details with:

```bash
systemctl list-timers wg-traffic-collect.timer
```

The timer file in the repository is the source of truth for the exact collection cadence.

---

## Verify recent timer execution

Use:

```bash
systemctl list-timers wg-traffic-collect.timer
```

and:

```bash
journalctl -u wg-traffic-collect.service
```

Recent successful collector invocations indicate that accounting is continuing to advance.

If the timer is active but the database does not change while traffic exists, inspect the collector service journal.

---

## Usage report

The human-readable reporting tool is deployed as:

```text
/usr/local/bin/wg-usage
```

Repository source:

```text
server/traffic/wg-usage.py
```

Run:

```bash
sudo wg-usage
```

The tested report includes per-client information such as:

```text
client / peer
status
latest handshake
today usage
month usage
all-time usage
received traffic
sent traffic
```

The report also includes a GCP egress reference intended to help interpret outbound usage.

---

## Live state and historical state

`wg-usage` can combine two different classes of information.

### Live WireGuard state

Examples:

```text
latest handshake
peer currently known to wg0
runtime received bytes
runtime sent bytes
```

### Historical accounting state

Examples:

```text
today
month
all-time
```

This distinction matters when interpreting a peer that has not connected recently.

A peer may be:

```text
offline now
```

while still having:

```text
historical usage in SQLite
```

---

## Direction terminology

WireGuard server counters are observed from the server's perspective.

Conceptually:

```text
received by server from peer
    client -> VPN server

sent by server to peer
    VPN server -> client
```

When describing Internet use from the user's point of view, remember that the direction labels are based on the server-side counters.

---

## GCP egress

WireGuard transfer counters measure tunnel traffic.

They are not the same thing as the authoritative Google Cloud billing record.

For example:

```text
WireGuard server -> client bytes
```

can be useful as an approximation or reference for traffic that may contribute to cloud egress, but the exact billable GCP network usage is determined by Google Cloud billing rules.

Therefore:

```text
wg-usage
```

should be treated as an operational traffic-accounting tool, not as a replacement for the Google Cloud billing system.

---

## Inspect the database

If SQLite tooling is installed, the database can be inspected directly.

Example:

```bash
sudo sqlite3 /var/lib/wg-traffic/usage.db '.tables'
```

Expected logical tables include:

```text
daily_usage
peer_state
total_usage
```

Schema inspection:

```bash
sudo sqlite3 /var/lib/wg-traffic/usage.db '.schema'
```

Do not modify the production database manually unless you understand the collector's accounting state.

---

## Database consistency

The important accounting invariant is:

```text
new WireGuard traffic
    ->
new collector delta
    ->
daily usage increment
    ->
total usage increment
    ->
peer_state updated
```

The tested deployment passed consistency checks across:

```text
peer_state
daily_usage
total_usage
```

This verifies that the collector ledger was internally coherent for the tested state.

---

## Backup considerations

The database contains usage history, not WireGuard private keys.

If historical traffic accounting matters, the file worth preserving is:

```text
/var/lib/wg-traffic/usage.db
```

Losing this file does not prevent WireGuard from functioning, but it loses the persisted accounting history.

The WireGuard configuration and keys are separate runtime assets.

---

## Privacy

Traffic accounting records byte totals and peer-level operational metadata.

It does not require storing packet payloads.

The design is intentionally much lighter than packet capture.

Conceptually the system records:

```text
peer identity
time bucket
byte counts
runtime state
```

rather than:

```text
web page contents
DNS payload history
full packet captures
```

---

## Peer naming

WireGuard fundamentally identifies peers by public key.

A human-friendly usage report may map those peers to client labels.

Do not hard-code personal production peer public keys into a public repository.

The checked-in server artifacts were audited before publication and do not contain the tested deployment's live peer public keys.

---

## Runtime verification

The project server verifier checks whether the accounting layer is installed and active.

Run:

```bash
sudo ./scripts/verify-server.sh
```

Relevant fields include:

```text
TRAFFIC_TIMER_ENABLED
TRAFFIC_TIMER_ACTIVE
PASS=TRAFFIC_TIMER

WG_USAGE_TOOL
PASS=WG_USAGE_TOOL
```

A tested healthy state reported:

```text
TRAFFIC_TIMER_ENABLED=enabled
TRAFFIC_TIMER_ACTIVE=active
WG_USAGE_TOOL=present
```

---

## Troubleshooting: timer inactive

Check:

```bash
systemctl status wg-traffic-collect.timer
```

Then:

```bash
systemctl list-timers wg-traffic-collect.timer
```

If disabled:

```bash
sudo systemctl enable --now wg-traffic-collect.timer
```

Then verify again.

---

## Troubleshooting: collector failure

Check:

```bash
systemctl status wg-traffic-collect.service
```

and:

```bash
journalctl -u wg-traffic-collect.service
```

Also verify:

```bash
wg show wg0
```

The collector depends on valid WireGuard runtime state.

---

## Troubleshooting: database missing

Check:

```bash
sudo ls -l /var/lib/wg-traffic/
```

If the accounting components were newly installed and the collector has never completed successfully, the database may not yet contain usable history.

Run the collector once manually:

```bash
sudo /usr/local/libexec/wg-traffic-collect
```

Then inspect the service/database again.

---

## Troubleshooting: report missing peers

First compare:

```bash
sudo wg show wg0
```

with:

```bash
sudo wg-usage
```

Then inspect:

```bash
sudo sqlite3 /var/lib/wg-traffic/usage.db '.tables'
```

and the collector service journal.

A peer that exists only historically may not have the same live state as an actively configured and recently connected WireGuard peer.

---

## Troubleshooting: implausible usage jump

If a usage value unexpectedly jumps, investigate:

```text
WireGuard interface restart
peer recreation
counter reset
collector checkpoint
database state
```

Do not immediately rewrite totals manually.

First compare:

```bash
wg show wg0
```

with:

```text
peer_state
daily_usage
total_usage
```

to determine whether the runtime counter or accounting checkpoint changed.

---

## Installation

The traffic accounting files are installed by:

```bash
sudo ./server/install.sh
```

Traffic accounting can be controlled by the installer's traffic option.

Reference environment override:

```bash
ENABLE_TRAFFIC=1
```

The installer deploys:

```text
collector
usage reporter
service
timer
```

and enables the timer when traffic accounting is enabled.

---

## Runtime files versus repository files

Repository:

```text
server/traffic/wg-traffic-collect.py
server/traffic/wg-usage.py
server/traffic/wg-traffic-collect.service
server/traffic/wg-traffic-collect.timer
```

Runtime:

```text
/usr/local/libexec/wg-traffic-collect
/usr/local/bin/wg-usage
/etc/systemd/system/wg-traffic-collect.service
/etc/systemd/system/wg-traffic-collect.timer
/var/lib/wg-traffic/usage.db
```

Only the source code and systemd definitions belong in Git.

The SQLite database belongs to the running server.

---

## Reference healthy state

A healthy tested deployment has:

```text
WireGuard:
    wg0 active
    peers visible
    runtime transfer counters changing

Accounting:
    wg-traffic-collect.timer enabled
    wg-traffic-collect.timer active
    collector executions successful
    usage.db present
    peer_state populated
    daily_usage populated
    total_usage populated

Reporting:
    wg-usage executable
    today usage available
    month usage available
    all-time usage available
```

The accounting layer is operationally useful but is not required for the VPN tunnel itself to carry traffic.

WireGuard remains functional even if the optional accounting reporter is temporarily unavailable.