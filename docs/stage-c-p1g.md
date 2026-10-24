# Stage C P1G — CN SMART read-only route plan and collision inventory

**Date:** 2026-10-24 (China Standard Time)
**Scope:** Zero network mutations; existing v2rayN/xray stays primary.
**Basis:** P1F R3 verified one fixed TEST-NET `198.51.100.77/32` route was really removed by its independent watchdog. **That result does not validate bulk route rollback.**

## Read-only deliverables

- `audit/stage-c-p1g-readonly-cn-plan-20261024.ps1` — Windows PowerShell 5.1, `Live` (default) or explicit `Fixture`; inspects actual CN source, exact CIDR prefix equality, ActiveStore/PersistentStore, WLAN gateway, NRPT and current proxy/WG state.
- `audit/test-stage-c-p1g-readonly-20261024.ps1` — non-mutating AST and fixed fixtures; verifies read-only architecture, ownership ambiguity, invalid prefix/duplicate handling, gateway ambiguity, active/persistent collisions and unchanged route identity. **13/13 PASS** on real Windows PowerShell 5.1.
- This document records baseline, semantics, limitations and the **future** gates for safe staged development.

### Reproduce now without elevation

Run in an ordinary Windows PowerShell window:

~~~powershell
$root = Join-Path $env:USERPROFILE 'Documents\gcp-wireguard-smart-vpn'
$ps = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
& $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$root\audit\stage-c-p1g-readonly-cn-plan-20261024.ps1" -Mode Live
& $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$root\audit\test-stage-c-p1g-readonly-20261024.ps1"
~~~

These commands do not invoke `smart-on.ps1`, `smart-off.ps1`, `New-NetRoute`, `Remove-NetRoute`, `netsh`, DNS/NRPT setters, route installers, WireGuard, proxy setters, or privileged actions. The test suite creates and removes only **temporary fake JSON / CIDR fixtures** for offline classification.

## Verified 2026-10-24 baseline

| Evidence | 2026-10-24 actual value |
|---|---|
| CN IPv4 snapshot | 5,494 strictly canonical unique CIDRs, no overlaps/merges in independent Python `ipaddress` audit |
| CN file SHA256 | `DFCFE4937E81B2B1221E597519B9F0AD172BC0B7BA48577C062CB6D8B65DECEC` |
| Dataset local mtime | 2026-09-05; **49 days old** on test date, no APNIC refresh performed |
| CN NRPT snapshot | 12,160 source namespaces; 25 project rules |
| NRPT validation | Missing 0; extra 0; bad nameservers 0; `NRPT_EXACT=True` |
| Windows native ActiveStore | 24 existing IPv4 route objects |
| Windows native PersistentStore | 0 IPv4 route objects (empty-store NotFound query interpreted as empty; other query errors are fatal) |
| WLAN physical default | Exactly one, `InterfaceIndex=9`, gateway `192.168.0.1` |
| Full-CN proposed metric | 5 (legacy script's value, **not** live applied) |
| CN prefixes with no equal-prefix native route object | 5,494 candidate-only; **not** a command batch |
| Matching native route but unknown ownership | 0 |
| Conflicting ActiveStore / PersistentStore CN prefixes | 0 / 0 |
| Current primary mode | v2rayN/xray process 1, WinINET proxy 1 at `127.0.0.1:7897`; WG absent, /1 native routes 0 |
| P1G result | `READ_ONLY_PLAN_COMPLETE`; `P1G_FULL_CN_WRITE_AUTHORIZED=False` |
| Offline PowerShell regression | 13/13 pass, 0 fail, native route identity unchanged |

**Important:** 5,494 absent equal-prefix routes are expected while Windows is using the system proxy. This is not a fault to repair by abruptly installing routes. Also, a matching prefix alone **never demonstrates this project's ownership**.

### Counting semantics

- `CN_NO_EXACT_PREFIX_ROUTE_CANDIDATES`: source prefix has **zero exact matching destination-prefix route objects** across BOTH ActiveStore and PersistentStore. This is a hypothetical candidate, not an authorization.
- `CN_MATCHING_BUT_UNOWNED_PREFIXES`: exactly one ActiveStore route with matching WLAN interface index, next hop and planned metric, no PersistentStore duplicate. Still treated as **externally owned or unknown** without a run ledger.
- `CN_ACTIVE_CONFLICT_PREFIXES`: one or more same-prefix native routes exist with a mismatched interface, hop, metric or multiple route objects; fail closed.
- `CN_PERSISTENT_CONFLICT_PREFIXES`: a same-prefix PersistentStore route exists; fail closed.
- `PHYSICAL_DEFAULT_MATCHES`: must be **exactly one WLAN default route** for this version. No silently selecting another adapter. Wi-Fi name or gateway change must be investigated, not auto-repaired.
- Source validation rejects malformed, duplicate or noncanonical CIDRs. The source is not automatically refreshed; hash and age are reported.
- No installed native route is adopted as "ours" based on prefix/metric. No mutation script is produced, even if the count is 5,494.

The legacy `windows/smart-off.ps1` selects prefixes by `dataset + physical interface + gateway` and can remove a route it did not create. The legacy `windows/smart-on.ps1` checks only existing prefix coverage and uses a broad `netsh -f` batch; its `DryRun` checks are **not** evidence of safe lifecycle ownership. Do **not** run these for P1G.

## Proposed route ownership and recovery protocol (design ONLY)

1. **Prerequisites:** Freshly verified APNIC-derived CIDRs, immutable SHA256/row-count snapshot, per-run ID and exclusive lock, exact WLAN interface/gateway/metric, WG handshake and private DNS, WinINET state and xray mode captured. All baselines are checked *before* modifications. Current 49-day data snapshot should be refreshed and reviewed separately, not silently applied.
2. **Run ledger:** Append-only, durable, per-route intent and result: `runId`, prefix, ActiveStore, interface index, next hop, metric, preexisting route identities, write time, postwrite exact identity, rollback time, verification result. Save intent BEFORE every write. No claim of ownership without matching journal and exact native route identity.
3. **Limited-batch staging:** First rehearse on isolated fixtures, then a freshly authorized local supervised micro-batch only. Cap each batch by a bounded route count and observed duration. **The P1F 120-second one-route watchdog is NOT reused as a guarantee for 5,494 routes.** Use an independently verified staged recovery controller with durable progress, timeout, per-batch results, and human emergency return.
4. **Fail-closed rollback:** Remove only unique native routes actually written and proven owned in this run; reject ambiguous, modified or externally adopted rows. Re-read both route stores after every batch. PersistentStore routes and original NRPT rules are not removed merely because their names/prefixes look familiar.
5. **Proxy / tunnel order:** v2rayN/xray system proxy remains the daily baseline. Native `Find-NetRoute` does **not** prove the path an app uses while it still uses an HTTP/SOCKS system proxy. Future authenticated live testing must separately prove WG transport, DNS, IPv4 route direction, and actual application egress; restore original proxy/xray state from a snapshot rather than assuming a default.
6. **Restart/failure limits:** Treat process exit, permission-limited process status, reboot, power loss, WLAN changes and source dataset mutation separately. P1F only proved process-exit independent cleanup for a fixed /32. IPv6, DNS leakage, true dual-stack routing and bulk progress remain unverified.

### P1H next proposed boundary

Proceed next with **offline-owned-route ledger and multi-batch failure-injection mocks**, starting from P1G classification fixtures. No Windows native route writes, NRPT/DNS/proxy writes, WG install, reboot or live SMART until separate authorization while the user is physically at the Windows PC with a manual return path ready.

Status for this branch: **P1G READ-ONLY PASS, CN SMART LIVE NOT AUTHORIZED / NOT TESTED**.
