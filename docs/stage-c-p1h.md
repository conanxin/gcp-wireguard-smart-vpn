# Stage C P1H — Offline batch ownership ledger and crash recovery

**Date:** 2026-10-24, China Standard Time
**Verdict:** P1H OFFLINE MOCK PASS. Real native CN SMART writes: NOT RUN / NOT AUTHORIZED.

**Parent stages:** P1G read-only route classifications (Draft PR #7). P1F R3 truly removed a single TEST-NET /32 by its independent Watchdog, but that does **not** validate bulk recovery.

## Files

- audit/stage_c_p1h_batch_mock.py — Python 3.12 standard-library synthetic-only batch ledger.
- audit/test_stage_c_p1h_batch_mock.py — 28 independently executed regressions, including deliberate process exit 77, restart recovery, and full 5,494-prefix synthetic runs.
- docs/stage-c-p1h.md — this evidence and execution boundary.

### Re-run safely in ordinary Windows PowerShell

~~~powershell
$python = 'C:\Users\haili\AppData\Local\Programs\Python\Python312\python.exe'
$root = Join-Path $env:USERPROFILE 'Documents\gcp-wireguard-smart-vpn'
& $python (Join-Path $root 'audit\test_stage_c_p1h_batch_mock.py')
~~~

The test suite uses temporary directories under %LOCALAPPDATA%\GcpWGStageC\P1HMock\p1h-fixture-* and deletes only its own fixtures. On WSL, tests use ~/.local/state/GcpWGStageC/P1HMock/p1h-fixture-*. They do not require elevation.

The mock engine itself cannot execute native Windows route, DNS, NRPT, WinINET, xray or WireGuard commands, and does not launch external tools. Test harnesses launch **Python child processes only** to simulate writer crashes and fresh-process recovery.

Input CN IPv4 snapshot: 5,494 CIDRs, SHA256 DFCFE4937E81B2B1221E597519B9F0AD172BC0B7BA48577C062CB6D8B65DECEC; modified on 2026-09-05 (49 days before the test). The simulator validates strict IPv4 networks, duplicate/overlap, saves source SHA256, and never refreshes APNIC itself.

## Batch ownership protocol (synthetic)

1. **Initialize**: validate source and prefix digest; freeze RunId, physical gateway/interface/metric fixture (defaults: WLAN interface 9, gateway 192.168.0.1, metric 5), batch size, and original proxy/WG/NRPT mock state. Keep a third-party borrowed route in the fake baseline.
2. **Apply each batch**: persist BATCH_INTENT, atomically replace the fake world with new route objects (WORLD_BATCH_ADDED), then save BATCH_VERIFIED. Crash injection can exit process 77 at each boundary, including within a later batch.
3. **Recover in a new process**: verify original source checksum, audit SHA256 chain, full state seal and plan, per-route synthetic object identities, borrowed routes, and environment/gateway invariants **before deleting anything**.
4. **Reverse batches**: persist BATCH_ROLLBACK_INTENT, remove only this transaction's proven mock tokens, record WORLD_BATCH_REMOVED and BATCH_ROLLBACK_VERIFIED, then require exact baseline equality. Repeated recovery is idempotent.
5. **Fail closed**: foreign same-prefix route, PersistentStore collision, changed route object, new unrelated route, changed gateway, source drift, missing ledger or tampered state prevent automatic removal. No unrelated route is deleted.
6. **Exclusive mock writer**: OS-level file lock serializes writers per fixture in the same tested runtime. This is neither a machine-wide lock nor evidence of cross-WSL/Windows lock correctness.

### Synthetic owner marker does not exist on Windows

Each simulated route has a preallocated simOwnerToken tied to its RunId and ordinal. **Get-NetRoute exposes no equivalent durable custom owner field.** Hence the synthetic marker supports only fake-world tests, not automatic ownership inference on real Windows. A future native writer must save intent, route prestate, exact observed postwrite identity and per-run evidence and should block deletion of anything ambiguous or possibly inserted by another application.

State is atomically JSON-replaced at each transition and its audit events form a SHA256 chain. These hashes detect accidental changes but not an intentional same-account rewrite. Per-transition fsync is intentionally omitted for fast fixture-only, **process-exit-level** testing. Power failure, OS crash, disk flush persistence and uncontrolled crash windows remain UNTESTED. Python os._exit(77) proves a child process stopped, not that Windows reboot/recovery works.

## Actual verification, 2026-10-24

| Verification | Actual outcome |
|---|---|
| WSL Python 3.12.3 | 28/28 PASS, 0 failures |
| Native Windows Python 3.12.10 | 28/28 PASS, exit 0 |
| Windows IPv4 route table fingerprint before/after | Same SHA256 49776CA3C6DAACFF8797D4770280C2DFAAD854B1CA1506A67B221E58CD9B825C |
| Windows NRPT and WinINET | Unchanged; NRPT 25 rules |
| Windows WireGuard and xray | WG service 0, half-default /1 routes 0, xray process 1 |
| True separate Python subprocess failure | Exit 77, restarted process restores synthetic world |
| Simulation conflicts | Foreign same-prefix/PersistentStore collisions, source/gateway/identity drift and unrelated routes cause BLOCKED |
| Exclusive writer and source guard | Concurrent fixture writer, duplicate RunId, bad/duplicate/noncanonical CIDR, outside-sandbox path blocked |
| Native network modifications | ZERO |

### Full scale: 5,494 source prefixes

- Entire 5,494 actual CN IPv4 list, batches of 512 => **11 mock batches**.
- Independent WSL rehearsal: init 0.43 s; synthetic apply 3.30 s; synthetic rollback 4.45 s; status 0.22 s.
- All 5,494 mock additions and restorations verified. Baseline synthetic borrowed route untouched. State phase RESTORED, ledger audit chain 69 events.
- Regression test #27 reproduces full 5,494-prefix apply + rollback. Test #28 deliberately exits 77 after writing **batch 7 of 11**, then starts recovery in another process. Both passed on Windows and WSL.

**Do not extrapolate mock timings to real Windows routing performance.** Neither netsh nor New-NetRoute was executed for these 5,494 prefixes.

## Preserved boundaries

P1H is a new, independent Python fixture layer, aligned with P1G counting and P1C/P1E intent/rollback lessons. Frozen P1E/P1F native TEST-NET scripts, original Windows SMART ON/OFF, CN datasets, actual xray proxy and WireGuard configuration were not changed.

The 5,494 current absent routes are expected in daily xray proxy mode and are not installation failures. Existing 25 NRPT project rules are not modified or assumed owned by a new P1H run.

## Proposed P1I, not yet executed

Design a **Windows CIM-native adapter contract with no network writes**: map real route properties such as Store/PolicyStore, define journal evidence sufficient to avoid deleting someone else's route, model partial batch receipts and enumerations, define a supervised micro-canary rollback gate, and keep existing locked TEST-NET scripts unchanged. Before any actual CN route, NRPT, proxy or WG changes, obtain new explicit local supervision and emergency return approval.

Final fields: P1H_MOCK_RECOVERY=PASS; P1H_NATIVE_ROUTE_RECOVERY=NOT_TESTED; FULL_CN_SMART_LIVE=NOT_AUTHORIZED; PRIMARY=v2rayN/xray.
