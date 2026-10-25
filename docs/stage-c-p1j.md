# Stage C P1J — indistinguishable native route race and crash-window mock

**Date:** 2026-10-25 (China Standard Time)
**Verdict:** P1J MOCK OBSERVABILITY PASS. Native CN SMART writes/deletions: NOT RUN / NOT AUTHORIZED.
**Parent:** P1I Draft PR #9; P1H synthetic batch recovery; P1F one fixed TEST-NET watchdog test.

## Scope and deliverables

Three NEW, separate files; no existing P1E/P1F/P1G/P1H/P1I or legacy SMART scripts modified:

- audit/stage_c_p1j_native_race_model.py — Python 3.12 pure evidence / possible-worlds model, with no Windows APIs, network calls or system-mutating subprocesses.
- audit/test_stage_c_p1j_native_race_model.py — 99 regression tests, including 44 independent race/window cases, four genuine Python child exit-77 and fresh-process evidence replays, 5,494-CIDR corpus stress, and WLAN interface/gateway drift.
- audit/test-stage-c-p1j-readonly-windows-20261025.ps1 — repeatable ordinary-user Windows PowerShell 5.1 read-only gate (12/12 checks); creates only temporary fixture/stdout/stderr files and removes them afterward.
- docs/stage-c-p1j.md — this evidence and architecture handoff.

### Reproduce without Administrator rights

Windows PowerShell:

~~~powershell
$root = Join-Path $env:USERPROFILE 'Documents\gcp-wireguard-smart-vpn'
$ps = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
& $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$root\audit\test-stage-c-p1j-readonly-windows-20261025.ps1"
~~~

WSL:

~~~bash
cd /mnt/c/Users/haili/Documents/gcp-wireguard-smart-vpn
python3 audit/test_stage_c_p1j_native_race_model.py
python3 audit/stage_c_p1j_native_race_model.py --matrix
python3 audit/stage_c_p1j_native_race_model.py --corpus data/cn-ipv4-cidrs.txt
~~~

These operations DO NOT perform New-NetRoute, Remove-NetRoute, netsh routing, DNS/NRPT writes, WinINET changes, WireGuard activation, proxy switching or reboots. Only the test harness launches Python subprocesses with synthetic fixtures. The genuine 77 exit is a **Python process exit only**, not a Windows operating-system crash, power-loss experiment or native network operation.

## Key result: observational indistinguishability of native route ownership

P1J builds two possible *simulated* histories:

A. This run created a route and the route remains owned by this run.

B. This run originally created a route but a foreign actor inserted an identical native route, either before the first postread, between postread/current enumeration, after the parent process exited, or during recovery.

The test-only ground-truth attribute (PROJECT vs EXTERNAL) is removed before any route enters the P1I CIM contract. In both histories, Windows-observable fields can match **exactly**: Store, DestinationPrefix, InterfaceIndex, NextHop, RouteMetric, CompartmentId, Protocol, and even InstanceID. Frozen run ID, submitted source hash and apparently complete intent/API-return/postread receipts may also match.

Formal statement, limited to this evidence set:

O(owned history) = O(external replacement history), while TrueOwner(owned) differs from TrueOwner(replacement).

Therefore a deterministic decision procedure relying ONLY on O cannot always safely distinguish the two. P1J returns **MANUAL_REVIEW_ONLY_OWNERSHIP_UNPROVEN** for exact matching evidence, **BLOCKED_NO_NATIVE_DELETE** for ambiguous/incomplete records, and **NO_TARGET_TO_DELETE** for unambiguous absence. It **never** upgrades the result to permission for a native route delete.

This is a demonstration of an information gap, not proof that no other Windows architecture or exclusive route writer could ever address it. Native InstanceID and the P1H synthetic simOwnerToken are not an authenticated persistent owner property in the observed Get-NetRoute data. A SHA256 journal or an API success return alone cannot certify that the CURRENT indistinguishable route is still ours after external replacement.

## Crash-window and race matrix (44 cases)

Four simulated external route events:

- EXTERNAL_INSERT_BEFORE_POSTREAD
- EXTERNAL_REPLACE_AFTER_POSTREAD
- EXTERNAL_RECREATE_AFTER_PARENT_EXIT
- EXTERNAL_REPLACE_DURING_RECOVERY

Eleven ledger/crash observation windows:

- BEFORE_INTENT; INTENT_ONLY
- CALL_ENTERED_NO_ACK; API_RETURN_NOT_PERSISTED; CALL_ACK_DURABLE
- POSTREAD_NOT_COMMITTED; VERIFIED_RECEIPT
- ROLLBACK_INTENT_PENDING; DELETE_ACK_NOT_PERSISTED
- ROLLBACK_CLOSED_BUT_ROUTE_PRESENT; ROLLBACK_CLOSED_AND_ABSENT

The full cross product is 44 possible-history comparisons. All 44 observable pairs are equivalent within the model; in **28 cases a route is present and the ground-truth owner differs**, while the other 16 cases have no target route. Decisions: 32 blocked, 4 human-review-only, 8 no-native-delete-needed. Unsafe native delete authorizations: **ZERO**.

P1J also starts four genuine child processes that persist synthetic evidence and deliberately exit with code 77. A separately launched Python process reads the evidence afterward and refuses automatic deletion for full-receipt, missing-postread, pending rollback and missing-delete-ack windows.

## Full 5,494-CIDR corpus

Actual project CIDR source input: 5,494 unique records, 512 per batch = 11 *synthetic* batches.

One native-shaped read-only scenario injects two unseen external same-identity replacements (the 7th batch and last entry), plus one deliberately missing postread receipt. Outcome:

- 5,493 matching-but-ownership-UNPROVEN, review-only;
- 1 missing-postread-crash-gap BLOCKED;
- 5,494 native ownership proofs still missing; nativeDeleteAuthorized=False.

A control scenario with all 5,494 receipts apparently complete also yields **5,494 review-only** — never permission to delete. A full batch-7 missing receipt case blocks exactly 512 entries. No actual CN Windows routes are created or removed in these tests. Batch speed is not a native-route throughput benchmark.

The data file remains the unchanged 2026-09-05 APNIC-derived local snapshot, SHA256 DFCFE4937E81B2B1221E597519B9F0AD172BC0B7BA48577C062CB6D8B65DECEC. It was 50 days old on 2026-10-25 and should be separately refreshed/reviewed before any authorized native SMART experiment.

## Actual Windows 2026-10-25 observations

| Check | Directly observed |
|---|---|
| Windows Python 3.12.10 and WSL Python 3.12.3 | **99/99 PASS** on both |
| Windows PowerShell 5.1 end-to-end no-write gate | **12/12 PASS**, exit 0 |
| Actual native IPv4 route-table SHA before/after today's test | Equal: 6DC81B4D72AF45BC033776FF608281695AACFC39ED7049262E11A533E3B59AAE |
| xray system proxy | WinINET ProxyEnable=1, localhost 127.0.0.1:7897, xray process 1, proxy HTTPS 204 |
| Project NRPT | 25 rules, exact mapping of 12,160 namespaces, unchanged |
| WireGuard / default half routes | WG service 0, half routes 0 |
| P1F TEST-NET route | 0 residual |
| CN native routes actually installed | 0 / 5,494 planned |
| Native route mutations | 0 |

Important operational drift detected on **2026-10-25 at 10:49 +08**:

| Physical routing measurement | Previous 2026-10-24 | Current 2026-10-25 |
|---|---:|---:|
| WLAN interface index | 9 | **8** |
| ActiveStore IPv4 route objects | 24 | **28** |
| WLAN next hop | 192.168.0.1 | 192.168.0.1 |
| Native CN dataset exact-prefix collisions | 0 | 0 |

The observed change of interface index is not by itself a network error; however, any old run ledger or simulated route intent pinned to index 9 is now **stale** for a new live operation. Always re-read the unique WLAN default route, compare interface index/gateway, and block automated network mutations on drift. P1J includes explicit fixture tests for interface index and next-hop drift.

Today's native route SHA is expected to differ from yesterday's historical SHA because the current route table has changed; evidence of **no mutation by P1J** comes only from the equal SHA recorded at the beginning and end of today's run.

## Recovery boundary and next architecture decision

**P1J has not solved native route ownership.** It demonstrates why more successful read-only simulations cannot make an unidentifiable competing native route safe to remove.

The next stage should be an **architecture decision**, not automatic installation of all 5,494 routes:

1. Keep fail-closed/no-delete-on-ambiguity and human-supervised cleanup as the present contract. This maximizes third-party route safety but can leave an unresolved route until someone reviews it.
2. Investigate a genuinely exclusive single-writer routing authority for the relevant Windows route scope, if feasible; test whether independent tools can still create indistinguishable objects before claiming unattended safe rollback.
3. Consider isolating routing to a dedicated environment or simplifying the native split-routing design rather than proliferating 5,494 unmanaged system-wide entries.
4. If any new real single-route or small-batch experiment is proposed, it needs a fresh explicit onsite authorization, two-window manual return readiness and its own independent post-network audit; historical user permissions do NOT cover new changes.
5. Keep all stacked PRs Draft/unmerged until a clear safe contract is chosen.

P1F's successful fixed TEST-NET 120-second watchdog shows that one deliberately abandoned native route was deleted under one observed run. It is not proof that an unattended controller can safely delete an indistinguishable third-party route, nor proof of power-loss or mass CN-route recovery.

**Final gate:** P1J_IDENTICAL_ROUTE_RACE_MODEL=PASS; P1J_WINDOWS_READ_ONLY=PASS; NATIVE_OWNERSHIP_UNAMBIGUOUS=NOT_PROVEN; NATIVE_DELETE_AUTHORIZED=False; FULL_CN_SMART_LIVE=NOT_TESTED; PRIMARY=v2rayN/xray.
