# Stage C P1C — protected persistent mock journal and crash recovery

Date: 2026-10-24

**Status: Windows PowerShell 5.1 sandbox 32/32 PASS. Native network writes CLOSED.**

This Stage C P1C increment is a real Windows filesystem and cross-process
simulation, **not** a working SMART VPN switcher. The 2026-10-18 supervised
base WireGuard tunnel test remains the only true Windows tunnel Live PASS.
Stage C CN routes have never been installed in Live as part of this work.

## Files and supported modes

- audit/stage-c-p1c-durable-sandbox.ps1 — protected per-user sandbox
  mock plan/apply/recover, append-only SHA256 audit, file lock, hard crash
  and mocked timer recovery; all actions affect only synthetic files.
- audit/test-stage-c-p1c.ps1 — separate PowerShell process fault tests,
  grouped into 1 / 2 / 3; automatically deletes its synthetic fixtures.
- docs/stage-c-p1c.md — this contract and evidence.

Supported safe mode: PlanOnly (delegates to existing P1 Windows read-only
planner). MockPlan, MockApply, MockRollback, MockHoldLock and
MockTimeoutRecover work **only** with protected synthetic fixture files.

NativeApply and NativeRollback are **HARD DISABLED** at the start of the
script. They return NATIVE_GATE=HARD_DISABLED_REVIEW_REQUIRED, exit 40.
Although the derived source retains New-NetRoute and Remove-NetRoute
adapter DRAFT helper functions, none is reachable via an allowed action.
Do NOT enable them in-place without a separate code review and
disposable Windows VM verification.

## Reproducing safe tests

From a PowerShell 5.1 window in the project root directory:

    $ps = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    $driver = Join-Path (Get-Location) 'audit\stage-c-p1c-durable-sandbox.ps1'
    $tests = Join-Path (Get-Location) 'audit\test-stage-c-p1c.ps1'

    & $ps -NoProfile -ExecutionPolicy Bypass -File $driver -Mode PlanOnly

    & $ps -NoProfile -ExecutionPolicy Bypass -File $tests -Group 1
    & $ps -NoProfile -ExecutionPolicy Bypass -File $tests -Group 2
    & $ps -NoProfile -ExecutionPolicy Bypass -File $tests -Group 3

All test files are synthetic; no actual WireGuard configuration, server
key, system route, DNS, WinINET, NRPT or GCP data is modified.

## Persisted Windows mock state and ACL

All fixture paths are restricted to this subtree:

    %LOCALAPPDATA%\GcpWGStageC\P1CMock\p1c-fixture-<random>

The sandbox parent and per-run fixture folder must both disable inherited
NTFS ACLs. The driver rejects any unexpected allow ACE identity other than
the current user's SID, SYSTEM or Administrators. It also rejects
reparse-point fixture folders and file targets.

Mock state is persisted across independently launched processes:
mockworld.json, prefixes.txt, plan-<RUN_ID>.json, journal-<RUN_ID>.json,
audit-<RUN_ID>.ndjson and a fixture-wide exclusive lock file.
The test harness deletes only its synthetic fixture folders.

**Single-writer:** a FileStream opened with FileShare.None serializes
writes for the whole fixture **across RUN_IDs**. A second process is
blocked as LOCK_BUSY_EXCLUSIVE_WRITER. A process killed by the OS releases
the handle, enabling another process to attempt inspected recovery.
A future real network writer needs a stronger *machine-wide* lock.

## Journal and recovery ordering

1. MockPlan checks synthetic aligned/unique/non-overlapping IPv4 routes,
   borrowed third-party routes, NRPT resolver and xray proxy prestate,
   and writes a saved baseline and prefix digest.
2. MockApply requires the exact saved plan, fingerprint and CIDR list.
   Modified files or ACL permissions block further action.
3. Each simulated route insertion is first recorded in a journal as
   INTENT with full identity: prefix, interface index, next hop, metric,
   and policy store.
4. After the synthetic route write is verified it becomes VERIFIED.
   Interruption between INTENT and VERIFIED is intentionally recoverable.
5. Each committed JSON update appends a SHA256-chained event recording
   the file digest, sequence, previous digest and RUN_ID. The event is
   flushed to a Windows FileStream.
6. An independently launched mock PowerShell process can recover after
   an actual Environment.Exit(77) in the writer. It reads the persisted
   journal, verifies the hash chain and expected files, removes only
   unique run-owned mock routes, then requires full baseline equality.
7. If a foreign same-prefix route appears or an external NRPT, gateway
   or proxy change occurs, the process reports ROLLBACK_INCOMPLETE
   instead of deleting ambiguous objects or overriding someone else's
   changes. Repeated successful rollback is an idempotent no-op.
8. A sandbox-only MockTimeoutRecover action waits and starts a separate
   inspected rollback. It is NOT a real independently installed watchdog.

The SHA256 chain detects accidental/casual log corruption, but it is not
an authenticated signature. A same-account adversary could recompute
the entire chain. Likewise, an abrupt crash after an atomic world-file
replace but before its audit append can cause a digest mismatch that
blocks automatic recovery. This is deliberately fail-closed, not evidence
that production crash safety has been fully solved.

## Actual Windows fault-injection results

All final tests ran with Windows PowerShell 5.1 after strengthening the
fixture-global lock and ACL identity validation.

| Test group | Scope | Final result |
| --- | --- | --- |
| 1 | hard native deny; allowlist and protected ACL; durable plan/apply/rollback; repeat rollback; two different RUN_IDs contend for same lock; reject broad Authenticated Users permission; preserve borrowed routes; stale data | **11/11 PASS** |
| 2 | third-party route and NRPT conflicts; CIDR duplicate/overlap; 100th route-write failure; real writer process exit 77; separate-process durable recovery | **9/9 PASS** |
| 3 | foreign route/NRPT/proxy/gateway drift; mocked timeout and independent recovery; hash-chain corruption; missing journal; duplicate plans; tampered run ID/route identity | **12/12 PASS** |

**TOTAL: 32/32 PASS, all three process exit codes 0.**
Driver and test harness PowerShell AST parser: zero errors.
Both NativeApply and NativeRollback: hard-denied, exit 40.
The distinct Stage C P1 Python suite passed 23/23 and the P1B PowerShell
separate-process suite passed 26/26 earlier. None of those tests performs
a native Windows route insertion or implements true unattended failover.

## Known remaining gates — Stage C P1D

- A disposable and isolated Windows VM was not available via the known
  local VM management commands. Real New-NetRoute / Remove-NetRoute
  fault tests must not run on the user's primary Windows computer
  without separate explicit in-person authorization.
- Implement a native machine-wide single-writer lease, protected durable
  journal, native crash/restart test and route identity verification
  in that disposable VM before exposing any native Apply.
- Implement Stage C-specific return to original WinINET, WG, xray and
  NRPT states. Stage B's rollback alone cannot clear any Stage C-added
  CN routes.
- Test an actual independent local watchdog expiry before relying on
  unattended recovery. MockTimeoutRecover is only a simulation.
- Later request new, explicit and supervised approval for a tiny
  CN CIDR canary before attempting the full 5,494 routes.
- Keep all stacked PRs DRAFT and unmerged until these gates pass.

## Current stage fields

    STAGE_B_REAL_BASE_VPN=PASS_2026_10_18
    STAGE_C_P1C_PS_AST=0
    STAGE_C_P1C_WINDOWS_FILESYSTEM_MOCK=32_OF_32_PASS
    STAGE_C_P1C_ACL_PROTECTED=PASS
    STAGE_C_P1C_FIXTURE_WIDE_LOCK=PASS
    STAGE_C_P1C_HASH_CHAIN=PASS_IN_SIMULATION
    STAGE_C_P1C_HARD_EXIT_77_RECOVERY=PASS_IN_SIMULATION
    STAGE_C_P1C_TIMEOUT=MOCK_ONLY
    STAGE_C_NATIVE_APPLY=HARD_DISABLED_EXIT_40
    STAGE_C_NATIVE_ROLLBACK=HARD_DISABLED_EXIT_40
    STAGE_C_LIVE_AUTHORIZED=False
    PRIMARY=v2rayN/xray
    BACKUP=WireGuard_OFF
