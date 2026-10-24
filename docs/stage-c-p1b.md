# Stage C P1B — Windows route transaction prototype (2026-10-24)

## Gate and scope

Status: **26/26 PowerShell 5.1 separate-process mock tests PASS.**
The production NativeApply and NativeRollback actions are **HARD DISABLED**,
and no live SMART network modification is approved or performed.

This package adds a Windows route-command adapter draft, a persisted
run-scoped mock plan and journal, and rollback fault injection. It does
NOT install WireGuard, alter the system proxy or NRPT, change routing,
deploy a watchdog, or implement an unattended failover workflow.

Stage B: real WireGuard base handshake, private DNS, WG-bound HTTPS and
return to xray passed on 2026-10-18. Stage C P1: Windows PlanOnly passed
and Python pure-model fault tests passed 23/23. See stage-c-p1.md.

## Package

- audit/stage-c-p1b-route-transaction.ps1
  - PlanOnly: invokes existing P1 Windows read-only planner.
  - MockPlan: takes a synthetic fixture under Windows TEMP, writes a
    persisted plan with prestate and desired-prefix hashes.
  - MockApply: executes only against fixture JSON, never Windows routes.
  - MockRollback: a separate PowerShell process uses the journal to
    remove only uniquely identified simulated routes, then checks the
    full original fixture fingerprint.
  - NativeApply / NativeRollback: return HARD_DISABLED_REVIEW_REQUIRED,
    exit code 40, before processing any fixture or invoking a route writer.
  - NativeAdd and NativeRemove are DRAFT helper definitions containing
    New-NetRoute / Remove-NetRoute syntax, NOT called by any P1B path.
    They are not tested and not a ready production implementation.
- audit/test-stage-c-p1b.ps1: isolated Windows fault tests (3 groups).
- docs/stage-c-p1b.md: this evidence and next-stage design gate.

## Running supported safe commands on Windows

    $base = Join-Path (Get-Location) 'audit'  # Run from the repository root
    $ps = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'

    & $ps -NoProfile -ExecutionPolicy Bypass -File "$base\stage-c-p1b-route-transaction.ps1" -Mode PlanOnly
    & $ps -NoProfile -ExecutionPolicy Bypass -File "$base\test-stage-c-p1b.ps1" -Group 1
    & $ps -NoProfile -ExecutionPolicy Bypass -File "$base\test-stage-c-p1b.ps1" -Group 2
    & $ps -NoProfile -ExecutionPolicy Bypass -File "$base\test-stage-c-p1b.ps1" -Group 3

Use only PlanOnly or test groups. Do not attempt production write modes;
the hard gate will reject them. Do not run legacy Windows smart-on.ps1
or smart-off.ps1 against the current xray-primary network.

## Mock transaction safety contract

1. Synthetic mock IO is restricted to an explicit Windows TEMP fixture
   folder named wg-stage-c-p1b-fixture-<random>. Immediate reparse-point
   directories are rejected; fixtures are removed by the test harness.
2. MockPlan rejects invalid/overlapping/duplicate IPv4 CIDRs, unexpected
   proxy, wrong NRPT resolver, active WG and foreign route collisions.
   Pre-existing physical routes are classified as BORROWED, not owned.
3. MockApply requires a prior matching saved plan and exact world/prefix
   hashes. Any changes between Plan and Apply abort before journaling.
4. Each route is recorded as INTENT in the run-specific JSON journal
   BEFORE simulated insertion, and VERIFIED only AFTER route identity
   has been rechecked. Temporary-file plus File.Replace writes use
   a real temporary backup path, required by the tested Windows runtime.
5. MockRollback runs in a separate PowerShell process and validates
   journal run ID, schema, original plan hash and allowed route prefixes.
   It reverses entries in order, matches prefix / ifIndex / nextHop /
   metric / store, preserves BORROWED routes and avoids deleting
   ambiguous or externally inserted route identities.
6. INTENT can represent either an interrupted pre-write or an
   interrupted post-write; the separate rollback checks the mock
   world before deciding whether removal is safe.
7. Changes by another actor to NRPT, physical gateway or proxy remain
   untouched, and such a mismatch yields ROLLBACK_INCOMPLETE rather
   than a fabricated PASS. Full baseline fingerprint equality is
   required for ROLLBACK_SIMULATION_PASS.
8. The test harness verifies that NativeApply and NativeRollback are
   blocked (exit 40), while the synthetic mock adapter cannot call the
   Windows route cmdlets. A mocked timeout is NOT a working real timer.

## Windows PowerShell 5.1 test evidence

Group 1: 8/8 PASS
- hard native Apply/Rollback gates
- outside-TEMP path blocked
- complete Plan/Apply/Rollback using separate processes
- repeated rollback is safe/idempotent
- BORROWED existing physical route remains unchanged
- stale mock world / edited desired prefixes blocked before journal

Group 2: 8/8 PASS
- third-party conflicting route rejected at preflight
- unexpected NRPT resolver or xray proxy rejected
- overlapped or duplicated route prefix rejected
- two ambiguous pre-existing physical routes rejected
- 100th simulated route write fails with 99 already verified;
  separate process rollback restores all, INTENT #100 not present
- simulated crash AFTER native-adapter-mock write but BEFORE
  journal confirmation is repaired by separate process

Group 3: 10/10 PASS
- new third-party route with same prefix during execution is
  preserved and produces ROLLBACK_INCOMPLETE
- external NRPT, gateway and proxy drift are not overwritten
- simulated timer timeout triggers a separate mock rollback
- missing journal, duplicate Apply, tampered journal run ID
  and tampered journal route identity all fail closed
- second Plan for an existing run is blocked

Final Windows totals: 26 tests; 26 PASS; 0 FAIL; each group exited 0.
PowerShell AST parser: driver 0 errors; harness 0 errors.
Native mode: hard blocked exit 40.
Earlier Python P1 fault suite: independent 23/23 PASS.
These two suites do not constitute 49 live Windows route tests.

Development bugs found and repaired before these final test runs:
- In PowerShell 5.1 a scalar PSCustomObject lacks the expected Count
  property, therefore exact route result variables are forced to arrays.
- System.IO.File.Replace on this Windows installation requires a
  non-null backup path; the mock journal now uses one.
- Plan/world hash comparison must happen before secondary environment
  gate errors so stale plans are reported accurately.

## Actual Windows PlanOnly observation

At 2026-10-24 10:02 CST:
- WG service/adapter absent; xray process 1, xray_tun absent.
- WinINET proxy enabled to 127.0.0.1:7897.
- Physical interface WLAN, index 9 (observed, not hard-coded).
- 5,494 planned CN IPv4 routes, 0 borrowed, 0 competing prefixes.
- 25 CN NRPT rules; all 12,160 namespaces present;
  missing=0, extra=0, wrong NameServers=0.
- No real route, WinINET, NRPT, DNS, WG, GCP or xray mutation.
- PlanOnly exit 0.
- Prestate fingerprint was
  B9B4D1ECD5D09B00DA9B8B05DF8BE7A33424A015238137ABEC08489516D05D61
  (point-in-time evidence only; not a durable approval or ownership proof).

## Explicitly not implemented or guaranteed

- The native Windows write helpers are not wired into an authorized
  production state machine, and neither has received native functional
  verification. Removing the hard gate alone would be unsafe.
- No protected durable native journal, live lease/lock, crash-restart
  supervisor, route native fault-injection test or independent real
  watchdog timeout gate is ready.
- The mock is not a proof of uniqueness where two independent writers
  create indistinguishable routes. A later implementation must serialize
  writes and fail closed on external concurrency or ownership ambiguity.
- The route transaction driver deliberately leaves real WireGuard,
  proxy and NRPT state untouched. Stage B rollback does not clean up
  Stage C route additions. A future Stage C-specific return sequence is
  required before live rollout.
- Only 150 routes were used to fault-test the 100th write. A real
  5,494-route native transaction remains untested for correctness,
  performance and recovery after termination.
- Windows IPv4 routing and NRPT do not cover application HTTP/SOCKS
  proxies, browser DoH, or IPv6 routes. SMART classification cannot
  guarantee every Chinese application exits directly.

## Next Gate: Stage C P1C (not approved yet)

1. Design and review a real Windows single-writer route lease and a
   persistent, access-controlled, append-only intent/verify journal.
2. Use a disposable Windows VM for actual native route insertion and
   recovery tests, including crashes between journal and route write.
3. Implement cross-layer restoration of original WinINET, WG and NRPT
   state; do not use broad CIDR deletion or legacy SMART OFF as a
   fallback shortcut.
4. Verify a local independent timeout rollback on a disposable system.
5. Seek fresh explicit, in-person approval for any real canary on the
   Windows primary computer; first test only a small selected prefix
   set, not all 5,494.
6. Keep this PR as Draft and the native gate closed until those
   preconditions pass.

## Gate fields

    STAGE_B_REAL_BASE_WG=PASS_2026_10_18
    STAGE_C_P1_PLANONLY=PASS
    STAGE_C_P1_PYTHON_MOCK=23_OF_23_PASS
    STAGE_C_P1B_PS_AST=0
    STAGE_C_P1B_SEPARATE_PROCESS_MOCK=26_OF_26_PASS
    STAGE_C_P1B_NATIVE_GATE=HARD_DISABLED_EXIT_40
    STAGE_C_REAL_ROUTE_APPLY=NOT_EXECUTED
    STAGE_C_REAL_ROUTE_ROLLBACK=NOT_EXECUTED
    STAGE_C_LIVE_APPROVED=False
    PRIMARY=xray_system_proxy
    BACKUP=WireGuard_OFF
