# Stage C P1F — independent watchdog stranded TEST-NET native route

2026-10-24. Initial status: **PREPARED, native stranded-route scenario NOT YET RUN**.

The 2026-10-24 P1E user-supervised native test already demonstrated one
TEST-NET route add/select/immediate delete and poststate check. Its timer
fired on an *empty* route set. P1F explicitly distinguishes that idempotent
check from an independently observed **native route removal**.

P1F fixed destination: 198.51.100.77/32 (RFC 5737 TEST-NET-2).
No arbitrary route target, full CN data, WG install, xray, proxy,
NRPT, DNS, firewall, default route or GCP changes are allowed.

## Files

- audit/stage-c-p1f-watchdog-stranded-test-20261024.ps1:
  CheckOnly (read-only); Status (read-only); Run (requires elevated local
  admin + IAmAtThePC + SimulateParentCrash).
- audit/stage-c-p1f-independent-watchdog-20261024.ps1:
  fixed 120-second independent process; inspects unique exact native
  route before calling the PREVIOUSLY VERIFIED P1E exact rollback;
  records route-before, native rollback exit, route-after, baseline.
- audit/test-stage-c-p1f-preflight-20261024.ps1:
  15 non-mutating Windows PowerShell 5.1 AST/source/baseline/flag tests.
- docs/stage-c-p1f.md: this runbook.

The controller checks both the exact P1E script SHA256 and the independent
worker SHA256 before any run. P1E stays unchanged. The tested P1E script
checksum is:
36427E5BE890785AE37D4A81953CD4FFF7789153B8BF13C6CC6B4264E4ADA738

## Preflight and mock status

As of 2026-10-24 12:31 +08:
- Windows WG service absent, WG half-default route count=0.
- xray process 1, WinINET proxy 1:127.0.0.1:7897.
- Project NRPT=25, WLAN default gateway present.
- Target TEST-NET ActiveStore=0, PersistentStore=0.
- P1E previous run manifest ROLLBACK_VERIFIED.
- P1F CheckOnly exit 0, P1F Status NOT_STARTED.
- PowerShell 5.1 controller, worker, test AST errors=0.
- Nonmutating Windows test suite: 15/15 PASS.
- No native route was added in P1F test preparation.

These tests DO NOT certify the independent P1F worker has removed a
real stranded native route yet. That is the next local supervised gate.

## Local Windows supervised execution

Only with the user physically at the computer, two separate elevated
Administrator PowerShell windows, and acceptance of temporary network
risk. The prior Stage B/P1E authorizations do not permit unattended
repetition.

WINDOW 1 — emergency targeted rollback. Prepare but DO NOT RUN while
network is healthy:

    $ps = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    $project = Join-Path $env:USERPROFILE 'Documents\gcp-wireguard-smart-vpn'
    $legacy = Join-Path $project 'audit\stage-c-p1e-testnet-canary-20261024.ps1'
    & $ps -NoProfile -ExecutionPolicy Bypass -File $legacy -Mode Rollback

P1E Rollback only accepts an unambiguously identified open manifest and
removes a UNIQUE matching native 198.51.100.77/32 route by exact object.
It never performs broad CIDR deletion or resets the xray proxy.

WINDOW 2 — real single fixed native route test:

    $ps = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    $project = Join-Path $env:USERPROFILE 'Documents\gcp-wireguard-smart-vpn'
    $runner = Join-Path $project 'audit\stage-c-p1f-watchdog-stranded-test-20261024.ps1'
    & $ps -NoProfile -ExecutionPolicy Bypass -File $runner -Mode CheckOnly
    if ($LASTEXITCODE -eq 0) {
        & $ps -NoProfile -ExecutionPolicy Bypass -File $runner -Mode Run -IAmAtThePC -SimulateParentCrash
        "P1F_WRITER_CHILD_EXIT=$LASTEXITCODE"
    }

The elevated P1F writer creates an INTENT manifest BEFORE native route
insertion and arms an independent local child with a 120-second timer.
It verifies the worker PID and command line, the physical gateway and
the baseline again, then inserts only the fixed TEST-NET /32 in
ActiveStore with metric 171 and checks Windows Find-NetRoute.

It deliberately leaves the route present and ends its OWN child
PowerShell process with exit **77**. The user's OUTER Administrator
PowerShell window remains open. Exit 77 is an INTENTIONAL TEST SIGNAL,
not failure/success evidence by itself.

The independent watchdog must then see an exact route at its deadline.
It invokes the pinned P1E Rollback -RunId handler, confirms native
route removed, full original xray baseline restored, and records a
causally informative outcome.

READ-ONLY status command for any time after the run:

    $project = Join-Path $env:USERPROFILE 'Documents\gcp-wireguard-smart-vpn'
    $runner = Join-Path $project 'audit\stage-c-p1f-watchdog-stranded-test-20261024.ps1'
    & 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -NoProfile -ExecutionPolicy Bypass -File $runner -Mode Status

Do not call SMART ON/OFF or the full 5,494 CN route installers.

## Required P1F real PASS evidence

A complete PASS is possible only when all of these are observed in the
USER's real local elevated run and independently checked afterward:

- P1F_CHECK=PASS and previous target route count 0.
- P1F_WATCHDOG_ARMED=True and distinct worker PID.
- P1F_NATIVE_ROUTE_LEFT_PRESENT=True, real route identity fixed
  to TEST-NET /32, WLAN index/gateway and metric 171.
- Writer child actually exits 77.
- Worker reports outcome STRANDED_NATIVE_ROUTE_REMOVED_BY_WATCHDOG,
  routeCountBefore=1, routeCountAfter=0, nativeRollbackExit=0,
  nativeRouteRemovedByWatchdog=True, baselineRestored=True.
- P1F Status reports:
  P1F_RESULT=STRANDED_NATIVE_ROUTE_WATCHDOG_CLEANUP_PASS.
- Independent Windows read-only audit confirms both route stores empty,
  WG absent, no /1 routes, WLAN route, proxy=xray, NRPT25 and HTTPS204.
- Independent watchdog process no longer running.

If the worker reports IDEMPOTENT_EMPTY_ROUTE_AT_DEADLINE, even if CLEAN,
that does NOT establish actual stranded-route deletion.

If anything fails or the network behaves unexpectedly, do not retry.
Use Window 1 immediately, verify route absence and xray HTTPS204, and
report the exact console output. The one-shot worker is best effort and
cannot be guaranteed to survive total OS failure, suspension, reboot
or power loss. Manual recovery is therefore required.

## Stage boundary

    STAGE_C_P1F_PS_AST=0
    STAGE_C_P1F_READONLY_CHECKS=15_OF_15_PASS
    STAGE_C_P1F_NATIVE_STRANDED_WATCHDOG=PREPARED_NOT_RUN
    STAGE_C_P1F_ACTUAL_NATIVE_WATCHDOG_DELETE=NOT_TESTED
    STAGE_C_REAL_SMART_CN_IPV4=NOT_TESTED
    STAGE_C_FULL_5494_ROUTE_BATCH=NOT_AUTHORIZED
    PRIMARY=v2rayN/xray
    BACKUP=WireGuard_OFF

Keep all stacked GitHub pull requests DRAFT/unmerged until a separate
SMART CN-route-specific stage has passed real route and recovery gates.


## 2026-10-24 R1 real run aborted safely; verified root cause and R2 repair

**Real local Admin experiment R1 was NOT a P1F PASS.** Console output:
- CheckOnly PASS; independent 120-second worker successfully armed.
- One fixed TEST-NET ActiveStore route was added, but the new P1F
  controller returned NATIVE_POSTWRITE_ROUTE_IDENTITY_INVALID.
- P1E emergency exact rollback was immediately invoked by the parent,
  returning exit 0 and P1E_ROLLBACK=PASS. Run manifest ROLLBACK_VERIFIED.
- P1F writer returned BLOCKED_OR_INCOMPLETE (exit 4), NOT 77, and
  deliberately stranded route cleanup was not reached.
- Independent Windows recheck confirmed TEST-NET ActiveStore=0 and
  PersistentStore=0, WG service/adapter absent, half-default route count=0,
  WLAN default route intact, xray process=1, system proxy enabled
  127.0.0.1:7897, NRPT project count=25, xray HTTPS 204 / exit 0.
- Worker later emitted IDEMPOTENT_EMPTY_ROUTE_AT_DEADLINE, with before=0,
  after=0, native rollback exit=0 and baselineRestored=True. It did
  NOT remove a stranded native route; process then terminated.

**Exact root cause confirmed on the actual Windows Get-NetRoute CIM object:**
- The returned object has a Store property whose value is ActiveStore.
- It does NOT have a PolicyStore property.
- The original P1F controller and P1F worker incorrectly required
  Route.PolicyStore / Row.PolicyStore == ActiveStore.
- The successfully verified P1E source had supported either PolicyStore
  OR Store already, and that source remains unchanged.

**R2 repair:** Both P1F predicates now accept PolicyStore=ActiveStore
OR Store=ActiveStore, with no broadening to PersistentStore, mismatched
interface index or gateway. The controller updated the hard-pinned
independent worker SHA256. Read-only Status also explicitly classifies
the prior recovered abort as ABORTED_BEFORE_STRANDED_ROUTE_TEST_RECOVERED.

Windows PowerShell 5.1 *actual CIM route object* nonmutating regressions
now check BOTH predicates for:
- Positive match using real Store-only ActiveStore returned by Windows.
- Negative mismatched interface index.
- Negative PersistentStore route that must never be deleted.
Existing safe preflight / negative test gates remain intact.
**R2 nonmutating test result: 25/25 PASS, AST 0, exit 0**.

R2 has NOT been rerun under local Admin to add a real native route;
the stranded-watchdog branch remains NOT_TESTED until a separate
user-supervised R2 real console result and independent post-audit.
Never reinterpret R1's automatic emergency cleanup as P1F PASS.

R2 controller and worker source hashes (after the tested repair):
- controller SHA256: 8766502796F237348CEA735A3E850BB581EF97AB39893D82C9F0B6619A1784CC
- worker SHA256: 5D5EBB33EC466EDE17110911895DA953D62FAEBF5C850303DA51299C4002A9AD

**The original P1E emergency route rollback source remains pinned to
36427E5BE890785AE37D4A81953CD4FFF7789153B8BF13C6CC6B4264E4ADA738.**
