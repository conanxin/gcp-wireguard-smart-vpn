# Stage C P1E — crash-gap reconciliation and supervised TEST-NET micro-canary

Date: 2026-10-24. Two independent workstreams. Neither is a SMART VPN production release.

## A. Synthetic audit crash-gap recovery

Files:
- audit/stage_c_p1e_gap_reconcile.py
- audit/test_stage_c_p1e_gap_reconcile.py

The P1C mock journal saves an INTENT before updating a simulated route
file, then adds a checksum-chain event. A crash between the file
replacement and audit event append would previously cause P1D to
BLOCK the automatic mock rollback.

P1E now identifies precisely this synthetic-only gap. The audit chain
must itself be intact. Only mockworld.json may have an unlogged digest
change. Exactly one outstanding INTENT must correspond to a unique
route. The plan, journal, route identity, DNS/proxy/gateway snapshot
and prestate fingerprint must all agree. Any competing same-prefix
route, corrupted event chain, changed NRPT/proxy/gateway or different
unlogged file forces BLOCKED.

Explicit repair-mock-audit mode appends only the missing synthetic
world-digest event. It does not remove a route or modify any Windows
network state. The original P1C MockRollback can subsequently clean
the synthetic mockworld and P1D can classify it as restored.

Python 3.12.3 tests: **18/18 PASS**. A Windows P1C integration also
succeeded: MockPlan; actual PowerShell child exit 77 after synthetic
route write; simulated removal of the last world-digest event to
reproduce the precise crash gap; P1E read-only identified the gap;
P1E repaired the mock audit; original P1C independent MockRollback
reported BASELINE_RESTORED=True; P1D reported MOCK_ALREADY_RESTORED.
The test-created fixture was narrowly deleted.

A SHA256 event chain is not authenticated against a same-account
attacker. The P1E gap repair is a test-specific reconciliation model:
it does not solve arbitrary concurrent file writes, unexpected power
loss, or OS-native route crash recovery.

## B. One fixed real Windows RFC5737 TEST-NET route canary

Files:
- audit/stage-c-p1e-testnet-canary-20261024.ps1
- audit/test-stage-c-p1e-preflight-20261024.ps1

The canary fixes the destination at 198.51.100.77/32, a single host
address within RFC 5737 TEST-NET-2. It cannot accept arbitrary
destination CIDRs. It does not implement CN SMART routing or start
WireGuard. It does not modify WinINET, xray, NRPT, DNS, GCP, firewall
or the default route. ActiveStore is explicit (nonpersistent).

Current measured Windows read-only baseline:
- WireGuard tunnel service/adapter absent; WG half-default route count 0.
- xray running with WinINET ProxyEnable=1, ProxyServer=127.0.0.1:7897.
- Existing 25 project NRPT rules unchanged.
- Physical WLAN default gateway present.
- 198.51.100.77/32 absent from ActiveStore/PersistentStore.
- HTTPS over the existing xray proxy returns 204.
- Windows PowerShell 5.1 AST: 0 errors.
- CheckOnly: PASS, exit 0.
- Non-mutating safety smoke: 9/9 PASS.
- Remote CXRE session is NONADMIN and never ran a native route write.

### Human-controlled test execution

Only while the user is physically at the computer, in an elevated
local Administrator PowerShell window, with another elevated
PowerShell window already open for emergency recovery.

First window, emergency rollback (do NOT run it while test is healthy):

    $ps = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    $p = 'C:\Users\haili\Documents\gcp-wireguard-smart-vpn\audit\stage-c-p1e-testnet-canary-20261024.ps1'
    & $ps -NoProfile -ExecutionPolicy Bypass -File $p -Mode Rollback

Second window, test (only after physically preparing the backup window):

    $ps = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    $p = 'C:\Users\haili\Documents\gcp-wireguard-smart-vpn\audit\stage-c-p1e-testnet-canary-20261024.ps1'
    & $ps -NoProfile -ExecutionPolicy Bypass -File $p -Mode CheckOnly
    if ($LASTEXITCODE -eq 0) {
        & $ps -NoProfile -ExecutionPolicy Bypass -File $p -Mode Run -IAmAtThePC
    }

The Run mode performs another baseline preflight under Admin rights.
It persists a unique per-run INTENT before touching any native route;
starts an independent elevated PowerShell process with a 150-second
watchdog; verifies its armed marker, PID and process command line; and
rechecks that the watchdog is still alive with adequate time left.
Only THEN does it attempt ONE exact ActiveStore New-NetRoute to
198.51.100.77/32 using the currently observed WLAN interface/gateway,
route metric 171. It checks the newly inserted exact route and Windows
Find-NetRoute selection, and then immediately removes the exact
route via its actual Get-NetRoute object, verifying its absence
and rechecking xray baseline.

If the parent exits after route creation and before journal verification,
the saved INTENT gives the independent one-shot timer a narrowly
defined rollback target. The helper checks full route identity before
removal; it fails closed if any route identity is ambiguous or stale.
It also refuses to remove a matching route reintroduced after
rollback was already verified.

The standalone timer is a best-effort process-based failsafe,
not a reboot-persistent watchdog and not guaranteed to survive
Windows suspension or a total OS failure. Keep the manual emergency
window available. Do NOT repeatedly run the test after any error.
The route is documentation-only, not an actual CN IP test.

### Meaningful real canary success criteria

    P1E_WAL_INTENT_SAVED=True
    P1E_WATCHDOG_ARMED=True
    P1E_NATIVE_ROUTE_ADDED=True
    P1E_ROUTE_SELECTED=True
    P1E_IMMEDIATE_ROLLBACK=PASS
    P1E_FINAL_TARGET_ROUTE_COUNT=0
    P1E_XRAY_HTTP_CODE=204
    P1E_TEST_RESULT=PASS

All of these must come from the USER'S real elevated Windows
PowerShell result. A read-only CheckOnly PASS does NOT establish
the native route add/remove succeeded. If run fails, investigate
the actual state and do not rerun without a fresh safety check.

## Gate values at publication

    P1E_SYNTHETIC_GAP_REPAIR_TEST=18_OF_18_PASS
    P1E_WINDOWS_P1C_SYNTHETIC_INTEGRATION=PASS
    P1E_FIXED_TESTNET_CANARY_AST=0
    P1E_FIXED_TESTNET_READONLY_SMOKE=9_OF_9_PASS
    P1E_NATIVE_TESTNET_ROUTE=NOT_YET_EXECUTED
    P1E_REAL_WATCHDOG_TIMEOUT=NOT_YET_EXECUTED
    P1E_CN_SMART_ROUTE=NOT_TESTED
    P1E_FULL_5494_ROUTE_INSTALL=NOT_AUTHORIZED
    PRIMARY=v2rayN/xray
    BACKUP=WireGuard_OFF

This document is a controlled experiment runbook, not an automation
deployment or permission to install all 5,494 CN routes.
