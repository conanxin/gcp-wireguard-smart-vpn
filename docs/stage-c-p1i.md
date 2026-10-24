# Stage C P1I — Windows native CIM evidence contract, read-only

**Date:** 2026-10-24, China Standard Time
**Final result:** P1I READ_ONLY PASS; Windows native CN route deletion / 5,494-route SMART LIVE still NOT TESTED and NOT AUTHORIZED.

P1I extends P1G (5,494-prefix read-only classification) and P1H (28/28 synthetic batch-recovery tests) without altering either implementation. P1F R3 previously demonstrated the independent watchdog could remove **one fixed TEST-NET /32** on Windows; that evidence is deliberately not generalized to arbitrary CN routes.

## Delivered

1. audit/stage-c-p1i-readonly-cim-20261024.ps1 — actual Windows PowerShell 5.1 Get-NetRoute CIM snapshot; read-only, output normalized JSON or a short human summary.
2. audit/stage_c_p1i_native_contract.py — Python 3.12 standard-library-only evidence inspector and native route identity contract. Reads input JSON; never calls native network/system modification APIs.
3. audit/test_stage_c_p1i_native_contract.py — 55 deterministic scenarios, including 5,494 native-shaped route fixtures.
4. audit/test-stage-c-p1i-readonly-windows-20261024.ps1 — reproducible Windows 5.1 end-to-end gate: two independent live CIM enumerations, Python inspection + 55 regressions, source command scan, native route/NRPT/proxy/WG before-after readback.
5. docs/stage-c-p1i.md — this operation and evidence record.

### Reproduce on Windows, no elevation required

Open an ordinary Windows PowerShell window:

~~~powershell
$project = Join-Path $env:USERPROFILE 'Documents\gcp-wireguard-smart-vpn'
$ps = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
& $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$project\audit\stage-c-p1i-readonly-cim-20261024.ps1" -Mode Human
& $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$project\audit\test-stage-c-p1i-readonly-windows-20261024.ps1"
~~~

WSL / Python standalone mock:

~~~bash
cd /mnt/c/Users/haili/Documents/gcp-wireguard-smart-vpn
python3 audit/test_stage_c_p1i_native_contract.py
~~~

The Windows runner writes only disposable UTF-8 JSON and stdout/stderr files beneath a randomly named %TEMP%\p1i-fixture-* directory, then cleans them. The observer writes the JSON directly as UTF-8 to snapshot-1.json and snapshot-2.json using a constrained OutputPath, because piping Unicode interface aliases through the Windows PowerShell console encoding damaged JSON in an earlier read-only attempt. Target paths outside a dedicated temp fixture and preexisting target files are rejected. It does **not** issue New-NetRoute, Remove-NetRoute, netsh, DNS/NRPT setters, WinINET writes, WireGuard start/stop, routing mode changes, or privileged actions. Frozen P1E/P1F scripts and legacy SMART ON/OFF are never invoked.

## Observed native CIM property contract

**Actual connected Windows 11 PowerShell 5.1** at approximately 17:05 CST:

| Field / observation | Directly observed |
|---|---|
| CIM class | MSFT_NetRoute |
| CIM namespace | ROOT/StandardCimv2 |
| Get-NetRoute query flag | -PolicyStore ActiveStore |
| Actual returned CIM property | Store = ActiveStore |
| Returned object contains PolicyStore property | **False** |
| Primary physical default route | WLAN, interface index 9, gateway 192.168.0.1 |
| Sample protocol | NetMgmt |
| Current ActiveStore objects | 24 |
| Current PersistentStore objects | 0 (empty query returns a typed NotFound; other errors are not suppressed) |
| TEST-NET 198.51.100.77/32 leftovers | 0 |
| WinINET system proxy / NRPT | xray system proxy enabled at 127.0.0.1:7897; NRPT 25 |
| WireGuard | Tunnel service absent |

The old P1F mistake was to assume the returned route object contains PolicyStore. It does not on this machine: **PolicyStore is a cmdlet query parameter, while Store is the returned CIM field.** The new PowerShell adapter explicitly converts the typed Store enum to the canonical strings ActiveStore or PersistentStore; a numeric Store and missing/contradictory values are rejected by the Python native contract. A correctly absent PersistentStore is not confused with a generic read/query failure.

Native exact candidate identity in the P1I evidence model includes:
- Store and DestinationPrefix (strict canonical IPv4 CIDR)
- InterfaceIndex, NextHop, RouteMetric
- CompartmentId and Protocol

InstanceID is captured **for diagnostics only**. It may change on re-enumeration and is not an ownership marker. InterfaceAlias and lifetime likewise cannot establish run ownership. P1H's synthetic simOwnerToken field is ignored in native evidence matching because Windows does not expose a corresponding durable custom owner token in Get-NetRoute.

## Three-snapshot plus receipt adjudication

P1I inspects a **before**, **post**, and **current** route snapshot, together with a frozen run ID, source SHA256, batch index, expected route and staged receipt flags. This is a pure evidence model: it does not perform the imagined write.

- Preexisting same-prefix route: PREEXISTING_PREFIX_NOT_OWNED; **never adopt**.
- Two routes with the same prefix, conflicting PersistentStore, wrong interface/hop/metric/compartment/protocol: **block**.
- Intent persisted, route visible, but missing native call response or post-read receipt: crash-gap / unproven ownership, **block**.
- Route identity unchanged after re-enumeration, even when InstanceID changes, and receipts appear complete: **EXACT_ROUTE_WITNESSED_OWNERSHIP_UNPROVEN**. Reviewable evidence only; STILL NO deletion permission.
- Receipt says rollback completed but route remains: **block**. Snapshot says route absent: no native deletion needed; does not prove the former controller caused the absence.
- Unexpected unrelated route, NRPT, proxy, WG, WLAN index/gateway or other environment drift: **block** the entire batch review before any deletion.
- All reports always set nativeApplyAuthorized=false, nativeDeleteAuthorized=false, networkMutationsPerformed=false. The tool has **no code path** that invokes native route writes/deletions.

Most importantly, even a perfect pre-absence/intent/native-return/post-read/current identity chain cannot rule out an indistinguishable concurrent third-party route insertion. Therefore **native route ownership remains UNPROVEN**, not upgraded to “safe to remove” merely because the fields match.

## Actual test evidence, 2026-10-24

| Test | Verified result |
|---|---|
| WSL Python 3.12.3 offline regression | 55/55 PASS, 0 failed |
| Native Windows Python 3.12.10 offline regression | 55/55 PASS, 0 failed |
| Windows PowerShell 5.1 snapshot script AST | 0 errors |
| Repeatable Windows end-to-end read-only harness | **9/9 PASS**, exit 0 |
| Independent native CIM snapshot #1 and #2 | Native normalized route identity digests equal |
| Native CIM/Python interoperability | READ_ONLY_NATIVE_CIM_INSPECTED, Store correctly resolved, PolicyStore property absent |
| Native full-scale read-only test | 5,494 route-shaped synthetic witnesses grouped into 11 batches: 5,494 identities matched; 5,494 ownership proofs absent; 0 native delete permissions |
| Windows route table SHA256 before / after | 49776CA3C6DAACFF8797D4770280C2DFAAD854B1CA1506A67B221E58CD9B825C — unchanged |
| NRPT / WinINET / WireGuard before / after | Unchanged, NRPT 25; WG service 0; xray process 1 |
| Native Windows route writes | ZERO |

There are **two different digests**: the native RouteHash from the Windows gate includes the existing project's baseline comparison format; the P1I normalized identity digest additionally includes protocol and compartment, and ignores unstable InstanceID. They are not intended to have equal hash strings; each is compared only against its own repeated enumeration.

### Evidence limitations

- Windows operating system reboot, power loss, and route deletion on actual CN prefixes have not been tested.
- The 5,494 records in the contract test are **synthetic native-shaped observations**, not installed Windows routes. Their full-scale processing time is not native routing performance.
- A source SHA256 in a fixture is a declared evidence value, not an independently cryptographically attested route write. The test file does not trust it as proof of ownership.
- The P1H fixture token, native InstanceID and route-matching predicates cannot distinguish a concurrent identical external insertion.
- These read-only proofs are not an approval to run legacy smart-on.ps1 / smart-off.ps1 or install 5,494 CN IPv4 routes. The original CN source snapshot remains dated 2026-09-05.

## Next proposed stage P1J — still read-only / mock-only

Reconcile a durable native write witness with OS-level limitations in an isolated model: detect crash windows between intended write, native call, postread and committed receipt; prove failure behavior under concurrent identical insertions, interface changes, repeated native enumeration and partial batch recovery. A future tiny supervised TEST-NET route micro-canary is separate and requires renewed explicit local authorization and a prepared manual recovery path; **not authorized by this P1I work**.

Stage boundary: P1I_NATIVE_CIM_READ_ONLY=PASS; P1I_NATIVE_OWNERSHIP_UNAMBIGUOUS=NOT_PROVEN; P1I_NATIVE_DELETE_AUTHORIZED=False; FULL_CN_SMART_LIVE=NOT_TESTED; PRIMARY=v2rayN/xray.
