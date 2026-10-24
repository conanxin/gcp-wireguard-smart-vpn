# Stage C P1 — SMART routing safety model (2026-10-24)

**Status:** CODE + READ-ONLY PLAN + OFFLINE MOCK VERIFIED. **No Windows SMART APPLY/ROLLBACK implementation is enabled.**

Stage B independently passed a short supervised real WireGuard handshake,
private DNS, WG-bound HTTPS and complete return to the xray system-proxy baseline on
2026-10-18. That **does not** constitute native CN SMART routing verification.

## Safety contract

- Normal Windows state: xray/v2rayN is primary; `ProxyEnable=1`,
  `ProxyServer=127.0.0.1:7897`; xray TUN is absent; WireGuard OFF.
- Never stop/restart xray or change WinINET/NRPT/routes/GCP in the P1 tools.
- Do not run the legacy `windows/smart-on.ps1` or `windows/smart-off.ps1`
  as a live Stage C transaction. `-DryRun` does **not** bypass the existing
  WireGuard and WinINET preflight failures.
- The 25 existing CN NRPT rules are correct and already match the current
  checked-in 12,160-namespace dataset. Future code **must not** remove and
  recreate them merely to claim a fresh installation.
- The user's previous approval covered the *specific* Stage B supervised test.
  Stage C LIVE modifications need new on-device, interruption-aware approval.
- Do not put secrets, WireGuard .conf files, private keys or personal route
  snapshots in a public Git commit.

## What was built

| Path | Function | Side effects |
| --- | --- | --- |
| `audit/stage-c-readonly-audit-20261023.ps1` | P0 baseline audit | No system writes |
| `audit/stage-c-p1-planonly-20261024.ps1` | Current Windows prestate fingerprints, borrowed/missing/colliding CN routes and NRPT resolver validation | No system writes |
| `audit/stage_c_p1_model.py` | Python stdlib pure in-memory transactional route ownership / proxy / WG / NRPT model | No Windows API calls |
| `audit/test_stage_c_p1.py` | Deterministic 23-case model fault-injection suite | No Windows API calls |

To run the **read-only Windows** preview (PowerShell 5.1):

```powershell
& "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
  -NoProfile -ExecutionPolicy Bypass `
  -File ".\audit\stage-c-p1-planonly-20261024.ps1"
```

To run the **offline model** on a Python 3.11+ host:

```bash
python3 audit/stage_c_p1_model.py --repo .
python3 audit/test_stage_c_p1.py
```

Both are **only** planning/simulating, not running a canary. Do not interpret
`P1_PLANONLY=PASS` or `PASS_MOCK_ONLY` as LIVE authorization.

## Observed Windows evidence (2026-10-24 09:39 +08)

- GCP tunnel service and adapter: `ABSENT`. xray process count 1, TUN
  `ABSENT`, WinINET proxy enabled to `127.0.0.1:7897`.
- Physical interface: WLAN, interface index 9 (observed, **not hard-coded**).
- Validated dataset: 5,494 APNIC China CIDRs and 12,160 CN NRPT namespaces.
- Missing CN routes on the physical interface: 5,494; borrowed: 0;
  conflicting prefixes: 0.
- Project NRPT: 25 rules, 12,160 namespace rows, 0 missing, 0 extra,
  0 resolver mismatch, 0 duplicate namespace rows.
- Exact prestate SHA256 from `stage-c-p1-planonly-20261024.ps1`:
  `B9B4D1ECD5D09B00DA9B8B05DF8BE7A33424A015238137ABEC08489516D05D61`
  (an **instantaneous observation**, not an approval token or a stable value).
- No Windows system or GCP network mutation was performed.

This current-state evidence is not a claim that all Chinese websites currently
bypass the xray system proxy. Native IP routing, NRPT and application-level
HTTP/SOCKS proxy selection are **separate** mechanisms.

## P1 mock safety invariants

1. **Planning is separate from mutation.** Canonical IPv4 networks are
   validated for alignment, duplication and overlap. NRPT is validated by
   namespace membership, rule identity, row duplication and NameServers,
   not just a rule count.
2. **Strong prestate check.** Route/NRPT/proxy/physical gateway/WG/xray/timer
   prestate hash must match the plan; any drift aborts before simulated writes.
3. **Ownership ledger.** A simulated newly-added route is recorded with
   `(prefix, interfaceIndex, nextHop, metric, store)`, plus its run ID.
   Pre-existing identical routes are classified as **borrowed** and cannot
   be removed by the run.
4. **No unjustified deletion.** If an unrelated route uses the same prefix
   or a collision appears during execution, the rollback deliberately
   reports **INCOMPLETE** rather than pretending it can identify ownership.
   Real Windows route objects do **not** provide a trustworthy per-script
   ownership tag. Full LIVE implementation must include serialized
   single-writer control, an append-only journal and a concurrency check.
5. **Proxy snapshot.** In the model the original enabled proxy and server
   are preserved. A simulated proxy-restore failure produces
   `ROLLBACK_INCOMPLETE`, never a PASS.
6. **NRPT is read-only during Stage C P1.** External resolver/rule changes
   cause INCOMPLETE and are never overwritten by a mock rollback.
7. **WG is separate.** The model simulates a target tunnel lifecycle but
   **never calls WireGuard, netsh, Set-NetRoute, Set-DnsClientNrptRule,
   registry changes or Windows services**.
8. **Hard failures are truthful.** Fault at route 100, gateway changes,
   timer timeout, proxy errors and duplicate attempts cannot write a
   success marker. Mock success requires return to an identical baseline.
9. **IPv4-only scope.** The model does not classify native IPv6, QUIC
   application proxying, browser-specific DoH, or processes with their
   own proxy settings.

## Verified fault injection (23/23)

Cases include: xray-only baseline; complete simulated on/off; borrowed route;
competing third-party route; xray TUN conflict; timer already armed; wrong
proxy endpoint; NRPT wrong server, missing/extra rules and duplicates;
100th route write failure with 99 precise rollbacks; initial proxy failure;
proxy restoration failure; foreign NRPT changes; physical gateway changes;
external same-prefix route during execution; timer expiry; stale snapshots;
repeat simulated run; previous WG already active; malformed/overlapping
CIDR inputs; and actual full-data 5,494-route plan consistency.

Results are **offline model verification**, not native Windows fault
injection or actual watchdog timeout testing.

## Required Gate before a P1B native writer

- Implement a standalone Windows Plan/Apply/Rollback architecture using an
  explicitly selected test RUN_ID. Keep P1 PlanOnly independent.
- Explicit user-approved live flow must have a *real independently armed*
  locally recoverable timeout, a safe order for WG startup, WinINET transition,
  CN route additions, and rollback.
- No live writer should launch unless both a current prestate hash and
  independently measured real Windows route/NRPT identities match.
- Journal every successful native route insertion **before proceeding to
  another batch**; no broad `Get-NetRoute | Remove-NetRoute` or destructive
  cleanup based solely on CIDR membership.
- Pre-existing routes must be preserved. Any conflicting route,
  gateway drift, stale plan, wrong NameServers, or inability to write the
  journal must fail closed. Do not delete project NRPT rules as a rollback
  shortcut when they existed before the run.
- The native Stage C return path must remove only run-owned routes, remove
  only the target WireGuard tunnel (if this run installed it), restore the
  original WinINET state, and verify pre-existing NRPT/xray/WLAN state.
- Test a **small canary** route set under user supervision before a
  5,494-route full apply. Never run the existing legacy SMART ON/OFF as a
  substitute for the P1B transaction.

## Gate values

```text
STAGE_B_REAL_WG_TEST=PASS_2026_10_18
STAGE_C_P0_READONLY=PASS
STAGE_C_P1_WINDOWS_PLANONLY=PASS
STAGE_C_P1_PYTHON_TESTS=23_OF_23_PASS
STAGE_C_P1_MODEL_MUTATORS=NONE
STAGE_C_NATIVE_APPLY=NOT_IMPLEMENTED
STAGE_C_NATIVE_ROLLBACK=NOT_IMPLEMENTED
STAGE_C_LIVE=NOT_AUTHORIZED
```
