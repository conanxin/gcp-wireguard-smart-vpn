# Stage C P1D — isolated VM readiness and read-only crash recovery

2026-10-24. **P1D test artifacts are complete, but NativeApply/NativeRollback remain HARD BLOCKED.**

This stage did not test actual Windows OS route modifications, did not install WireGuard, and did not change xray, WinINET, NRPT, DNS, firewall, GCP or user network routes. The 2026-10-18 supervised Stage B WireGuard test remains the only completed real VPN connection/return test.

## Deliverables

- audit/stage-c-p1d-vm-gate-20261024.ps1 — read-only Windows virtualization, memory and VM tool availability preflight. Its NativeCanary mode is deliberately hard disabled, exit 60.
- audit/stage_c_p1d_recovery_audit.py — Python stdlib READ-ONLY verification of synthetic P1C persisted plan/world/journal and append-only SHA256 audit.
- audit/test_stage_c_p1d_recovery_audit.py — 16 fault-injection unit cases with ephemeral synthetic fixtures.
- docs/stage-c-p1d.md — this evidence and next-stage gate.

## Windows VM environment facts (2026-10-24 10:49 +08)

Windows CIM reported Windows 10 Home build 19045, Intel Core i7-6700, 15.88 GB physical RAM and approximately 1.03 GB free at final audit. No Get-VM, VBoxManage.exe, vmrun.exe or QEMU management command was discovered. Win32_ComputerSystem returned HypervisorPresent=True, whereas processor WMI virtualization-firmware and SLAT flags returned False. These contradictory/incomplete data points DO NOT prove VM capability is unavailable or that an isolated VM exists; an externally verifiable Windows guest identity and rollback snapshot were NOT found. Windows optional-feature queries previously lacked adequate access and do not prove feature absence.

**VM_TEST_READINESS=BLOCKED_UNVERIFIED_ISOLATION.** Low free RAM alone would make starting a new Windows guest risky. No VM was launched, no Windows features changed or installed, and no BIOS/virtualization settings modified. NativeCanary exit 60 verifies refusal, not the safety of any real route operation.

To recheck read-only, run from project root:

    $ps = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    & $ps -NoProfile -ExecutionPolicy Bypass -File (Join-Path (Get-Location) 'audit\stage-c-p1d-vm-gate-20261024.ps1') -Mode Audit

## P1D read-only journal audit

Example for a synthetic P1C fixture only:

    python3 audit/stage_c_p1d_recovery_audit.py --fixture "PATH_TO_P1C_SYNTHETIC_FIXTURE" --run-id "EXAMPLE-001"

The tool does not invoke PowerShell, Windows network commands, GCP or any mutator. It checks:
1. Monotonic event sequence, prev/hash SHA256 chain, RUN_ID and allowlisted filename;
2. Last committed file digests against actual bytes on disk;
3. Saved mock plan schema, desired prefix SHA256 and journal/run agreement;
4. Exact mock route identities, borrowed route protection and competing same-prefix entries;
5. Whether removing *hypothetically* the unique owned mock routes would reconstruct the full original synthetic world fingerprint.

Classifications:
- MOCK_PLAN_ONLY: saved plan without apply journal.
- MOCK_RECOVERY_CANDIDATE_READONLY: synthetic owned routes appear uniquely recoverable; NO actual rollback is performed or authorized.
- MOCK_ALREADY_RESTORED: full synthetic world is back at the original fingerprint.
- MOCK_MANUAL_REVIEW_REQUIRED: third-party route collision, modified NRPT/proxy/gateway or other uncertain simulated state.
- BLOCKED: corrupt/truncated audit, inconsistent journal/plan or unsafe synthetic files.

The analyzer always outputs native_rollback_authorized=false, live_canary_authorized=false and native_windows_routes_were_mutated=false. It cannot independently verify NTFS ACLs. A candidate decision is NOT production readiness.

## Tests and Windows integration

Run Python tests from repo root:

    python3 audit/test_stage_c_p1d_recovery_audit.py

**16/16 PASS**. These cover valid plan-only state, unique owned mock route, completed rollback, corrupted audit event, modified world bytes, interrupted write before audit append, foreign same-prefix route, changed NRPT, mismatched journal/plan, altered prefix source, borrowed route incorrectly marked owned, invalid run ID, truncated audit, unsafe filename, duplicate exact route and deliberate refusal to claim native authorization.

A separate integration test used the unchanged Windows P1C sandbox source:
1. An ACL-protected P1C synthetic fixture was created under LocalAppData, with two target CIDRs. MockPlan returned exit 0.
2. MockApply with HardCrashAfterRoute=1 caused a REAL Windows PowerShell child process to exit 77 after changing one synthetic route-file object.
3. The new P1D Python analyzer read the ACTUAL Windows P1C journal and returned MOCK_RECOVERY_CANDIDATE_READONLY, one owned candidate, exit 0.
4. Another Windows PowerShell process ran the P1C MockRollback, returning BASELINE_RESTORED=True, exit 0, and changed synthetic files only.
5. P1D then returned MOCK_ALREADY_RESTORED, zero candidates, exit 0.
6. Synthetic integration folders were explicitly cleaned after verifying results.

Thus P1D interoperates with actual P1C Windows filesystem journals, but this does NOT imply native New-NetRoute/Remove-NetRoute was run.

## Unresolved crash window and security boundaries

The P1C write order replaces the mockworld JSON then appends a committed digest record to the audit. A crash in between can leave a new world with the last audit record pointing to the old bytes. P1D deliberately blocks recovery and reports a digest mismatch. This avoids unsafe deletion but means arbitrary power-loss recovery is NOT fully solved.

The SHA256 audit chain is not an authenticated signature and can be recomputed by an adversary with the same user's write permissions. It is adequate only as limited accident/casual-corruption detection.

An isolated Windows guest with an EXTERNALLY VERIFIED snapshot, machine-wide route ownership controls, protected native journal and a real independent timeout rollback is required before Stage C NativeApply can be considered. The Stage B rollback is insufficient to remove any future Stage C-added CN routes. Any live canary on the primary computer requires fresh, explicit and on-site user approval.

## Final gates

    P1D_VM_READONLY_AUDIT=PASS
    P1D_VERIFIED_DISPOSABLE_WINDOWS_VM=NO
    P1D_VM_AVAILABLE_RAM_GT_4GB=NO
    P1D_NATIVE_CANARY=HARD_DISABLED_EXIT_60
    P1D_PYTHON_RECOVERY_AUDIT=16_OF_16_PASS
    P1D_P1C_REAL_SUBPROCESS_EXIT77_INTEGRATION=PASS_SYNTHETIC_ONLY
    P1D_P1C_SYNTHETIC_RECOVERY=PASS
    P1D_NATIVE_WINDOWS_ROUTE_WRITE=NOT_TESTED
    P1D_NATIVE_WINDOWS_ROUTE_ROLLBACK=NOT_TESTED
    P1D_REAL_WATCHDOG_EXPIRY=NOT_TESTED
    STAGE_C_LIVE=NOT_AUTHORIZED
    PRIMARY=xray_system_proxy
    BACKUP=WireGuard_OFF
