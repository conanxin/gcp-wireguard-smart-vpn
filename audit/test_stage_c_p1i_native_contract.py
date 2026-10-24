#!/usr/bin/env python3
"""P1I pure evidence-contract regressions: never touches native routes."""
from __future__ import annotations

import ast
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))
from stage_c_p1i_native_contract import (  # noqa: E402
    InvalidEvidence, assess_scenario, parse_snapshot, _digest_route_keys,
)

RUN_ID = "abcdef0123456789abcdef0123456789"
DATA_SHA = "a" * 64
ENV = {
    "PhysicalDefaultCount": 1, "PhysicalInterfaceIndex": 9,
    "PhysicalNextHop": "192.168.0.1", "WinINETProxyEnable": 1,
    "WinINETProxyServer": "127.0.0.1:7897", "NRPTCount": 25,
    "WGServiceCount": 0, "XrayProcessCount": 1, "HalfDefaultRouteCount": 0,
}
TARGET = "10.20.0.0/16"


def route(prefix: str = TARGET, *, idx: int = 9, hop: str = "192.168.0.1",
          metric: int = 5, store: str = "ActiveStore", protocol: str = "NetMgmt",
          compartment: int = 1, instance: str = "ephemeral-A") -> dict:
    return {
        "DestinationPrefix": prefix, "InterfaceIndex": idx,
        "NextHop": hop, "RouteMetric": metric, "Store": store,
        "Protocol": protocol, "CompartmentId": compartment,
        "InstanceID": instance, "InterfaceAlias": "WLAN",
        "simOwnerToken": "P1H_FAKE_TOKEN_IS_NOT_NATIVE_EVIDENCE",
    }


def snapshot(rows=(), environment: dict | None = None) -> dict:
    all_rows = deepcopy(list(rows))
    active = [r for r in all_rows if r["Store"] == "ActiveStore"]
    persistent = [r for r in all_rows if r["Store"] == "PersistentStore"]
    return {
        "schema": "stage-c-p1i-native-cim-snapshot-v1",
        "nativeAccess": "READ_ONLY_GET", "cmdlet": "Get-NetRoute",
        "networkMutationsPerformed": False, "nativeWriteAuthorized": False,
        "activeRoutes": active, "persistentRoutes": persistent,
        "activeRouteCount": len(active), "persistentRouteCount": len(persistent),
        "environment": deepcopy(ENV if environment is None else environment),
        "cimClass": "MSFT_NetRoute",
        "sampleStoreString": "ActiveStore",
        "sampleHasPolicyStoreProperty": False,
    }


def witness(prefix=TARGET, **override) -> dict:
    r = route(prefix)
    row = {key: r[key] for key in (
        "DestinationPrefix", "InterfaceIndex", "NextHop", "RouteMetric",
        "Store", "Protocol", "CompartmentId",
    )}
    row.update({
        "runId": RUN_ID, "batch": 1,
        "phase": "POSTREAD_VERIFIED",
        "intentPersisted": True, "nativeCallReturned": True,
        "postReadVerified": True,
    })
    row.update(override)
    return row


def scenario(*, before=None, post=None, current=None, entries=None,
             batch_size=2, env=None) -> dict:
    default = route("0.0.0.0/0", metric=0, protocol="NetMgmt", instance="default")
    before = before if before is not None else [default]
    post = post if post is not None else [default, route()]
    current = current if current is not None else [default, route(instance="re-enumerated")]
    return {
        "schema": "stage-c-p1i-native-evidence-fixture-v1",
        "runId": RUN_ID, "datasetSHA256": DATA_SHA,
        "batchSize": batch_size, "entries": deepcopy(entries if entries is not None else [witness()]),
        "before": snapshot(before), "post": snapshot(post),
        "current": snapshot(current, env),
    }


class NativeContractTests(unittest.TestCase):
    def classification(self, s: dict, expected: str, blocked: bool = True) -> dict:
        r = assess_scenario(s)
        self.assertEqual(r["claims"][0]["classification"], expected)
        self.assertEqual(r["nativeDeleteAuthorized"], False)
        self.assertEqual(r["nativeApplyAuthorized"], False)
        self.assertEqual(r["networkMutationsPerformed"], False)
        self.assertEqual(r["blockedWitnesses"] > 0, blocked)
        return r

    def invalid(self, s: dict, expected: str) -> None:
        with self.assertRaisesRegex(InvalidEvidence, expected):
            assess_scenario(s)

    def test_01_exact_identity_is_review_only_never_native_delete(self):
        r = self.classification(scenario(),
            "EXACT_ROUTE_WITNESSED_OWNERSHIP_UNPROVEN", blocked=False)
        self.assertEqual(r["reviewOnlyWitnesses"], 1)

    def test_02_reenumeration_changes_instanceid_not_route_identity(self):
        r = self.classification(scenario(),
            "EXACT_ROUTE_WITNESSED_OWNERSHIP_UNPROVEN", False)
        self.assertEqual(r["nativeReEnumerationInstanceIdChanges"], 1)

    def test_03_reordered_native_routes_stable_digest(self):
        d = route("0.0.0.0/0", metric=0, instance="foo")
        t = route(instance="bar")
        first = parse_snapshot(snapshot([d, t]))
        second = parse_snapshot(snapshot([t, d]))
        self.assertEqual(first["routeIdentityDigest"], second["routeIdentityDigest"])

    def test_04_matching_policy_store_alias_may_be_present(self):
        s = scenario()
        for moment in ("post", "current"):
            s[moment]["activeRoutes"][1]["PolicyStore"] = "ActiveStore"
        self.classification(s, "EXACT_ROUTE_WITNESSED_OWNERSHIP_UNPROVEN", False)

    def test_05_no_policy_store_native_property_is_normal(self):
        s = snapshot([route("0.0.0.0/0", metric=0)])
        self.assertFalse(s["sampleHasPolicyStoreProperty"])
        self.assertEqual(parse_snapshot(s)["countActive"], 1)

    def test_06_missing_store_but_policy_store_present_rejected(self):
        s = scenario()
        r = s["post"]["activeRoutes"][1]
        del r["Store"]
        r["PolicyStore"] = "ActiveStore"
        self.invalid(s, "NATIVE_CIM_FIELDS_INCOMPLETE")

    def test_07_numeric_cim_store_not_accepted(self):
        s = scenario()
        s["post"]["activeRoutes"][1]["Store"] = 1
        self.invalid(s, "INVALID_CIM_STORE")

    def test_08_contradictory_store_and_policy_store_rejected(self):
        s = scenario()
        s["post"]["activeRoutes"][1]["PolicyStore"] = "PersistentStore"
        self.invalid(s, "STORE_POLICY_STORE_CONTRADICTION")

    def test_09_preexisting_exact_route_never_adopted(self):
        s = scenario()
        s["before"]["activeRoutes"].append(route())
        s["before"]["activeRouteCount"] += 1
        self.classification(s, "PREEXISTING_PREFIX_NOT_OWNED")

    def test_10_preexisting_nonmatching_route_also_blocked(self):
        s = scenario()
        s["before"]["activeRoutes"].append(route(metric=99))
        s["before"]["activeRouteCount"] += 1
        self.classification(s, "PREEXISTING_PREFIX_NOT_OWNED")

    def test_11_postread_duplicate_exact_prefix_blocked(self):
        s = scenario()
        s["post"]["activeRoutes"].append(route(instance="other"))
        s["post"]["activeRouteCount"] += 1
        self.classification(s, "DUPLICATE_TARGET_PREFIX")

    def test_12_current_duplicate_exact_prefix_blocked(self):
        s = scenario()
        s["current"]["activeRoutes"].append(route(instance="other"))
        s["current"]["activeRouteCount"] += 1
        self.classification(s, "DUPLICATE_TARGET_PREFIX")

    def test_13_persistent_post_collision_blocked(self):
        s = scenario()
        s["post"]["persistentRoutes"].append(route(store="PersistentStore"))
        s["post"]["persistentRouteCount"] = 1
        self.classification(s, "PERSISTENT_PREFIX_CONFLICT")

    def test_14_persistent_current_collision_blocked(self):
        s = scenario()
        s["current"]["persistentRoutes"].append(route(store="PersistentStore"))
        s["current"]["persistentRouteCount"] = 1
        self.classification(s, "PERSISTENT_PREFIX_CONFLICT")

    def test_15_persistent_before_collision_blocked(self):
        s = scenario()
        s["before"]["persistentRoutes"].append(route(store="PersistentStore"))
        s["before"]["persistentRouteCount"] = 1
        self.classification(s, "PERSISTENT_PREFIX_CONFLICT")

    def test_16_interface_mismatch_blocked(self):
        s = scenario()
        s["current"]["activeRoutes"][1]["InterfaceIndex"] = 12
        self.classification(s, "NATIVE_IDENTITY_DRIFT")

    def test_17_next_hop_mismatch_blocked(self):
        s = scenario()
        s["current"]["activeRoutes"][1]["NextHop"] = "10.1.1.1"
        self.classification(s, "NATIVE_IDENTITY_DRIFT")

    def test_18_metric_mismatch_blocked(self):
        s = scenario()
        s["current"]["activeRoutes"][1]["RouteMetric"] = 9
        self.classification(s, "NATIVE_IDENTITY_DRIFT")

    def test_19_protocol_mismatch_blocked(self):
        s = scenario()
        s["current"]["activeRoutes"][1]["Protocol"] = "Local"
        self.classification(s, "NATIVE_IDENTITY_DRIFT")

    def test_20_compartment_mismatch_blocked(self):
        s = scenario()
        s["current"]["activeRoutes"][1]["CompartmentId"] = 10
        self.classification(s, "NATIVE_IDENTITY_DRIFT")

    def test_21_missing_durable_intent_blocked(self):
        s = scenario(entries=[witness(intentPersisted=False)])
        self.classification(s, "MISSING_DURABLE_INTENT")

    def test_22_intent_crash_gap_with_still_present_route_blocked(self):
        s = scenario(entries=[witness(phase="INTENT", nativeCallReturned=False,
                                      postReadVerified=False)])
        self.classification(s, "UNRESOLVED_INTENT_WITH_ROUTE")

    def test_23_planned_route_absent_is_harmless_but_no_delete(self):
        default = route("0.0.0.0/0", metric=0)
        s = scenario(post=[default], current=[default],
                     entries=[witness(phase="PLANNED", nativeCallReturned=False,
                                      postReadVerified=False)])
        self.classification(s, "ABSENT_NO_NATIVE_DELETE_NEEDED", False)

    def test_24_missing_native_call_receipt_blocked(self):
        s = scenario(entries=[witness(nativeCallReturned=False)])
        self.classification(s, "MISSING_NATIVE_CALL_RESULT")

    def test_25_missing_postread_receipt_blocked(self):
        s = scenario(entries=[witness(postReadVerified=False)])
        self.classification(s, "CRASH_GAP_MISSING_POSTREAD")

    def test_26_api_returned_but_falsely_postread_verified_phase_blocked(self):
        s = scenario(entries=[witness(phase="API_RETURNED")])
        self.classification(s, "RECEIPT_PHASE_INCONSISTENT")

    def test_27_rollback_intent_with_route_present_blocked(self):
        s = scenario(entries=[witness(phase="ROLLBACK_INTENT")])
        self.classification(s, "ROLLBACK_GAP_PRESENT_OWNERSHIP_UNPROVEN")

    def test_28_rollback_intent_with_route_absent_still_uncertain(self):
        default = route("0.0.0.0/0", metric=0)
        s = scenario(current=[default], entries=[witness(phase="ROLLBACK_INTENT")])
        self.classification(s, "ROLLBACK_GAP_NO_TARGET")

    def test_29_rolled_back_and_absent_is_closed_with_no_delete(self):
        default = route("0.0.0.0/0", metric=0)
        s = scenario(current=[default], entries=[witness(phase="ROLLED_BACK")])
        self.classification(s, "CLOSED_NO_TARGET_PRESENT", False)

    def test_30_rolled_back_but_target_present_blocked(self):
        s = scenario(entries=[witness(phase="ROLLED_BACK")])
        self.classification(s, "CLOSED_RECEIPT_ROUTE_STILL_PRESENT")

    def test_31_missing_postread_route_with_current_target_blocked(self):
        default = route("0.0.0.0/0", metric=0)
        s = scenario(post=[default])
        self.classification(s, "INSUFFICIENT_NATIVE_EVIDENCE")

    def test_32_target_absent_after_verified_receipt_blocked(self):
        default = route("0.0.0.0/0", metric=0)
        s = scenario(current=[default])
        self.classification(s, "TARGET_ABSENT_AFTER_RECEIPT")

    def test_33_physical_gateway_drift_blocks(self):
        e = dict(ENV, PhysicalNextHop="10.0.0.1")
        self.classification(scenario(env=e), "ENVIRONMENT_OR_PHYSICAL_GATE_DRIFT")

    def test_34_system_proxy_drift_blocks(self):
        e = dict(ENV, WinINETProxyEnable=0)
        self.classification(scenario(env=e), "ENVIRONMENT_OR_PHYSICAL_GATE_DRIFT")

    def test_35_nrpt_drift_blocks(self):
        e = dict(ENV, NRPTCount=24)
        self.classification(scenario(env=e), "ENVIRONMENT_OR_PHYSICAL_GATE_DRIFT")

    def test_36_foreign_unrelated_route_added_blocks(self):
        s = scenario()
        s["current"]["activeRoutes"].append(route("203.0.113.0/24", idx=12))
        s["current"]["activeRouteCount"] += 1
        self.classification(s, "UNRELATED_ROUTE_WORLD_DRIFT")

    def test_37_unrelated_baseline_route_removed_blocks(self):
        default = route("0.0.0.0/0", metric=0)
        extra = route("203.0.113.0/24", idx=12)
        s = scenario(before=[default, extra])
        self.classification(s, "UNRELATED_ROUTE_WORLD_DRIFT")

    def test_38_duplicate_plan_prefix_rejected(self):
        s = scenario(entries=[witness(batch=1), witness(batch=1)])
        self.invalid(s, "DUPLICATE_PLAN_PREFIX")

    def test_39_wrong_batch_assignment_rejected(self):
        s = scenario(entries=[witness(batch=2)])
        self.invalid(s, "BATCH_INDEX_MISMATCH")

    def test_40_cross_run_receipt_rejected(self):
        s = scenario(entries=[witness(runId="0"*32)])
        self.invalid(s, "RUN_ID_CROSS_RUN_MISMATCH")

    def test_41_malformed_frozen_dataset_sha_rejected(self):
        s = scenario()
        s["datasetSHA256"] = "not a digest"
        self.invalid(s, "INVALID_FROZEN_DATASET_HASH")

    def test_42_invalid_ipv4_target_rejected(self):
        s = scenario(entries=[witness(DestinationPrefix="10.20.1.1/16")])
        self.invalid(s, "INVALID_OR_NONCANONICAL_IPV4_CIDR")

    def test_43_missing_native_protocol_rejected(self):
        s = scenario()
        del s["post"]["activeRoutes"][1]["Protocol"]
        self.invalid(s, "NATIVE_CIM_FIELDS_INCOMPLETE")

    def test_44_wrong_snapshot_schema_rejected(self):
        s = scenario()
        s["post"]["schema"] = "fiction"
        self.invalid(s, "WRONG_SNAPSHOT_SCHEMA")

    def test_45_snapshot_claiming_write_authorized_rejected(self):
        s = scenario()
        s["post"]["nativeWriteAuthorized"] = True
        self.invalid(s, "SNAPSHOT_WRITE_AUTHORIZED")

    def test_46_native_query_count_mismatch_rejected(self):
        s = scenario()
        s["current"]["activeRouteCount"] += 1
        self.invalid(s, "ROUTE_SNAPSHOT_COUNT_MISMATCH")

    def test_47_persistent_store_as_witness_target_denied(self):
        s = scenario(entries=[witness(Store="PersistentStore")])
        self.invalid(s, "PERSISTENT_TARGET_NOT_AUTHORIZED")

    def test_48_native_instanceid_and_simulated_owner_marker_not_proof(self):
        s = scenario()
        for snap in ("post", "current"):
            s[snap]["activeRoutes"][1]["simOwnerToken"] = "SHARED_SPOOFED_TOKEN"
            s[snap]["activeRoutes"][1]["InstanceID"] = "APPARENTLY_MATCHING_OWNER"
        self.classification(s, "EXACT_ROUTE_WITNESSED_OWNERSHIP_UNPROVEN", False)

    def test_49_partial_batch_receipt_and_unfinished_next_batch(self):
        default = route("0.0.0.0/0", metric=0)
        a = route("10.0.0.0/16", instance="a")
        b = route("10.1.0.0/16", instance="b")
        c = route("10.2.0.0/16", instance="c")
        d = route("10.3.0.0/16", instance="d")
        entries = [
            witness("10.0.0.0/16", batch=1),
            witness("10.1.0.0/16", batch=1),
            witness("10.2.0.0/16", batch=2,
                    phase="INTENT", nativeCallReturned=False, postReadVerified=False),
            witness("10.3.0.0/16", batch=2,
                    phase="INTENT", nativeCallReturned=False, postReadVerified=False),
        ]
        s = scenario(before=[default], post=[default, a, b, d],
                     current=[default, a, b, d], entries=entries, batch_size=2)
        r = assess_scenario(s)
        self.assertEqual(r["batchCount"], 2)
        self.assertEqual(r["reviewOnlyWitnesses"], 2)
        self.assertEqual(r["blockedWitnesses"], 1)
        self.assertEqual(r["absentOrClosedWitnesses"], 1)
        self.assertFalse(r["nativeDeleteAuthorized"])

    def test_50_receipt_reenumeration_route_order_does_not_change_status(self):
        default = route("0.0.0.0/0", metric=0)
        t1 = route("10.20.0.0/16", instance="a")
        t2 = route("10.21.0.0/16", instance="b")
        entries = [witness("10.20.0.0/16", batch=1),
                   witness("10.21.0.0/16", batch=1)]
        s = scenario(before=[default], post=[t2, t1, default],
                     current=[t1, default, t2], entries=entries)
        r = assess_scenario(s)
        self.assertEqual(r["reviewOnlyWitnesses"], 2)
        self.assertEqual(r["blockedWitnesses"], 0)

    def test_51_inspect_cli_reports_readonly_on_static_cim_fixture(self):
        with tempfile.TemporaryDirectory(prefix="p1i-evidence-") as tmp:
            path = Path(tmp) / "snapshot.json"
            path.write_text(json.dumps(snapshot([route("0.0.0.0/0", metric=0)])))
            proc = subprocess.run([sys.executable,
                str(BASE / "stage_c_p1i_native_contract.py"),
                "--snapshot-json", str(path)], capture_output=True, text=True, timeout=10)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            report = json.loads(proc.stdout)
            self.assertEqual(report["result"], "READ_ONLY_NATIVE_CIM_INSPECTED")
            self.assertEqual(report["storeField"], "Store")
            self.assertFalse(report["nativeDeleteAuthorized"])
            self.assertFalse(report["networkMutationsPerformed"])

    def test_52_cli_blocks_unsafe_scenario_with_exit_two(self):
        s = scenario(entries=[witness(phase="INTENT")])
        with tempfile.TemporaryDirectory(prefix="p1i-evidence-") as tmp:
            path = Path(tmp) / "fixture.json"
            path.write_text(json.dumps(s))
            proc = subprocess.run([sys.executable,
                str(BASE / "stage_c_p1i_native_contract.py"),
                "--scenario-json", str(path)], capture_output=True,
                text=True, timeout=10)
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assertEqual(json.loads(proc.stdout)["result"], "NATIVE_EVIDENCE_BLOCKED")

    def test_53_missing_evidence_file_blocks_and_never_mutates(self):
        proc = subprocess.run([sys.executable,
            str(BASE / "stage_c_p1i_native_contract.py"),
            "--snapshot-json", "/no/such/path/p1i-evidence.json"],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, 4)
        self.assertFalse(json.loads(proc.stdout)["nativeApplyAuthorized"])

    def test_54_engine_no_network_or_mutator_imports(self):
        tree = ast.parse((BASE / "stage_c_p1i_native_contract.py").read_text(encoding="utf-8"))
        modules = {alias.name for n in ast.walk(tree) if isinstance(n, ast.Import)
                   for alias in n.names}
        modules |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        self.assertFalse(modules.intersection({"subprocess", "socket", "ctypes",
                        "winreg", "win32api", "win32com", "requests", "urllib.request"}))

    def test_55_large_5494_entry_batch_classification_never_authorizes_deletion(self):
        source = (BASE.parent / "data" / "cn-ipv4-cidrs.txt").read_text(encoding="utf-8-sig").splitlines()
        prefixes = [s for s in source if s.strip()]
        self.assertEqual(len(prefixes), 5494)
        default = route("0.0.0.0/0", metric=0)
        all_target = [route(prefix, instance="ephemeral-" + str(i))
                      for i, prefix in enumerate(prefixes)]
        entries = [witness(prefix, batch=i//512 + 1) for i, prefix in enumerate(prefixes)]
        s = scenario(before=[default], post=[default] + all_target,
                     current=[default] + list(reversed(all_target)),
                     entries=entries, batch_size=512)
        r = assess_scenario(s)
        self.assertEqual(r["batchCount"], 11)
        self.assertEqual(r["reviewOnlyWitnesses"], 5494)
        self.assertEqual(r["blockedWitnesses"], 0)
        self.assertFalse(r["nativeDeleteAuthorized"])
        self.assertFalse(r["networkMutationsPerformed"])


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=1).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(NativeContractTests)
    )
    print("P1I_TESTS_PASSED=" + str(result.testsRun - len(result.failures) - len(result.errors)))
    print("P1I_TESTS_FAILED=" + str(len(result.failures) + len(result.errors)))
    print("P1I_NATIVE_NETWORK_WRITES_EXECUTED=False")
    print("P1I_RESULT=" + ("READ_ONLY_TESTS_PASS" if result.wasSuccessful() else "TESTS_FAILED"))
    sys.exit(0 if result.wasSuccessful() else 1)
