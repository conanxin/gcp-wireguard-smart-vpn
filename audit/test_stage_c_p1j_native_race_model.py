#!/usr/bin/env python3
"""P1J proof obligations: indistinguishable foreign insertion => never auto-delete.

44 independent race × receipt windows plus input guardrails, full 5,494-CIDR
batch evidence replay, native fixture compatibility and CLI checks.
All "owners" here are simulated truth-oracle labels hidden from native reads.
"""
from __future__ import annotations

import ast
from collections import Counter
from copy import deepcopy
import ipaddress
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import stage_c_p1j_native_race_model as model  # noqa: E402
from stage_c_p1i_native_contract import InvalidEvidence, parse_snapshot, assess_scenario

SOURCE = (HERE.parent / "data" / "cn-ipv4-cidrs.txt")
SCRIPT = HERE / "stage_c_p1j_native_race_model.py"


class RaceModelTests(unittest.TestCase):
    def no_delete(self, report: dict) -> None:
        self.assertFalse(report["nativeDeleteAuthorized"])
        self.assertFalse(report["networkMutationsPerformed"])
        if "nativeApplyAuthorized" in report:
            self.assertFalse(report["nativeApplyAuthorized"])

    def test_01_verified_receipt_cannot_prove_native_ownership(self):
        r = model.evaluate_pair()
        self.assertEqual(r["decision"], "MANUAL_REVIEW_ONLY_OWNERSHIP_UNPROVEN")
        self.assertEqual(r["p1iClassification"],
                         "EXACT_ROUTE_WITNESSED_OWNERSHIP_UNPROVEN")
        self.assertEqual(r["oracleOwnerProject"], "PROJECT")
        self.assertEqual(r["oracleOwnerExternal"], "EXTERNAL")
        self.no_delete(r)

    def test_02_race_oracle_stripped_from_cim(self):
        hidden = model.hidden_object(model.DEFAULT_PREFIX, "EXTERNAL")
        observed = model.hide_truth(hidden)
        self.assertNotIn("truthOwner", observed)
        self.assertNotIn("simOwnerToken", observed)
        self.assertEqual(set(observed), set(model.NATIVE_VISIBLE_FIELDS))

    def test_03_foreign_replacement_same_native_fields(self):
        w = model.observation_worlds(model.DEFAULT_PREFIX,
                                    race=model.RACES[1], target_present=True)
        self.assertEqual(w["project"]["current"][-1]["truthOwner"], "PROJECT")
        self.assertEqual(w["external"]["current"][-1]["truthOwner"], "EXTERNAL")
        self.assertEqual(model.hide_truth(w["project"]["current"][-1]),
                         model.hide_truth(w["external"]["current"][-1]))

    def test_04_reenumeration_instanceid_cannot_prove_ownership(self):
        report = model.evaluate_pair(instance_current="different-native-opaque-instance")
        self.assertTrue(report["observationallyIndistinguishable"])
        self.assertEqual(report["decision"], "MANUAL_REVIEW_ONLY_OWNERSHIP_UNPROVEN")
        self.no_delete(report)

    def test_05_race_before_postread_equivalence(self):
        w = model.observation_worlds(model.DEFAULT_PREFIX,
                                    race=model.RACES[0], target_present=True)
        self.assertEqual(w["project"]["post"][-1]["truthOwner"], "PROJECT")
        self.assertEqual(w["external"]["post"][-1]["truthOwner"], "EXTERNAL")
        p = model.fixture_from_worlds(w, "project", prefix=model.DEFAULT_PREFIX,
                                      window="VERIFIED_RECEIPT")
        q = model.fixture_from_worlds(w, "external", prefix=model.DEFAULT_PREFIX,
                                      window="VERIFIED_RECEIPT")
        self.assertEqual(model.fingerprint(p), model.fingerprint(q))

    def test_06_after_postread_swap_is_invisible(self):
        w = model.observation_worlds(model.DEFAULT_PREFIX,
                                    race=model.RACES[1], target_present=True)
        self.assertEqual(w["external"]["post"][-1]["truthOwner"], "PROJECT")
        self.assertEqual(w["external"]["current"][-1]["truthOwner"], "EXTERNAL")
        p = model.fixture_from_worlds(w, "project", prefix=model.DEFAULT_PREFIX,
                                      window="VERIFIED_RECEIPT")
        q = model.fixture_from_worlds(w, "external", prefix=model.DEFAULT_PREFIX,
                                      window="VERIFIED_RECEIPT")
        self.assertEqual(p, q)

    def test_07_no_native_lookup_of_hidden_oracle_owner(self):
        row = model.hidden_object(model.DEFAULT_PREFIX, "EXTERNAL")
        snapshot = model.native_snapshot([row])
        self.assertNotIn("truthOwner", json.dumps(snapshot))
        self.assertNotIn("simOwnerToken", json.dumps(snapshot))
        self.assertEqual(parse_snapshot(snapshot)["countActive"], 1)

    def test_08_precise_window_count(self):
        self.assertEqual(len(model.WINDOWS), 11)
        self.assertEqual(len(model.RACES), 4)
        self.assertEqual(sum(v[1] for v in model.WINDOWS.values()), 7)

    def test_09_even_complete_receipts_do_not_override_owner_ambiguity(self):
        for race in model.RACES:
            r = model.evaluate_pair(race=race, window="VERIFIED_RECEIPT")
            self.assertEqual(r["p1iReviewOnly"], 1)
            self.assertEqual(r["p1iBlocked"], 0)
            self.no_delete(r)

    def test_10_incomplete_call_receipt_blocks(self):
        self.assertEqual(model.evaluate_pair(window="API_RETURN_NOT_PERSISTED")["decision"],
                         "BLOCKED_NO_NATIVE_DELETE")

    def test_11_intent_crash_during_native_call_blocks(self):
        r = model.evaluate_pair(window="CALL_ENTERED_NO_ACK")
        self.assertEqual(r["p1iClassification"], "UNRESOLVED_INTENT_WITH_ROUTE")
        self.no_delete(r)

    def test_12_missing_postread_receipt_blocks(self):
        r = model.evaluate_pair(window="CALL_ACK_DURABLE")
        self.assertEqual(r["p1iClassification"], "CRASH_GAP_MISSING_POSTREAD")
        self.no_delete(r)

    def test_13_postread_without_commit_blocks(self):
        r = model.evaluate_pair(window="POSTREAD_NOT_COMMITTED")
        self.assertEqual(r["p1iClassification"], "RECEIPT_PHASE_INCONSISTENT")
        self.no_delete(r)

    def test_14_rollback_intent_with_route_blocks(self):
        self.assertEqual(model.evaluate_pair(
            window="ROLLBACK_INTENT_PENDING")["decision"], "BLOCKED_NO_NATIVE_DELETE")

    def test_15_rollback_ack_lost_without_route_needs_no_delete_action(self):
        r = model.evaluate_pair(window="DELETE_ACK_NOT_PERSISTED")
        self.assertEqual(r["decision"], "BLOCKED_NO_NATIVE_DELETE")
        self.assertEqual(r["oracleOwnerProject"], "NONE")
        self.no_delete(r)

    def test_16_closed_receipt_route_present_blocks(self):
        r = model.evaluate_pair(window="ROLLBACK_CLOSED_BUT_ROUTE_PRESENT")
        self.assertEqual(r["p1iClassification"],
                         "CLOSED_RECEIPT_ROUTE_STILL_PRESENT")

    def test_17_closed_receipt_absent_has_no_delete_work(self):
        r = model.evaluate_pair(window="ROLLBACK_CLOSED_AND_ABSENT")
        self.assertEqual(r["decision"], "NO_TARGET_TO_DELETE")
        self.no_delete(r)

    def test_18_all_matrix_cases_observationally_indistinguishable(self):
        seen = []
        for race in model.RACES:
            for window in model.WINDOWS:
                p = model.evaluate_pair(race=race, window=window)
                self.assertTrue(p["observationallyIndistinguishable"])
                self.no_delete(p)
                seen.append(p)
        self.assertEqual(len(seen), 44)
        self.assertEqual(sum(p["oracleOwnerProject"] != p["oracleOwnerExternal"]
                             for p in seen), 28)
        self.assertEqual(sum(p["oracleOwnerProject"] == "NONE" for p in seen), 16)

    def test_19_invalid_race_is_blocked(self):
        with self.assertRaisesRegex(InvalidEvidence, "UNKNOWN_RACE"):
            model.evaluate_pair(race="invented")

    def test_20_invalid_window_is_blocked(self):
        with self.assertRaisesRegex(InvalidEvidence, "UNKNOWN_CRASH_WINDOW"):
            model.evaluate_pair(window="invented")

    def test_21_invalid_cidr_is_blocked(self):
        with self.assertRaisesRegex(InvalidEvidence, "INVALID_TEST_TARGET_CIDR"):
            model.evaluate_pair(prefix="300.1.1.1/32")

    def test_22_noncanonical_cidr_is_blocked(self):
        with self.assertRaisesRegex(InvalidEvidence, "INVALID_TEST_TARGET_CIDR"):
            model.evaluate_pair(prefix="198.51.100.83/24")

    def test_23_foreign_truth_does_not_leak_through_native_fingerprint(self):
        w = model.observation_worlds(model.DEFAULT_PREFIX,
                                    race=model.RACES[2], target_present=True)
        for key in ("project", "external"):
            p = model.fixture_from_worlds(w, key, prefix=model.DEFAULT_PREFIX,
                                          window="VERIFIED_RECEIPT")
            self.assertNotIn("truthOwner", json.dumps(p))
            self.assertNotIn("simOwnerToken", json.dumps(p))

    def test_24_dataset_5494_cidrs_loaded_strictly(self):
        prefixes = model.load_cidrs(str(SOURCE))
        self.assertEqual(len(prefixes), 5494)
        self.assertEqual(len(set(prefixes)), 5494)
        self.assertTrue(all(isinstance(ipaddress.ip_network(x, strict=True),
                                       ipaddress.IPv4Network) for x in prefixes))

    def test_25_5494_entries_most_review_only_one_receipt_gap(self):
        prefixes = model.load_cidrs(str(SOURCE))
        r = model.batch_corpus(prefixes, external_ordinals={3072, 5493},
                               receipt_gap_ordinals={3073})
        self.assertEqual(r["batchCount"], 11)
        self.assertEqual(r["reviewOnlyWitnesses"], 5493)
        self.assertEqual(r["blockedWitnesses"], 1)
        self.assertEqual(r["oracleExternalReplacements"], 2)
        self.assertEqual(r["unprovenNativeOwnership"], 5494)
        self.no_delete(r)

    def test_26_all_5494_reported_receipts_complete_still_no_delete(self):
        prefixes = model.load_cidrs(str(SOURCE))
        r = model.batch_corpus(prefixes)
        self.assertEqual(r["reviewOnlyWitnesses"], 5494)
        self.assertEqual(r["blockedWitnesses"], 0)
        self.no_delete(r)

    def test_27_every_batch_7_receipt_missing_blocks_every_entry(self):
        prefixes = model.load_cidrs(str(SOURCE))
        gap = set(range(3072, 3584))
        r = model.batch_corpus(prefixes, external_ordinals={3072},
                               receipt_gap_ordinals=gap)
        self.assertEqual(r["blockedWitnesses"], 512)
        self.assertEqual(r["reviewOnlyWitnesses"], 5494 - 512)
        self.no_delete(r)

    def test_28_batch_size_one(self):
        r = model.batch_corpus(
            ["198.51.100.7/32", "198.51.100.8/32"], batch_size=1)
        self.assertEqual(r["batchCount"], 2)
        self.no_delete(r)

    def test_29_batch_size_512_limit(self):
        r = model.batch_corpus(
            ["198.51.100.7/32", "198.51.100.8/32"], batch_size=512)
        self.assertEqual(r["batchCount"], 1)

    def test_30_batch_size_zero_rejected(self):
        with self.assertRaisesRegex(InvalidEvidence, "INVALID_BATCH_SIZE"):
            model.batch_corpus(["198.51.100.7/32"], batch_size=0)

    def test_31_batch_size_over_512_rejected(self):
        with self.assertRaisesRegex(InvalidEvidence, "INVALID_BATCH_SIZE"):
            model.batch_corpus(["198.51.100.7/32"], batch_size=513)

    def test_32_out_of_range_external_ordinal_rejected(self):
        with self.assertRaisesRegex(InvalidEvidence, "BAD_CORPUS_FAULT_INDEX"):
            model.batch_corpus(["198.51.100.7/32"], external_ordinals={2})

    def test_33_out_of_range_receipt_gap_ordinal_rejected(self):
        with self.assertRaisesRegex(InvalidEvidence, "BAD_CORPUS_FAULT_INDEX"):
            model.batch_corpus(["198.51.100.7/32"], receipt_gap_ordinals={-1})

    def test_34_duplicate_source_prefix_rejected(self):
        with self.assertRaisesRegex(InvalidEvidence, "EMPTY_OR_DUPLICATE_SOURCE"):
            model.batch_corpus(["198.51.100.7/32", "198.51.100.7/32"])

    def test_35_empty_source_rejected(self):
        with self.assertRaisesRegex(InvalidEvidence, "EMPTY_OR_DUPLICATE_SOURCE"):
            model.batch_corpus([])

    def test_36_fake_other_authorization_blocked_by_gate(self):
        forged = {"nativeDeleteAuthorized": True,
                  "nativeApplyAuthorized": False,
                  "networkMutationsPerformed": False}
        with self.assertRaisesRegex(InvalidEvidence, "P1I_REPORT_UNSAFE_AUTHORIZATION"):
            model.adjudication(forged)

    def test_37_intact_full_scale_report_has_no_delete(self):
        source = model.load_cidrs(str(SOURCE))
        r = model.batch_corpus(source, external_ordinals={0, 512, 1024, 3072, 5493})
        self.assertEqual(r["unprovenNativeOwnership"], 5494)
        self.assertFalse(r["nativeDeleteAuthorized"])

    def test_38_cli_pair_returns_proof(self):
        run = subprocess.run([sys.executable, str(SCRIPT), "--pair"],
                             capture_output=True, text=True, timeout=12)
        self.assertEqual(run.returncode, 0, run.stderr)
        r = json.loads(run.stdout)
        self.assertTrue(r["observationallyIndistinguishable"])
        self.assertEqual(r["decision"], "MANUAL_REVIEW_ONLY_OWNERSHIP_UNPROVEN")
        self.no_delete(r)

    def test_39_cli_matrix_counts_44(self):
        run = subprocess.run([sys.executable, str(SCRIPT), "--matrix"],
                             capture_output=True, text=True, timeout=12)
        self.assertEqual(run.returncode, 0, run.stderr)
        r = json.loads(run.stdout)
        self.assertEqual(r["cases"], 44)
        self.assertEqual(r["pairsWithPresentTargetAndDifferentHiddenOwners"], 28)
        self.assertEqual(r["pairsWithAbsentTargetNoDeleteNeeded"], 16)
        self.assertEqual(r["unsafeNativeDeleteApprovals"], 0)
        self.no_delete(r)

    def test_40_cli_5494_corpus(self):
        run = subprocess.run([sys.executable, str(SCRIPT), "--corpus", str(SOURCE)],
                             capture_output=True, text=True, timeout=12)
        self.assertEqual(run.returncode, 0, run.stderr)
        r = json.loads(run.stdout)
        self.assertEqual(r["sourceCount"], 5494)
        self.assertEqual(r["batchCount"], 11)
        self.assertEqual(r["blockedWitnesses"], 1)
        self.no_delete(r)

    def test_41_cli_missing_corpus_is_blocked(self):
        run = subprocess.run([sys.executable, str(SCRIPT),
                              "--corpus", "nonexistent-source.txt"],
                             capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 4, run.stderr)
        self.assertEqual(json.loads(run.stdout)["result"], "BLOCKED_INVALID_FIXTURE")

    def test_42_cli_bad_prefix_is_blocked(self):
        run = subprocess.run([sys.executable, str(SCRIPT),
                              "--pair", "--prefix", "198.51.100.77/24"],
                             capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 4)
        self.assertFalse(json.loads(run.stdout)["nativeDeleteAuthorized"])

    def test_43_random_fixed_seed_64_native_observation_pairs(self):
        prng = random.Random(20261025)
        source = model.load_cidrs(str(SOURCE))
        for prefix in prng.sample(source, 64):
            r = model.evaluate_pair(prefix=prefix, race=prng.choice(model.RACES),
                                    window="VERIFIED_RECEIPT")
            self.assertTrue(r["observationallyIndistinguishable"])
            self.assertEqual(r["decision"], "MANUAL_REVIEW_ONLY_OWNERSHIP_UNPROVEN")
            self.no_delete(r)

    def test_44_oracle_owner_not_available_to_p1i_decoder(self):
        pair = model.observation_worlds(model.DEFAULT_PREFIX, race=model.RACES[0],
                                        target_present=True)
        one = model.fixture_from_worlds(pair, "project",
                                        prefix=model.DEFAULT_PREFIX,
                                        window="VERIFIED_RECEIPT")
        two = model.fixture_from_worlds(pair, "external",
                                        prefix=model.DEFAULT_PREFIX,
                                        window="VERIFIED_RECEIPT")
        self.assertEqual(one, two)
        self.assertEqual(model.fingerprint(one), model.fingerprint(two))

    def test_45_engine_imports_no_system_mutation_capability(self):
        tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
        imports = {n.module for n in ast.walk(tree)
                   if isinstance(n, ast.ImportFrom)}
        imports |= {a.name for n in ast.walk(tree)
                    if isinstance(n, ast.Import) for a in n.names}
        banned = {"subprocess", "ctypes", "socket", "winreg", "win32api",
                  "win32com", "requests", "urllib", "psutil"}
        self.assertFalse(imports & banned, imports & banned)

    def test_46_cli_oracle_flags_do_not_influence_authorization(self):
        for race in model.RACES:
            r = model.evaluate_pair(race=race, window="VERIFIED_RECEIPT")
            self.no_delete(r)

    def test_47_native_route_opaque_instance_identifier_is_not_owner_token(self):
        r = model.evaluate_pair(instance_current="reset-other-id",
                                window="VERIFIED_RECEIPT")
        self.assertTrue(r["observationallyIndistinguishable"])
        self.no_delete(r)

    def test_48_empty_native_route_after_closed_receipt_not_a_success_proof(self):
        r = model.evaluate_pair(window="ROLLBACK_CLOSED_AND_ABSENT")
        self.assertEqual(r["decision"], "NO_TARGET_TO_DELETE")
        self.assertEqual(r["oracleOwnerProject"], "NONE")
        self.no_delete(r)


    def _crash_replay(self, *, window: str, expected_class: str):
        # A child persists purely synthetic/native-shaped evidence to a temp
        # file and really exits 77. Another process independently parses
        # only the observable JSON after that exit.
        with tempfile.TemporaryDirectory(prefix="p1j-crash-fixture-") as tmp:
            path = str(Path(tmp) / "observation.json")
            child = """
import json,os,sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import stage_c_p1j_native_race_model as model
worlds=model.observation_worlds(model.DEFAULT_PREFIX,
    race=model.RACES[1],target_present=model.WINDOWS[sys.argv[3]][1])
scenario=model.fixture_from_worlds(worlds,'external',
    prefix=model.DEFAULT_PREFIX,window=sys.argv[3])
Path(sys.argv[2]).write_text(json.dumps(scenario),encoding='utf-8')
os._exit(77)
"""
            stopped = subprocess.run(
                [sys.executable, "-c", child, str(HERE), path, window],
                capture_output=True, text=True, timeout=10)
            self.assertEqual(stopped.returncode, 77, stopped.stderr)
            recovery = """
import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from stage_c_p1i_native_contract import assess_scenario
from stage_c_p1j_native_race_model import adjudication
scenario=json.loads(Path(sys.argv[2]).read_text(encoding='utf-8'))
report=assess_scenario(scenario)
print(json.dumps({'classification':report['claims'][0]['classification'],
 'decision':adjudication(report),'nativeDeleteAuthorized':report['nativeDeleteAuthorized'],
 'networkMutationsPerformed':report['networkMutationsPerformed']}))
"""
            fresh = subprocess.run(
                [sys.executable, "-c", recovery, str(HERE), path],
                capture_output=True, text=True, timeout=10)
            self.assertEqual(fresh.returncode, 0, fresh.stderr)
            result = json.loads(fresh.stdout)
            self.assertEqual(result["classification"], expected_class)
            self.assertFalse(result["nativeDeleteAuthorized"])
            self.assertFalse(result["networkMutationsPerformed"])
            return result

    def test_49_real_child_exit_77_then_new_process_reviews_matched_route(self):
        r = self._crash_replay(window="VERIFIED_RECEIPT",
            expected_class="EXACT_ROUTE_WITNESSED_OWNERSHIP_UNPROVEN")
        self.assertEqual(r["decision"], "MANUAL_REVIEW_ONLY_OWNERSHIP_UNPROVEN")

    def test_50_real_child_exit_77_after_native_call_without_postread(self):
        r = self._crash_replay(window="CALL_ACK_DURABLE",
            expected_class="CRASH_GAP_MISSING_POSTREAD")
        self.assertEqual(r["decision"], "BLOCKED_NO_NATIVE_DELETE")

    def test_51_real_child_exit_77_rollback_intent_route_still_present(self):
        r = self._crash_replay(window="ROLLBACK_INTENT_PENDING",
            expected_class="ROLLBACK_GAP_PRESENT_OWNERSHIP_UNPROVEN")
        self.assertEqual(r["decision"], "BLOCKED_NO_NATIVE_DELETE")

    def test_52_real_child_exit_77_after_delete_ack_without_receipt(self):
        r = self._crash_replay(window="DELETE_ACK_NOT_PERSISTED",
            expected_class="ROLLBACK_GAP_NO_TARGET")
        self.assertEqual(r["decision"], "BLOCKED_NO_NATIVE_DELETE")


    def test_53_physical_interface_index_change_blocks_recovery(self):
        # Observed Windows WLAN index changed from 9 on 24 Oct to 8 on
        # 25 Oct. A fixture must never freeze 9 as permanently valid.
        w = model.observation_worlds(model.DEFAULT_PREFIX,
                                     race=model.RACES[1], target_present=True)
        s = model.fixture_from_worlds(w, "project",
                                      prefix=model.DEFAULT_PREFIX,
                                      window="VERIFIED_RECEIPT")
        s["current"]["environment"]["PhysicalInterfaceIndex"] = 8
        r = assess_scenario(s)
        self.assertEqual(r["claims"][0]["classification"],
                         "ENVIRONMENT_OR_PHYSICAL_GATE_DRIFT")
        self.no_delete(r)

    def test_54_route_ifindex_changes_even_if_gateway_same(self):
        w = model.observation_worlds(model.DEFAULT_PREFIX,
                                     race=model.RACES[1], target_present=True)
        s = model.fixture_from_worlds(w, "project",
                                      prefix=model.DEFAULT_PREFIX,
                                      window="VERIFIED_RECEIPT")
        s["current"]["activeRoutes"][-1]["InterfaceIndex"] = 8
        r = assess_scenario(s)
        self.assertEqual(r["claims"][0]["classification"],
                         "NATIVE_IDENTITY_DRIFT")
        self.no_delete(r)

    def test_55_same_ifindex_but_gateway_changed_blocks_recovery(self):
        w = model.observation_worlds(model.DEFAULT_PREFIX,
                                     race=model.RACES[1], target_present=True)
        s = model.fixture_from_worlds(w, "project",
                                      prefix=model.DEFAULT_PREFIX,
                                      window="VERIFIED_RECEIPT")
        s["current"]["environment"]["PhysicalNextHop"] = "192.168.1.1"
        r = assess_scenario(s)
        self.assertEqual(r["claims"][0]["classification"],
                         "ENVIRONMENT_OR_PHYSICAL_GATE_DRIFT")
        self.no_delete(r)


def make_case(race: str, window: str):
    def test(self):
        result = model.evaluate_pair(race=race, window=window)
        self.assertTrue(result["observationallyIndistinguishable"])
        self.assertEqual(result["observableFingerprintProject"],
                         result["observableFingerprintExternal"])
        self.assertFalse(result["nativeApplyAuthorized"])
        self.assertFalse(result["nativeDeleteAuthorized"])
        self.assertFalse(result["networkMutationsPerformed"])
        if model.WINDOWS[window][1]:
            self.assertEqual(result["oracleOwnerProject"], "PROJECT")
            self.assertEqual(result["oracleOwnerExternal"], "EXTERNAL")
        else:
            self.assertEqual(result["oracleOwnerProject"], "NONE")
            self.assertEqual(result["oracleOwnerExternal"], "NONE")
        self.assertIn(result["decision"], (
            "BLOCKED_NO_NATIVE_DELETE",
            "MANUAL_REVIEW_ONLY_OWNERSHIP_UNPROVEN",
            "NO_TARGET_TO_DELETE",
        ))
    return test


# Forty-four independently runnable tests, not just one aggregate for-loop.
for race_name in model.RACES:
    for window_name in model.WINDOWS:
        setattr(RaceModelTests,
                "test_pair_" + race_name.lower() + "__" + window_name.lower(),
                make_case(race_name, window_name))


if __name__ == "__main__":
    results = unittest.TextTestRunner(verbosity=1).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(RaceModelTests)
    )
    passed = results.testsRun - len(results.failures) - len(results.errors)
    print("P1J_TESTS_PASSED=" + str(passed))
    print("P1J_TESTS_FAILED=" + str(len(results.failures) + len(results.errors)))
    print("P1J_NATIVE_NETWORK_WRITES_EXECUTED=False")
    print("P1J_RESULT=" + ("MOCK_RACE_GATE_PASS" if results.wasSuccessful()
                           else "MOCK_RACE_GATE_FAILED"))
    sys.exit(0 if results.wasSuccessful() else 1)
