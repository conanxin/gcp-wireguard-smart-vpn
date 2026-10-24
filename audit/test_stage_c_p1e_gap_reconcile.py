#!/usr/bin/env python3
"""Stage C P1E synthetic world-before-audit append gap tests."""
from __future__ import annotations
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_stage_c_p1d_recovery_audit import Fixture, RUN_ID, ROUTE
from stage_c_p1e_gap_reconcile import assess, repair_mock_audit
from stage_c_p1d_recovery_audit import analyze_fixture


class GapRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory(prefix="p1c-fixture-")
        self.p = Path(self.t.name)
        self.f = Fixture(self.p)

    def tearDown(self):
        self.t.cleanup()

    def gap(self):
        # Exact crash boundary: mockworld.json was atomically replaced,
        # but the tail audit "FILE_COMMITTED" record was never appended.
        # Earlier PLAN+INTENT journal records remain intact.
        tail = self.f.events.pop()
        self.assertEqual(tail["file"], "mockworld.json")
        self.f.flush_audit()
        return tail

    def assess(self):
        return assess(self.p, RUN_ID, allow_test_fixture=True)

    def repair(self):
        return repair_mock_audit(self.p, RUN_ID, allow_test_fixture=True)

    def test_no_gap_no_repair_needed(self):
        self.assertEqual(self.assess()["decision"], "ALREADY_AUDITED")

    def test_single_intent_gap_is_classified_readonly(self):
        self.gap()
        out = self.assess()
        self.assertEqual(out["decision"], "MOCK_AUDIT_GAP_RECONCILABLE")
        self.assertEqual(out["mock_intent_candidates"], 1)
        self.assertFalse(out["native_route_mutation"])

    def test_inspect_does_not_write_audit(self):
        self.gap()
        before=(self.p/f"audit-{RUN_ID}.ndjson").read_bytes()
        self.assess()
        after=(self.p/f"audit-{RUN_ID}.ndjson").read_bytes()
        self.assertEqual(before,after)

    def test_repair_appends_one_valid_audit_event(self):
        self.gap()
        out=self.repair()
        self.assertEqual(out["decision"],"MOCK_AUDIT_GAP_REPAIRED")
        self.assertTrue(out["audit_repair_authorized"])
        self.assertEqual(analyze_fixture(self.p,RUN_ID)["decision"],
                         "MOCK_RECOVERY_CANDIDATE_READONLY")

    def test_repeated_repair_is_noop(self):
        self.gap()
        self.assertEqual(self.repair()["decision"],"MOCK_AUDIT_GAP_REPAIRED")
        before=(self.p/f"audit-{RUN_ID}.ndjson").read_bytes()
        self.assertEqual(self.repair()["decision"],"ALREADY_AUDITED")
        self.assertEqual((self.p/f"audit-{RUN_ID}.ndjson").read_bytes(),before)

    def test_foreign_route_sharing_prefix_blocks(self):
        self.gap()
        self.f.world["routes"].append(dict(ROUTE,ifIndex=99,nextHop="198.51.100.1"))
        (self.p/"mockworld.json").write_text(json.dumps(self.f.world))
        self.assertEqual(self.assess()["decision"],"BLOCKED")

    def test_nrpt_drift_blocks(self):
        self.gap()
        self.f.world["nrpt"][0]["server"]="8.8.8.8"
        (self.p/"mockworld.json").write_text(json.dumps(self.f.world))
        self.assertEqual(self.assess()["decision"],"BLOCKED")

    def test_gateway_drift_blocks(self):
        self.gap()
        self.f.world["gateway"]="198.51.100.1"
        (self.p/"mockworld.json").write_text(json.dumps(self.f.world))
        self.assertEqual(self.assess()["decision"],"BLOCKED")

    def test_proxy_drift_blocks(self):
        self.gap()
        self.f.world["proxyServer"]="127.0.0.1:19999"
        (self.p/"mockworld.json").write_text(json.dumps(self.f.world))
        self.assertEqual(self.assess()["decision"],"BLOCKED")

    def test_audit_chain_tamper_blocks(self):
        self.gap()
        path=self.p/f"audit-{RUN_ID}.ndjson"
        path.write_bytes(path.read_bytes().replace(b'"kind":"FILE_COMMITTED"',
                                                   b'"kind":"CORRUPTED"',1))
        self.assertEqual(self.assess()["decision"],"BLOCKED")

    def test_prefix_file_change_blocks(self):
        self.gap()
        (self.p/"prefixes.txt").write_text("8.8.8.0/24\n")
        self.assertEqual(self.assess()["decision"],"BLOCKED")

    def test_journal_changed_without_audit_blocks(self):
        self.gap()
        path=self.p/f"journal-{RUN_ID}.json"
        j=json.loads(path.read_text())
        j["beforeHash"]="0"*64
        path.write_text(json.dumps(j))
        self.assertEqual(self.assess()["decision"],"BLOCKED")

    def test_duplicate_same_route_blocks(self):
        self.gap()
        self.f.world["routes"].append(copy.deepcopy(ROUTE))
        (self.p/"mockworld.json").write_text(json.dumps(self.f.world))
        self.assertEqual(self.assess()["decision"],"BLOCKED")

    def test_intent_route_disappeared_but_unlogged_bytes_blocks(self):
        self.gap()
        self.f.world["routes"]=[]
        (self.p/"mockworld.json").write_text(json.dumps(self.f.world))
        # Even semantically equivalent but DIFFERENT unlogged bytes cannot be
        # silently presumed an audited/prepared state.
        self.assertEqual(self.assess()["decision"],"BLOCKED")

    def test_bad_run_id_blocks(self):
        self.gap()
        self.assertEqual(assess(self.p,"../outside",allow_test_fixture=True)["decision"],
                         "BLOCKED")

    def test_path_requires_protected_location_without_test_override(self):
        self.gap()
        self.assertEqual(assess(self.p,RUN_ID)["decision"],"BLOCKED")

    def test_no_gap_when_finished_plan_only(self):
        with tempfile.TemporaryDirectory(prefix="p1c-fixture-") as loc:
            folder=Path(loc)
            Fixture(folder,journal=False)
            self.assertEqual(assess(folder,RUN_ID,allow_test_fixture=True)["decision"],
                             "ALREADY_AUDITED")

    def test_truncated_audit_line_blocks(self):
        self.gap()
        path=self.p/f"audit-{RUN_ID}.ndjson"
        path.write_bytes(path.read_bytes().rstrip(b"\n"))
        self.assertEqual(self.assess()["decision"],"BLOCKED")


if __name__=="__main__":
    unittest.main(verbosity=2)
