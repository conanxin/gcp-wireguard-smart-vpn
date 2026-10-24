#!/usr/bin/env python3
"""Stage C P1D: tests for read-only P1C audit/recovery candidate analysis."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from stage_c_p1d_recovery_audit import (
    analyze_fixture, audit_event_hash, digest_text,
    route_identity, world_hash,
)

RUN_ID = "P1D-TEST-001"
ROUTE = {
    "prefix": "1.0.1.0/24", "ifIndex": 13,
    "nextHop": "192.0.2.1", "metric": 5, "store": "ActiveStore",
}


class Fixture:
    def __init__(self, folder: Path, *, journal: bool = True, restored: bool = False):
        self.folder = folder
        self.events: list[dict] = []
        self.world = {
            "physicalIndex": 13,
            "gateway": "192.0.2.1",
            "proxyEnabled": 1,
            "proxyServer": "127.0.0.1:7897",
            "wgActive": False,
            "routes": [],
            "nrpt": [
                {"id": "F001", "server": "223.5.5.5",
                 "namespaces": [".baidu.com", "baidu.com"]},
            ],
        }
        self.before_hash = world_hash(self.world)
        self.prefixes = ["1.0.1.0/24", "223.5.5.0/24"]
        self.commit("mockworld.json", self.world, "PLAN_BASELINE_WORLD")
        self.commit("prefixes.txt", "\n".join(self.prefixes) + "\n",
                    "PLAN_DESIRED_PREFIXES")
        self.plan = {
            "schema": "stage-c-p1c-route-v1",
            "runId": RUN_ID,
            "worldHash": self.before_hash,
            "prefixesHash": digest_text("\n".join(self.prefixes)),
            "targetCount": len(self.prefixes),
            "type": "MOCK_ONLY_NOT_LIVE",
        }
        self.commit(f"plan-{RUN_ID}.json", self.plan, "FILE_COMMITTED")
        self.journal: dict | None = None
        if journal:
            entry = dict(ROUTE, state="REMOVED" if restored else "INTENT")
            self.journal = {
                "schema": "stage-c-p1c-route-v1",
                "runId": RUN_ID,
                "beforeHash": self.before_hash,
                "beforeIndex": 13,
                "beforeGateway": "192.0.2.1",
                "beforeRoutes": [],
                "entries": [entry],
                "status": ("MOCK_ROLLBACK_VERIFIED" if restored
                           else "APPLYING"),
                "events": ["BASELINE_SNAPSHOT_SAVED"],
            }
            self.commit(f"journal-{RUN_ID}.json", self.journal, "FILE_COMMITTED")
            if not restored:
                self.world["routes"] = [dict(ROUTE)]
                self.commit("mockworld.json", self.world, "FILE_COMMITTED")

    def commit(self, name: str, content, kind: str = "FILE_COMMITTED"):
        path = self.folder / name
        if isinstance(content, str):
            data = content.encode("utf-8")
        else:
            data = json.dumps(content, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        path.write_bytes(data)
        seq = len(self.events) + 1
        prev = self.events[-1]["hash"] if self.events else "GENESIS"
        event = {
            "sequence": seq,
            "prev": prev,
            "kind": kind,
            "file": name,
            "fileSha256": hashlib.sha256(data).hexdigest().upper(),
            "runId": RUN_ID,
        }
        event["hash"] = audit_event_hash(event)
        self.events.append(event)
        self.flush_audit()

    def flush_audit(self):
        target = self.folder / f"audit-{RUN_ID}.ndjson"
        target.write_text(
            "".join(json.dumps(x, separators=(",", ":")) + "\n"
                    for x in self.events),
            encoding="utf-8",
        )

    def analyze(self):
        return analyze_fixture(self.folder, RUN_ID)


class RecoveryAuditUnitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="p1c-fixture-")
        self.folder = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_valid_mock_plan_only(self):
        f = Fixture(self.folder, journal=False)
        self.assertEqual(f.analyze()["decision"], "MOCK_PLAN_ONLY")

    def test_unique_run_owned_route_is_candidate_only(self):
        f = Fixture(self.folder)
        out = f.analyze()
        self.assertEqual(out["decision"], "MOCK_RECOVERY_CANDIDATE_READONLY")
        self.assertEqual(out["owned_candidate_routes"], 1)
        self.assertFalse(out["native_rollback_authorized"])

    def test_completed_mock_rollback(self):
        f = Fixture(self.folder, restored=True)
        self.assertEqual(f.analyze()["decision"], "MOCK_ALREADY_RESTORED")

    def test_audit_chain_event_change_blocks(self):
        f = Fixture(self.folder)
        path = self.folder / f"audit-{RUN_ID}.ndjson"
        path.write_text(path.read_text().replace('"kind":"FILE_COMMITTED"',
                                                  '"kind":"CORRUPTED"', 1))
        self.assertEqual(f.analyze()["decision"], "BLOCKED")

    def test_world_byte_corruption_blocks(self):
        f = Fixture(self.folder)
        path = self.folder / "mockworld.json"
        path.write_bytes(path.read_bytes() + b" ")
        out = f.analyze()
        self.assertEqual(out["decision"], "BLOCKED")
        self.assertIn("AUDIT_COMMITTED_FILE_DIGEST_MISMATCH", out["reasons"])

    def test_gap_after_world_write_before_audit_append_blocks(self):
        f = Fixture(self.folder, journal=True)
        path = self.folder / "mockworld.json"
        world = json.loads(path.read_text())
        world["routes"].append(dict(ROUTE, prefix="223.5.5.0/24"))
        # emulate atomic mockworld write, then crash before audit append
        path.write_text(json.dumps(world), encoding="utf-8")
        self.assertEqual(f.analyze()["decision"], "BLOCKED")

    def test_foreign_same_prefix_route_causes_manual_review(self):
        f = Fixture(self.folder)
        f.world["routes"].append(
            dict(ROUTE, ifIndex=99, nextHop="198.51.100.1", metric=1)
        )
        f.commit("mockworld.json", f.world)
        out = f.analyze()
        self.assertEqual(out["decision"], "MOCK_MANUAL_REVIEW_REQUIRED")
        self.assertTrue(any(x.startswith("AMBIGUOUS_ROUTE_PREFIX")
                            for x in out["reasons"]))

    def test_nrpt_changed_but_journal_valid_causes_manual_review(self):
        f = Fixture(self.folder)
        f.world["nrpt"][0]["server"] = "8.8.8.8"
        f.commit("mockworld.json", f.world)
        self.assertEqual(f.analyze()["decision"], "MOCK_MANUAL_REVIEW_REQUIRED")

    def test_plan_journal_mismatch_blocks(self):
        f = Fixture(self.folder)
        f.journal["beforeHash"] = "0" * 64
        f.commit(f"journal-{RUN_ID}.json", f.journal)
        self.assertEqual(f.analyze()["decision"], "BLOCKED")

    def test_corrupted_prefix_source_blocks(self):
        f = Fixture(self.folder)
        (self.folder / "prefixes.txt").write_text("8.8.8.0/24\n")
        self.assertEqual(f.analyze()["decision"], "BLOCKED")

    def test_journal_borrowed_route_claim_blocks(self):
        f = Fixture(self.folder)
        f.journal["beforeRoutes"] = [route_identity(ROUTE)]
        f.commit(f"journal-{RUN_ID}.json", f.journal)
        self.assertEqual(f.analyze()["decision"], "BLOCKED")

    def test_invalid_run_id_rejected(self):
        f = Fixture(self.folder)
        self.assertEqual(analyze_fixture(self.folder, "../other")["decision"],
                         "BLOCKED")

    def test_truncated_audit_file_rejected(self):
        f = Fixture(self.folder)
        path = self.folder / f"audit-{RUN_ID}.ndjson"
        path.write_bytes(path.read_bytes().rstrip(b"\n"))
        self.assertEqual(f.analyze()["decision"], "BLOCKED")

    def test_unapproved_audit_filename_rejected(self):
        f = Fixture(self.folder)
        f.events[-1]["file"] = "../outside.json"
        f.events[-1]["hash"] = audit_event_hash(f.events[-1])
        f.flush_audit()
        self.assertEqual(f.analyze()["decision"], "BLOCKED")

    def test_duplicate_identical_route_detected(self):
        f = Fixture(self.folder)
        f.world["routes"].append(dict(ROUTE))
        f.commit("mockworld.json", f.world)
        out = f.analyze()
        self.assertEqual(out["decision"], "MOCK_MANUAL_REVIEW_REQUIRED")

    def test_unverified_acl_never_promotes_native_access(self):
        f = Fixture(self.folder)
        out = f.analyze()
        self.assertFalse(out["acl_externally_verified"])
        self.assertFalse(out["live_canary_authorized"])
        self.assertFalse(out["native_windows_routes_were_mutated"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
