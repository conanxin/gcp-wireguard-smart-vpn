#!/usr/bin/env python3
"""P1H isolated fixture-only integration regressions. No OS route/proxy calls."""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
SOURCE = HERE / "stage_c_p1h_batch_mock.py"
sys.path.insert(0, str(HERE))
from stage_c_p1h_batch_mock import ROOT  # noqa: E402

ORIGINAL = PROJECT / "data" / "cn-ipv4-cidrs.txt"


class BatchMocks(unittest.TestCase):
    def setUp(self):
        ROOT.mkdir(parents=True, exist_ok=True)
        self.directory = Path(tempfile.mkdtemp(prefix="p1h-fixture-", dir=ROOT))
        self.data = self.directory / "small-corpus.txt"
        self.data.write_text("\n".join(ORIGINAL.read_text(encoding="utf-8-sig").splitlines()[:12]) + "\n",
                             encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.directory)

    def call(self, action: str, *args: str, expected: int = 0) -> str:
        command = [sys.executable, str(SOURCE), "--sandbox", str(self.directory), action, *args]
        run = subprocess.run(command, capture_output=True, text=True, timeout=30)
        self.assertEqual(run.returncode, expected, "\n".join(["COMMAND: " + " ".join(command),
                            "EXIT=" + str(run.returncode), run.stdout, run.stderr]))
        return run.stdout

    def setup_plan(self):
        result = self.call("init", "--dataset", str(self.data), "--limit", "12",
                           "--batch-size", "4")
        self.assertIn("P1H_RESULT=MOCK_PLAN_READY", result)

    def state(self):
        return json.loads((self.directory / "state.json").read_text(encoding="utf-8"))

    def assert_restored(self):
        after = self.call("recover")
        self.assertIn("P1H_RESULT=MOCK_BATCH_ROLLBACK_VERIFIED", after)
        self.assertEqual(self.state()["phase"], "RESTORED")
        self.assertEqual(self.state()["world"], self.state()["baselineWorld"])
        self.assertIn("P1H_RESULT=MOCK_LEDGER_INTEGRITY_PASS", self.call("status"))

    def test_01_fixture_only_no_native_apis(self):
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        imports = {node.module or "" for node in ast.walk(tree)
                   if isinstance(node, ast.ImportFrom)}
        imports |= {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                    for alias in node.names}
        for module in ("subprocess", "ctypes", "winreg", "socket", "win32api", "win32com"):
            self.assertNotIn(module, imports)
        source = SOURCE.read_text(encoding="utf-8")
        for forbidden in ("New-NetRoute", "Remove-NetRoute", "netsh.exe", "Set-ItemProperty"):
            self.assertNotIn(forbidden, source)

    def test_02_freeze_real_sample_into_three_batches(self):
        self.setup_plan()
        state = self.state()
        self.assertEqual(state["dataset"]["sourceCount"], 12)
        self.assertEqual(state["dataset"]["selectedCount"], 12)
        self.assertEqual(state["dataset"]["batchSize"], 4)
        self.assertEqual(state["phase"], "READY")
        self.assertEqual(len(state["entries"]), 12)
        self.assertEqual(len(state["world"]), 1)
        self.assertEqual(state["world"][0]["simOwnerToken"], "THIRD_PARTY")
        self.assertIn("P1H_BATCH_COUNT=3", self.call("status"))

    def test_03_normal_apply_and_exact_reverse_batches(self):
        self.setup_plan()
        self.assertIn("P1H_VERIFIED_ROUTES=12", self.call("apply"))
        self.assertEqual(len(self.state()["world"]), 13)
        self.assertIn("P1H_RESULT=IDEMPOTENT_ALREADY_APPLIED", self.call("apply"))
        self.assert_restored()
        self.assertIn("P1H_RESULT=IDEMPOTENT_ALREADY_RESTORED", self.call("recover"))
        kinds = [e["kind"] for e in self.state()["audit"]]
        self.assertEqual(kinds.count("BATCH_VERIFIED"), 3)
        self.assertEqual(kinds.count("BATCH_ROLLBACK_VERIFIED"), 3)

    def test_04_crash_after_intent(self):
        self.setup_plan()
        out = self.call("apply", "--fault", "after_intent", expected=77)
        self.assertIn("P1H_INJECTED_CRASH=after_intent", out)
        self.assertEqual(self.state()["entries"][0]["status"], "INTENT")
        self.assertIn("P1H_RESULT=BLOCKED_FAIL_CLOSED", self.call("apply", expected=2))
        self.assert_restored()

    def test_05_crash_after_world_before_receipt(self):
        self.setup_plan()
        self.call("apply", "--fault", "after_world", expected=77)
        self.assertEqual(len(self.state()["world"]), 5)
        self.assertEqual(self.state()["entries"][0]["status"], "INTENT")
        self.assert_restored()

    def test_06_crash_after_verified_before_next_batch(self):
        self.setup_plan()
        self.call("apply", "--fault", "after_verified", expected=77)
        self.assertEqual(self.state()["entries"][0]["status"], "VERIFIED")
        self.assert_restored()

    def test_07_third_batch_fault_after_prior_batches(self):
        self.setup_plan()
        self.call("apply", "--fault", "after_world", "--fault-batch", "3", expected=77)
        state = self.state()
        self.assertEqual(len(state["world"]), 13)
        self.assertEqual(state["entries"][0]["status"], "VERIFIED")
        self.assertEqual(state["entries"][-1]["status"], "INTENT")
        self.assert_restored()

    def test_08_rollback_crash_after_remove_intent(self):
        self.setup_plan()
        self.call("apply")
        self.call("recover", "--fault", "after_remove_intent",
                  "--fault-batch", "3", expected=77)
        self.assertEqual(self.state()["entries"][-1]["status"], "ROLLBACK_INTENT")
        self.assert_restored()

    def test_09_rollback_crash_after_world_removed(self):
        self.setup_plan()
        self.call("apply")
        self.call("recover", "--fault", "after_remove_world",
                  "--fault-batch", "2", expected=77)
        self.assertEqual(self.state()["entries"][4]["status"], "ROLLBACK_INTENT")
        self.assert_restored()

    def test_10_foreign_same_prefix_blocks_rollback(self):
        self.setup_plan()
        self.call("apply")
        self.call("inject", "--kind", "foreign_collision")
        self.assertIn("P1H_BLOCK_REASON=OWNED_ROUTE_MISSING_OR_MODIFIED",
                      self.call("recover", expected=2))
        self.assertEqual(len(self.state()["world"]), 14)

    def test_11_persistent_same_prefix_blocks_rollback(self):
        self.setup_plan()
        self.call("apply")
        self.call("inject", "--kind", "persistent_collision")
        self.assertIn("P1H_RESULT=BLOCKED_FAIL_CLOSED", self.call("recover", expected=2))
        self.assertEqual(len(self.state()["world"]), 14)

    def test_12_foreign_unrelated_route_is_not_silently_removed(self):
        self.setup_plan()
        self.call("apply")
        self.call("inject", "--kind", "foreign_unrelated")
        self.assertIn("P1H_BLOCK_REASON=UNRELATED_FOREIGN_WORLD_DRIFT",
                      self.call("recover", expected=2))

    def test_13_simulated_owned_identity_drift_blocks(self):
        self.setup_plan()
        self.call("apply")
        self.call("inject", "--kind", "owned_identity_drift")
        self.assertIn("P1H_RESULT=BLOCKED_FAIL_CLOSED", self.call("recover", expected=2))

    def test_14_gateway_drift_blocks_cleanup(self):
        self.setup_plan()
        self.call("apply")
        self.call("inject", "--kind", "gateway_drift")
        self.assertIn("P1H_BLOCK_REASON=ENVIRONMENT_GATEWAY_OR_PROXY_DRIFT",
                      self.call("recover", expected=2))

    def test_15_audit_seal_tamper_blocks(self):
        self.setup_plan()
        self.call("apply")
        self.call("inject", "--kind", "audit_tamper")
        self.assertIn("P1H_BLOCK_REASON=STATE_SEAL_MISMATCH",
                      self.call("recover", expected=2))

    def test_16_frozen_source_drift_blocks(self):
        self.setup_plan()
        self.call("apply")
        self.data.write_text(self.data.read_text(encoding="utf-8") +
                             "198.51.100.0/24\n", encoding="utf-8")
        self.assertIn("P1H_BLOCK_REASON=FROZEN_SOURCE_SHA_CHANGED",
                      self.call("recover", expected=2))

    def test_17_exclusive_lock_blocks_second_writer(self):
        self.setup_plan()
        cmd = [sys.executable, str(SOURCE), "--sandbox",
               str(self.directory), "hold-lock", "--seconds", "1.5"]
        holder = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True)
        try:
            line = holder.stdout.readline().strip()
            self.assertEqual(line, "P1H_LOCK=HELD")
            self.assertIn("P1H_BLOCK_REASON=EXCLUSIVE_WRITER_BUSY",
                          self.call("apply", expected=2))
            self.assertEqual(holder.wait(timeout=5), 0)
        finally:
            if holder.poll() is None:
                holder.kill()
                holder.wait(timeout=5)
            if holder.stdout is not None:
                holder.stdout.close()
            if holder.stderr is not None:
                holder.stderr.close()
        self.assert_restored()

    def test_18_sandbox_outside_root_denied(self):
        arbitrary = Path(tempfile.gettempdir()) / ("unsafe-" + uuid.uuid4().hex)
        cmd = [sys.executable, str(SOURCE), "--sandbox",
               str(arbitrary), "init", "--dataset", str(self.data)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(arbitrary.exists())
        self.assertIn("SANDBOX_OUTSIDE_DEDICATED_ROOT", result.stdout)

    def test_19_duplicate_run_init_fails_without_overwrite(self):
        self.setup_plan()
        before = (self.directory / "state.json").read_bytes()
        self.assertIn("RUN_ALREADY_EXISTS_NO_OVERWRITE",
                      self.call("init", "--dataset", str(self.data), expected=2))
        self.assertEqual(before, (self.directory / "state.json").read_bytes())

    def test_20_preexisting_same_prefix_not_adopted(self):
        first = self.data.read_text(encoding="utf-8").splitlines()[0]
        self.assertIn("PREEXISTING_PREFIX_NOT_ADOPTABLE",
                      self.call("init", "--dataset", str(self.data),
                                "--borrowed-prefix", first, expected=2))
        self.assertFalse((self.directory / "state.json").exists())

    def test_21_duplicate_source_fails(self):
        first = self.data.read_text(encoding="utf-8").splitlines()[0]
        self.data.write_text(first + "\n" + first + "\n", encoding="utf-8")
        self.assertIn("DATASET_MALFORMED_OR_DUPLICATE",
                      self.call("init", "--dataset", str(self.data), expected=2))

    def test_22_noncanonical_source_fails(self):
        self.data.write_text("1.2.3.4/24\n", encoding="utf-8")
        self.assertIn("DATASET_MALFORMED_OR_DUPLICATE",
                      self.call("init", "--dataset", str(self.data), expected=2))

    def test_23_full_5494_corpus_plan_only(self):
        out = self.call("init", "--dataset", str(ORIGINAL),
                        "--batch-size", "256", expected=0)
        self.assertIn("P1H_FROZEN_SOURCE_COUNT=5494", out)
        self.assertIn("P1H_PLAN_PREFIXES=5494", out)
        self.assertIn("P1H_BATCHES=22", out)
        self.assertEqual(self.state()["phase"], "READY")
        self.assertEqual(len(self.state()["world"]), 1)
        self.assertEqual(self.state()["dataset"]["sha256"].upper(),
                         "DFCFE4937E81B2B1221E597519B9F0AD172BC0B7BA48577C062CB6D8B65DECEC")

    def test_24_bad_limit_fails(self):
        self.assertIn("INVALID_PLAN_LIMIT",
                      self.call("init", "--dataset", str(self.data),
                                "--limit", "100000", expected=2))

    def test_25_missing_state_denied(self):
        self.assertIn("STATE_MISSING_OR_SYMLINK", self.call("recover", expected=2))

    def test_26_only_exact_original_borrowed_world_survives(self):
        self.setup_plan()
        before = list(self.state()["baselineWorld"])
        self.call("apply")
        self.call("recover")
        self.assertEqual(self.state()["world"], before)
        self.assertEqual(self.state()["world"][0]["simOwnerToken"], "THIRD_PARTY")


    def test_27_full_corpus_11_batch_apply_recover(self):
        self.call("init", "--dataset", str(ORIGINAL), "--batch-size", "512")
        self.assertIn("P1H_VERIFIED_ROUTES=5494", self.call("apply"))
        self.assertIn("P1H_RESTORED_COUNT=5494", self.call("recover"))
        state = self.state()
        self.assertEqual(state["world"], state["baselineWorld"])
        self.assertEqual(state["phase"], "RESTORED")
        self.assertEqual(len(state["audit"]), 69)

    def test_28_full_corpus_batch_seven_crash_recovery(self):
        self.call("init", "--dataset", str(ORIGINAL), "--batch-size", "512")
        self.call("apply", "--fault", "after_world", "--fault-batch", "7", expected=77)
        state = self.state()
        self.assertEqual(state["entries"][3072]["status"], "INTENT")
        self.assertEqual(state["entries"][0]["status"], "VERIFIED")
        self.assertIn("P1H_RESTORED_COUNT=5494", self.call("recover"))
        self.assertEqual(self.state()["world"], self.state()["baselineWorld"])


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=1).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(BatchMocks)
    )
    print("P1H_TESTS_PASSED=" + str(result.testsRun - len(result.errors) - len(result.failures)))
    print("P1H_TESTS_FAILED=" + str(len(result.errors) + len(result.failures)))
    print("P1H_NATIVE_NETWORK_WRITES_EXECUTED=False")
    print("P1H_RESULT=" + ("MOCK_TESTS_PASS" if result.wasSuccessful() else "MOCK_TESTS_FAILED"))
    sys.exit(0 if result.wasSuccessful() else 1)
