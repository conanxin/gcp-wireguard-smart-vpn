#!/usr/bin/env python3
"""Offline Stage C P1 safety harness. Runs in WSL/Python stdlib only."""
import copy
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from stage_c_p1_model import (CN_DNS, XRAY_PROXY, NO_NATIVE_MUTATORS,
    NrptRule, Route, World, canonical_cidrs, canonical_namespaces,
    create_plan, fixture_world, load_dataset, route_for_ip, simulate)


CN = ("1.0.1.0/24", "223.5.5.0/24", "36.0.0.0/8")
NS = (".baidu.com", "baidu.com", "full.example.cn")


def world_plan(preexisting=None):
    world = fixture_world(list(CN), NS, preexisting=preexisting)
    return world, create_plan(world, CN, NS)


class StageCP1OfflineTests(unittest.TestCase):
    def test_no_native_operations_exist(self):
        self.assertTrue(NO_NATIVE_MUTATORS)
        self.assertFalse(hasattr(sys.modules["stage_c_p1_model"], "run_powershell"))
        self.assertFalse(hasattr(sys.modules["stage_c_p1_model"], "apply_windows_routes"))

    def test_current_xray_only_plan_can_be_previewed(self):
        w, p = world_plan()
        self.assertEqual(p.blockers, ())
        self.assertEqual(len(p.add), 3)
        self.assertFalse(p.metadata()["live_approved"])
        self.assertEqual(w.proxy_enabled, 1)
        self.assertFalse(w.wg_active)

    def test_successful_full_mock_lifecycle_and_exact_rollback(self):
        w, p = world_plan()
        original = w.fingerprint()
        o = simulate(w, p)
        self.assertEqual(o.status, "PASS_MOCK_ONLY")
        self.assertTrue(o.success_marker)
        self.assertTrue(o.baseline_restored)
        self.assertEqual(o.state.fingerprint(), original)
        self.assertEqual(w.fingerprint(), original)
        self.assertEqual(len(o.journal.owned), 3)
        self.assertIn("MODEL_CN_IPV4_VIA_PHYSICAL", o.journal.events)
        self.assertIn("MODEL_FOREIGN_IPV4_VIA_WG", o.journal.events)
        self.assertIn("VERIFY_BASELINE_PASS", o.journal.events)

    def test_preexisting_physical_route_preserved(self):
        external = Route("223.5.5.0/24", 13, "192.0.2.1", metric=19)
        w, p = world_plan(preexisting=[external])
        self.assertEqual(len(p.borrowed), 1)
        self.assertEqual(len(p.add), 2)
        out = simulate(w, p)
        self.assertEqual(out.status, "PASS_MOCK_ONLY")
        self.assertIn(external, out.state.routes)
        self.assertEqual(out.state.fingerprint(), w.fingerprint())
        self.assertNotIn(external, out.journal.owned)

    def test_competing_third_party_route_blocks_before_write(self):
        alien = Route("223.5.5.0/24", 98, "10.1.1.1", metric=1)
        w, p = world_plan(preexisting=[alien])
        self.assertTrue(any("CONFLICTING_ROUTE_" in x for x in p.blockers))
        out = simulate(w, p)
        self.assertEqual(out.status, "BLOCKED")
        self.assertFalse(out.success_marker)
        self.assertEqual(out.state.routes, [alien])

    def test_xray_tun_active_blocks(self):
        w, _ = world_plan()
        w.xray_tun = True
        p = create_plan(w, CN, NS)
        self.assertIn("XRAY_TUN_CONFLICT", p.blockers)
        self.assertFalse(simulate(w, p).success_marker)

    def test_already_armed_timer_blocks(self):
        w, _ = world_plan()
        w.timer_armed = True
        p = create_plan(w, CN, NS)
        self.assertIn("ANOTHER_TIMER_ARMED", p.blockers)

    def test_wrong_proxy_server_blocks(self):
        w, _ = world_plan()
        w.proxy_server = "127.0.0.1:7898"
        p = create_plan(w, CN, NS)
        self.assertIn("UNEXPECTED_PROXY_SERVER", p.blockers)

    def test_nrpt_wrong_resolver_fails_closed(self):
        w, _ = world_plan()
        w.nrpt[0] = NrptRule(w.nrpt[0].rule_id,
                             w.nrpt[0].namespaces, ("8.8.8.8",))
        p = create_plan(w, CN, NS)
        self.assertIn("WRONG_NRPT_NAMESERVER", p.blockers)
        self.assertEqual(simulate(w, p).status, "BLOCKED")

    def test_nrpt_missing_and_extra_set_diff(self):
        w, _ = world_plan()
        w.nrpt[0] = NrptRule("GCP-WG-SMART-FULLCN-001",
                            (".baidu.com", "alien.example"), (CN_DNS,))
        p = create_plan(w, CN, NS)
        self.assertTrue(any(x.startswith("NRPT_SET_DIFF") for x in p.blockers))

    def test_nrpt_duplicate_namespace_rows_detected(self):
        w, _ = world_plan()
        w.nrpt.append(NrptRule("GCP-WG-SMART-FULLCN-002",
                                (".baidu.com",), (CN_DNS,)))
        p = create_plan(w, CN, NS)
        self.assertTrue(any(x.startswith("NRPT_DUPLICATE_ROWS") for x in p.blockers))

    def test_route_100_failure_rolls_back_exact_owned_set(self):
        # 150 disjoint synthetic prefixes: route #100 faults after 99 adds.
        prefixes = [f"11.{i//256}.{i%256}.0/24" for i in range(150)]
        w = fixture_world(prefixes, NS)
        p = create_plan(w, prefixes, NS)
        self.assertEqual(len(p.add), 150)
        o = simulate(w, p, failure_at_route=100)
        self.assertEqual(o.status, "FAILED_ROLLED_BACK")
        self.assertFalse(o.success_marker)
        self.assertTrue(o.baseline_restored)
        self.assertEqual(len(o.journal.owned), 99)
        self.assertEqual(o.state.fingerprint(), w.fingerprint())

    def test_failure_before_proxy_disable_rolls_back_tunnel(self):
        w, p = world_plan()
        o = simulate(w, p, fail_proxy_disable=True)
        self.assertEqual(o.status, "FAILED_ROLLED_BACK")
        self.assertTrue(o.baseline_restored)
        self.assertFalse(o.state.wg_active)
        self.assertEqual(o.state.proxy_enabled, 1)
        self.assertFalse(o.success_marker)

    def test_proxy_restore_failure_does_not_claim_success(self):
        w, p = world_plan()
        o = simulate(w, p, fail_proxy_restore=True)
        self.assertEqual(o.status, "ROLLBACK_INCOMPLETE")
        self.assertFalse(o.success_marker)
        self.assertFalse(o.baseline_restored)
        self.assertEqual(o.state.proxy_enabled, 0)

    def test_nrpt_external_mutation_not_overwritten(self):
        w, p = world_plan()
        o = simulate(w, p, external_nrpt_change_at=1)
        self.assertEqual(o.status, "ROLLBACK_INCOMPLETE")
        self.assertFalse(o.success_marker)
        self.assertIn("NRPT_DRIFT_NOT_OVERWRITTEN", o.reasons)
        self.assertEqual(o.state.nrpt[0].servers, ("8.8.8.8",))

    def test_gateway_drift_detected_and_not_falsely_recovered(self):
        w, p = world_plan()
        o = simulate(w, p, gateway_change_at=2)
        self.assertEqual(o.status, "ROLLBACK_INCOMPLETE")
        self.assertFalse(o.success_marker)
        self.assertIn("BASELINE_NOT_FULLY_RESTORED", o.reasons)

    def test_third_party_route_inserted_during_run_not_deleted(self):
        w, p = world_plan()
        o = simulate(w, p, route_conflict_at=1)
        self.assertEqual(o.status, "ROLLBACK_INCOMPLETE")
        self.assertFalse(o.success_marker)
        self.assertTrue(any("OWNED_ROUTE_AMBIGUOUS_" in x for x in o.reasons))
        self.assertGreater(len(o.state.routes), 0)

    def test_watchdog_timeout_rolls_back_but_not_success(self):
        w, p = world_plan()
        o = simulate(w, p, watchdog_timeout_at=2)
        self.assertEqual(o.status, "TIMEOUT_ROLLED_BACK")
        self.assertTrue(o.baseline_restored)
        self.assertFalse(o.success_marker)
        self.assertIn("INDEPENDENT_TIMER_SIMULATED_FIRE", o.journal.events)

    def test_stale_prestate_blocks(self):
        w, p = world_plan()
        w.proxy_enabled = 0  # change between planning and mock execution
        o = simulate(w, p)
        self.assertEqual(o.status, "BLOCKED_STALE_SNAPSHOT")
        self.assertFalse(o.success_marker)
        self.assertEqual(len(o.journal.owned), 0)

    def test_idempotent_repeated_simulation_same_source(self):
        w, p = world_plan()
        a = simulate(w, p, run_id="SIM-A")
        b = simulate(w, p, run_id="SIM-B")
        self.assertEqual(a.status, b.status)
        self.assertTrue(a.success_marker and b.success_marker)
        self.assertEqual(a.state.fingerprint(), b.state.fingerprint())
        self.assertEqual(w.fingerprint(), a.state.fingerprint())

    def test_no_wireguard_prestate_claimed_when_proxy_only(self):
        w, _ = world_plan()
        w.wg_active = True
        w.wg_half_routes = True
        p = create_plan(w, CN, NS)
        self.assertIn("WG_PRESTATE_NOT_OFF", p.blockers)

    def test_cidr_validator_rejects_duplicates_overlaps_and_misaligned(self):
        for bad in (
            ["1.1.1.0/24", "1.1.1.0/24"],
            ["1.1.1.0/24", "1.1.1.0/25"],
            ["1.1.1.1/24"],
            ["127.0.0.0/33"]
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                canonical_cidrs(bad)

    def test_full_real_dataset_plan_counts(self):
        root = str(Path(__file__).resolve().parent.parent)
        cidrs, ns = load_dataset(root)
        self.assertEqual(len(cidrs), 5494)
        self.assertEqual(len(ns), 12160)
        self.assertIn(".baidu.com", ns)
        self.assertNotIn(".google.com", ns)
        w = World(
            routes=[],
            nrpt=[NrptRule(f"GCP-WG-SMART-FULLCN-{i+1:03d}",
                           ns[i*500:(i+1)*500], (CN_DNS,))
                  for i in range((len(ns)+499)//500)]
        )
        p = create_plan(w, cidrs, ns, full_dataset=True)
        self.assertEqual(p.blockers, ())
        self.assertEqual(len(p.add), 5494)
        self.assertEqual(len(w.nrpt), 25)
        self.assertEqual(w.proxy_enabled, 1)
        self.assertFalse(w.wg_active)


if __name__ == "__main__":
    unittest.main(verbosity=2)
