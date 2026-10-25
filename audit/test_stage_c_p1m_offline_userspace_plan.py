#!/usr/bin/env python3
"""P1M: security, contract, and synthetic-only policy regressions."""
from __future__ import annotations

import ast
import base64
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import stage_c_p1m_offline_userspace_plan as p1m


class P1MOfflinePolicyTests(unittest.TestCase):
    def setUp(self):
        self.valid = p1m.load_template()

    def denied(self, mutate, expected: str):
        target = deepcopy(self.valid)
        mutate(target)
        with self.assertRaisesRegex(p1m.GateError, expected):
            p1m.validate_template(target)

    def test_01_valid_non_deployable_template(self):
        p1m.validate_template(self.valid)

    def test_02_no_listening_inbounds(self):
        self.assertEqual(self.valid["inbounds"], [])

    def test_03_outbound_default_is_fail_closed_wg(self):
        self.assertEqual(self.valid["outbounds"][0]["protocol"], "wireguard")

    def test_04_userspace_no_kernel_tun(self):
        self.assertTrue(self.valid["outbounds"][0]["settings"]["noKernelTun"])

    def test_05_test_only_endpoint_is_reserved(self):
        self.assertEqual(
            self.valid["outbounds"][0]["settings"]["peers"][0]["endpoint"],
            "192.0.2.1:443",
        )

    def test_06_placeholder_only_no_user_private_key(self):
        self.assertEqual(self.valid["outbounds"][0]["settings"]["secretKey"],
                         p1m.PLACEHOLDER_CLIENT)

    def test_07_synthetic_key_material_has_valid_shape(self):
        obj = p1m.materialize_synthetic(self.valid)
        secret = obj["outbounds"][0]["settings"]["secretKey"]
        public = obj["outbounds"][0]["settings"]["peers"][0]["publicKey"]
        self.assertNotEqual(secret, p1m.PLACEHOLDER_CLIENT)
        self.assertNotEqual(public, p1m.PLACEHOLDER_SERVER)
        self.assertEqual(len(base64.b64decode(secret)), 32)
        self.assertEqual(len(base64.b64decode(public)), 32)
        self.assertNotIn("_NOTICE", obj)
        self.assertFalse(obj["inbounds"])

    def test_08_two_invocations_use_different_random_test_keys(self):
        a = p1m.materialize_synthetic(self.valid)
        b = p1m.materialize_synthetic(self.valid)
        self.assertNotEqual(a["outbounds"][0]["settings"]["secretKey"],
                            b["outbounds"][0]["settings"]["secretKey"])

    def test_09_no_real_gcp_endpoint_or_credentials_in_template(self):
        raw = json.dumps(self.valid)
        self.assertNotIn("35.212.139.174", raw)
        self.assertNotIn("PrivateKey =", raw)
        self.assertNotIn("0.0.0.0/1", raw)

    def test_10_cn_domain_rule(self):
        self.assertEqual(self.valid["routing"]["rules"][0]["domain"],
                         ["geosite:cn"])

    def test_11_cn_private_geoip_rule(self):
        self.assertEqual(self.valid["routing"]["rules"][1]["ip"],
                         ["geoip:private", "geoip:cn"])

    def test_12_default_noncn_uses_wg_first_outbound(self):
        self.assertEqual(self.valid["outbounds"][0]["tag"],
                         "GCP_WG_OUTBOUND_DRAFT")

    def test_13_wireguard_remotedns_reference(self):
        self.assertEqual(self.valid["outbounds"][0]["settings"]["remoteDNS"],
                         ["10.66.66.1"])

    def test_14_no_global_dns_without_e2e_gates(self):
        self.assertNotIn("dns", self.valid)

    def test_15_native_route_prefix_not_embedded(self):
        self.assertNotIn("0.0.0.0/1", json.dumps(self.valid))
        self.assertNotIn("128.0.0.0/1", json.dumps(self.valid))

    def test_16_no_inbounds_precondition_enforced(self):
        self.denied(lambda x: x["inbounds"].append({"port":7897}),
                    "MUST_HAVE_ZERO_INBOUNDS")

    def test_17_prevent_default_direct_outbound(self):
        self.denied(lambda x: x["outbounds"].reverse(),
                    "FIRST_OUTBOUND_MUST_BE_FAIL_CLOSED_WG")

    def test_18_no_kernel_tun_false_rejected(self):
        self.denied(lambda x: x["outbounds"][0]["settings"].update(
                    noKernelTun=False), "USERSpace_NO_KERNEL_TUN_REQUIRED")

    def test_19_real_server_ip_rejected(self):
        self.denied(lambda x: x["outbounds"][0]["settings"]["peers"][0].update(
                    endpoint="198.51.100.25:443"),
                    "REAL_ENDPOINT_FORBIDDEN_IN_SHARED_TEMPLATE")

    def test_20_real_private_key_rejected(self):
        self.denied(lambda x: x["outbounds"][0]["settings"].update(
                    secretKey="SENSITIVE_SHOULD_NOT_BE_HERE"),
                    "TEMPLATE_MUST_NOT_CONTAIN_REAL_CLIENT_PRIVATE_KEY")

    def test_21_client_address_changed_rejected(self):
        self.denied(lambda x: x["outbounds"][0]["settings"].update(
                    address=["10.0.0.3"]), "CLIENT_ADDRESS_HISTORICAL_REFERENCE_ONLY")

    def test_22_dns_route_not_verified_rejected(self):
        self.denied(lambda x: x.update(dns={"servers":["223.5.5.5"]}),
                    "BUILTIN_DNS_NOT_YET_E2E_VERIFIED")

    def test_23_non_cn_fallback_to_direct_is_not_allowed(self):
        self.denied(lambda x: x["routing"]["rules"].append({
                    "type":"field", "domain":["domain:example.com"],
                    "outboundTag":"CN_DIRECT_DRAFT"}),
                    "ONLY_TWO_REVIEWED_CN_ROUTES_ALLOWED")

    def test_24_ip_on_demand_requires_explicit_dns_review(self):
        self.denied(lambda x: x["routing"].update(domainStrategy="IPOnDemand"),
                    "UNTESTED_DNS_RESOLUTION_STRATEGY_REJECTED")

    def test_25_insecure_allowedips_ipv6_scope_rejected(self):
        self.denied(lambda x: x["outbounds"][0]["settings"]["peers"][0].update(
                    allowedIPs=["0.0.0.0/0", "::/0"]),
                    "WG_OUTBOUND_MUST_BE_IPV4_ONLY_IN_OFFLINE_DRAFT")

    def test_26_turn_on_keepalive_rejected_for_static_test(self):
        self.denied(lambda x: x["outbounds"][0]["settings"]["peers"][0].update(
                    keepAlive=25), "KEEPALIVE_FORBIDDEN_IN_OFFLINE_DRAFT")

    def test_27_readonly_contract_cli_returns_no_auth(self):
        run = subprocess.run(
            [sys.executable, str(ROOT / "stage_c_p1m_offline_userspace_plan.py"),
             "--mode", "contract"],
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        payload = json.loads(run.stdout)
        self.assertFalse(payload["templateIsDeployable"])
        self.assertFalse(payload["networkMutationsPerformed"])
        self.assertEqual(payload["result"], "TEMPLATE_CONTRACT_PASS")

    def test_28_engine_imports_no_winreg_socket_or_network(self):
        data = (ROOT / "stage_c_p1m_offline_userspace_plan.py").read_text()
        tree = ast.parse(data)
        imports = {alias.name for node in ast.walk(tree)
                   if isinstance(node, ast.Import) for alias in node.names}
        imports |= {node.module for node in ast.walk(tree)
                    if isinstance(node, ast.ImportFrom)}
        for denied in ("socket","winreg","requests","urllib.request","win32api"):
            self.assertNotIn(denied, imports)

    def test_29_asset_pair_detection_can_be_mocked(self):
        with tempfile.TemporaryDirectory(prefix="p1m-fixture-") as folder:
            root = Path(folder)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            image = bin_dir / "xray.exe"
            image.write_bytes(b"this is NOT a real executable")
            (root / "geoip.dat").write_bytes(b"test-geoip")
            (root / "geosite.dat").write_bytes(b"test-geosite")
            found, flags = p1m.local_asset_dir(image)
            self.assertEqual(found, root)
            self.assertTrue(flags["assetsFound"])
            self.assertEqual(len(flags["geoipSHA256Prefix"]),16)

    def test_30_missing_asset_pair_is_blocked(self):
        with tempfile.TemporaryDirectory(prefix="p1m-fixture-") as folder:
            image = Path(folder) / "xray.exe"
            image.write_bytes(b"fake")
            _, flags = p1m.local_asset_dir(image)
            self.assertFalse(flags["assetsFound"])

    def test_31_wrong_syntax_or_replaced_marker_fails(self):
        self.denied(lambda x:x.update(_NOTICE="PRODUCTION"),
                    "DOCUMENTATION_ONLY_BANNER_REQUIRED")

    def test_32_unexpected_secret_type_is_rejected(self):
        self.denied(lambda x:x["outbounds"][0]["settings"].update(
                    secretKey=1234),
                    "TEMPLATE_MUST_NOT_CONTAIN_REAL_CLIENT_PRIVATE_KEY")

    def test_33_gcp_server_status_not_conflated_with_parser(self):
        self.assertEqual(p1m.SERVER_READONLY,
                         "BLOCKED_NO_AUTHORIZED_GCP_SSH_TARGET")

    def test_34_synthetic_generate_has_exact_one_peer(self):
        v=p1m.materialize_synthetic(self.valid)
        self.assertEqual(len(v["outbounds"][0]["settings"]["peers"]),1)

    def test_35_no_secret_print_in_engine_api(self):
        source=(ROOT/"stage_c_p1m_offline_userspace_plan.py").read_text()
        self.assertNotIn('print(settings["secretKey"])',source)
        self.assertNotIn("print(cfg)",source)


if __name__ == "__main__":
    result=unittest.TextTestRunner(verbosity=1).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(P1MOfflinePolicyTests)
    )
    passed=result.testsRun-len(result.failures)-len(result.errors)
    print(f"P1M_OFFLINE_TESTS_PASS={passed}")
    print(f"P1M_OFFLINE_TESTS_FAIL={len(result.failures)+len(result.errors)}")
    print("P1M_NETWORK_MUTATIONS_PERFORMED=False")
    print("P1M_RESULT=" + ("CONTRACT_TESTS_PASS" if result.wasSuccessful()
                          else "CONTRACT_TESTS_FAILED"))
    sys.exit(0 if result.wasSuccessful() else 1)
