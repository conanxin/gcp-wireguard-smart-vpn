#!/usr/bin/env python3
"""P1N-1 regression suite: current TUN auto-outbound contract and WG parser."""
from __future__ import annotations
import ast
import json
from pathlib import Path
import subprocess
import sys
import unittest
from copy import deepcopy

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import stage_c_p1n1_tun_wg_contract as p1n
from stage_c_p1m_offline_userspace_plan import GateError

ENGINE=HERE/"stage_c_p1n1_tun_wg_contract.py"


class TunWireGuardContractTests(unittest.TestCase):
    def setUp(self):
        self.variants=p1n.make_variants()

    def test_01_four_synthetic_variants_exist(self):
        self.assertEqual(set(self.variants),{
            "auto_inherited","auto_with_explicit_wlan_override",
            "implicit_auto_with_explicit_wlan","implicit_auto_without_manual_override"})

    def test_02_existing_runtime_pattern_auto_inherited(self):
        cfg=self.variants["auto_inherited"]
        self.assertEqual(cfg["inbounds"][0]["settings"]["autoOutboundsInterface"],"auto")
        self.assertNotIn("streamSettings",cfg["outbounds"][0])

    def test_03_manual_wlan_is_explicit_override(self):
        self.assertEqual(self.variants["auto_with_explicit_wlan_override"]
                         ["outbounds"][0]["streamSettings"]["sockopt"]["interface"],"WLAN")

    def test_04_auto_system_route_implicitly_enables_auto_binding(self):
        cfg=self.variants["implicit_auto_without_manual_override"]
        self.assertNotIn("autoOutboundsInterface",cfg["inbounds"][0]["settings"])
        self.assertEqual(cfg["inbounds"][0]["settings"]["autoSystemRoutingTable"],
                         ["0.0.0.0/0"])

    def test_05_implicit_auto_manual_wlan_variant(self):
        cfg=self.variants["implicit_auto_with_explicit_wlan"]
        self.assertNotIn("autoOutboundsInterface",cfg["inbounds"][0]["settings"])
        self.assertEqual(cfg["outbounds"][0]["streamSettings"]["sockopt"]["interface"],"WLAN")

    def test_06_all_variants_use_synthetic_tun_name(self):
        for cfg in self.variants.values():
            self.assertEqual(cfg["inbounds"][0]["settings"]["name"],p1n.TEST_TUN_NAME)

    def test_07_no_tun_listen_or_port(self):
        for cfg in self.variants.values():
            self.assertNotIn("listen",cfg["inbounds"][0])
            self.assertNotIn("port",cfg["inbounds"][0])

    def test_08_synthetic_tun_has_no_network_listener_fields(self):
        for cfg in self.variants.values():
            self.assertNotIn("listen",cfg["inbounds"][0])
            self.assertNotIn("port",cfg["inbounds"][0])

    def test_09_wfp_dns_and_misconfig_guards(self):
        for cfg in self.variants.values():
            self.assertEqual(set(cfg["inbounds"][0]["settings"]["autoSystemWfpBlockLeak"]),
                             {"dns","misconfigtun"})

    def test_09_only_ipv4_default_is_routed_to_synthetic_tun(self):
        for cfg in self.variants.values():
            self.assertEqual(cfg["inbounds"][0]["settings"]["autoSystemRoutingTable"],
                             ["0.0.0.0/0"])

    def test_10_wireguard_no_kernel_tun(self):
        self.assertTrue(all(c["outbounds"][0]["settings"]["noKernelTun"]
                            for c in self.variants.values()))

    def test_11_reserved_documentation_endpoint_only(self):
        self.assertTrue(all(c["outbounds"][0]["settings"]["peers"][0]["endpoint"]
                            == "192.0.2.1:443" for c in self.variants.values()))

    def test_12_generated_random_test_keys(self):
        for c in self.variants.values():
            self.assertNotIn("__SYNTHETIC_ONLY",
                             c["outbounds"][0]["settings"]["secretKey"])
            self.assertNotIn("__SYNTHETIC_ONLY",
                             c["outbounds"][0]["settings"]["peers"][0]["publicKey"])

    def test_13_no_production_endpoint(self):
        all_json=json.dumps(list(self.variants.values()))
        endpoints = {peer.get("endpoint") for c in self.variants.values()
                     for peer in c["outbounds"][0]["settings"]["peers"]}
        self.assertEqual(endpoints,{p1n.RESERVED_ENDPOINT})
        self.assertNotIn("PrivateKey =",all_json)

    def test_14_remote_dns_is_reference_only(self):
        for c in self.variants.values():
            self.assertEqual(c["outbounds"][0]["settings"]["remoteDNS"],["10.66.66.1"])

    def test_15_wg_is_default_outbound(self):
        for c in self.variants.values():
            self.assertEqual(c["outbounds"][0]["tag"],"GCP_WG_OUTBOUND_DRAFT")
            self.assertEqual(c["outbounds"][0]["protocol"],"wireguard")

    def test_16_cn_direct_outbound_present(self):
        for c in self.variants.values():
            self.assertEqual(c["outbounds"][1]["tag"],"CN_DIRECT_DRAFT")
            self.assertEqual(c["outbounds"][1]["protocol"],"freedom")

    def test_17_cn_domain_route_to_direct(self):
        for c in self.variants.values():
            self.assertEqual(c["routing"]["rules"][0]["domain"],["geosite:cn"])
            self.assertEqual(c["routing"]["rules"][0]["outboundTag"],"CN_DIRECT_DRAFT")

    def test_18_cn_ip_route_to_direct(self):
        for c in self.variants.values():
            self.assertEqual(c["routing"]["rules"][1]["ip"],["geoip:private","geoip:cn"])
            self.assertEqual(c["routing"]["rules"][1]["outboundTag"],"CN_DIRECT_DRAFT")

    def test_19_no_global_dns_claim(self):
        for c in self.variants.values():
            self.assertNotIn("dns",c)

    def test_20_no_native_half_default_routes(self):
        for c in self.variants.values():
            self.assertNotIn("0.0.0.0/1",json.dumps(c))
            self.assertNotIn("128.0.0.0/1",json.dumps(c))

    def test_21_all_four_variants_pass_contract(self):
        for label,cfg in self.variants.items():
            p1n.validate_candidate(label,cfg)

    def test_22_wrong_auto_interface_is_rejected(self):
        cfg=deepcopy(self.variants["auto_inherited"])
        cfg["inbounds"][0]["settings"]["autoOutboundsInterface"]="xray_tun"
        with self.assertRaisesRegex(GateError,"AUTO_OUTBOUNDS_INTERFACE"):
            p1n.validate_candidate("auto_inherited",cfg)

    def test_23_missing_wfp_dns_guard_rejected(self):
        cfg=deepcopy(self.variants["auto_inherited"])
        cfg["inbounds"][0]["settings"]["autoSystemWfpBlockLeak"]=["misconfigtun"]
        with self.assertRaisesRegex(GateError,"SYNTHETIC_WFP_GUARDS_CHANGED"):
            p1n.validate_candidate("auto_inherited",cfg)

    def test_24_missing_default_route_rejected(self):
        cfg=deepcopy(self.variants["auto_inherited"])
        cfg["inbounds"][0]["settings"]["autoSystemRoutingTable"]=[]
        with self.assertRaisesRegex(GateError,"SYNTHETIC_TUN_ROUTE_SCOPE_CHANGED"):
            p1n.validate_candidate("auto_inherited",cfg)

    def test_25_kernel_tun_true_rejected(self):
        cfg=deepcopy(self.variants["auto_inherited"])
        cfg["outbounds"][0]["settings"]["noKernelTun"]=False
        with self.assertRaisesRegex(GateError,"WG_KERNEL_TUN"):
            p1n.validate_candidate("auto_inherited",cfg)

    def test_26_real_endpoint_rejected(self):
        cfg=deepcopy(self.variants["auto_inherited"])
        cfg["outbounds"][0]["settings"]["peers"][0]["endpoint"]="203.0.113.8:443"
        with self.assertRaisesRegex(GateError,"REAL_PEER_ENDPOINT_FORBIDDEN"):
            p1n.validate_candidate("auto_inherited",cfg)

    def test_27_unknown_candidate_label_rejected(self):
        with self.assertRaisesRegex(GateError,"UNKNOWN_CANDIDATE"):
            p1n.validate_candidate("production",self.variants["auto_inherited"])

    def test_28_forbidden_live_auth_flags_never_granted(self):
        report=p1n.route_risk_classifier("xray_tun",live_peer_confirmed=True,
              live_udp_bind_verified=True,dns_e2e_verified=True,inperson_permission=True)
        self.assertFalse(report["startUserspaceWireGuardAuthorized"])
        self.assertFalse(report["nativeRoutingChangesAuthorized"])

    def test_29_native_route_classifier_does_not_claim_socket_result(self):
        report=p1n.route_risk_classifier("xray_tun")
        self.assertTrue(report["historicalEndpointRoutesToTun"])
        self.assertTrue(report["physicalInterfaceBindNeeded"])
        self.assertEqual(report["result"],"BLOCKED_NO_FRESH_GCP_OR_SOCKET_PROOF")

    def test_30_engine_has_no_socket_or_winreg_mutator_imports(self):
        tree=ast.parse(ENGINE.read_text(encoding="utf-8"))
        imports={n.module for n in ast.walk(tree) if isinstance(n,ast.ImportFrom)}
        imports|={a.name for n in ast.walk(tree) if isinstance(n,ast.Import) for a in n.names}
        self.assertFalse(imports & {"socket","winreg","requests","urllib.request","win32api","win32com"})

    def test_31_contract_cli_is_not_deployable(self):
        run=subprocess.run([sys.executable,str(ENGINE),"--mode","contract"],
                           capture_output=True,text=True,timeout=12)
        self.assertEqual(run.returncode,0,run.stderr)
        payload=json.loads(run.stdout)
        self.assertFalse(payload["liveStartAuthorized"])
        self.assertFalse(payload["nativeNetworkMutationsPerformed"])
        self.assertEqual(payload["result"],"STATIC_P1N1_CONTRACT_PASS")

    def test_32_core_mode_without_pids_blocks(self):
        run=subprocess.run([sys.executable,str(ENGINE),"--mode","core-test"],
                           capture_output=True,text=True,timeout=12)
        self.assertEqual(run.returncode,4,run.stderr)
        self.assertFalse(json.loads(run.stdout)["liveStartAuthorized"])

    def test_33_parser_results_are_not_live_socket_proof(self):
        report=p1n.route_risk_classifier("WLAN",live_peer_confirmed=True,
                    live_udp_bind_verified=True,dns_e2e_verified=True,
                    inperson_permission=True)
        self.assertFalse(report["startUserspaceWireGuardAuthorized"])

    def test_34_runtime_inspector_does_not_print_config_values(self):
        src=ENGINE.read_text(encoding="utf-8")
        self.assertNotIn('print(config)',src)
        self.assertNotIn('print(settings)',src)
        self.assertIn('"productionConfigValuesPrinted": False',src)

    def test_35_no_production_config_write_path(self):
        src=ENGINE.read_text(encoding="utf-8")
        self.assertNotIn("write_text(config",src)
        self.assertIn('"productionConfigModified": False',src)


if __name__=="__main__":
    result=unittest.TextTestRunner(verbosity=1).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(TunWireGuardContractTests))
    passed=result.testsRun-len(result.failures)-len(result.errors)
    print("P1N1_REGRESSIONS_PASS="+str(passed))
    print("P1N1_REGRESSIONS_FAIL="+str(len(result.failures)+len(result.errors)))
    print("P1N1_NATIVE_NETWORK_MUTATIONS=False")
    print("P1N1_RESULT="+("OFFLINE_CONTRACT_PASS" if result.wasSuccessful()
                          else "OFFLINE_CONTRACT_FAILED"))
    sys.exit(0 if result.wasSuccessful() else 1)
