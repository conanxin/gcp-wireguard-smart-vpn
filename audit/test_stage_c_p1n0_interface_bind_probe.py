#!/usr/bin/env python3
"""P1N-0 regression contract: not a live tunnel test."""
from __future__ import annotations
import ast
import json
from pathlib import Path
import subprocess
import sys
import unittest

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from stage_c_p1m_offline_userspace_plan import (
    load_template, validate_template, materialize_synthetic, GateError,
)
import stage_c_p1n0_interface_bind_probe as p1n

ENGINE=HERE/"stage_c_p1n0_interface_bind_probe.py"


class PreliveSafetyTests(unittest.TestCase):
    def setUp(self):
        self.doc=load_template()
        validate_template(self.doc)
        self.variants=p1n.make_candidates(materialize_synthetic(self.doc))

    def test_01_offline_base_config(self):
        self.assertEqual(self.variants["base"]["inbounds"], [])

    def test_02_config_has_two_variants(self):
        self.assertEqual(set(self.variants), {"base","bound_wlan"})

    def test_03_wlan_candidate_sockopt(self):
        self.assertEqual(self.variants["bound_wlan"]["outbounds"][0]
                         ["streamSettings"]["sockopt"]["interface"],"WLAN")

    def test_04_no_sockopt_in_base(self):
        self.assertNotIn("streamSettings",self.variants["base"]["outbounds"][0])

    def test_05_wg_no_kernel_tun_in_both(self):
        self.assertTrue(all(v["outbounds"][0]["settings"]["noKernelTun"]
                            for v in self.variants.values()))

    def test_06_reserved_peer_endpoint_both(self):
        self.assertTrue(all(
            v["outbounds"][0]["settings"]["peers"][0]["endpoint"]=="192.0.2.1:443"
            for v in self.variants.values()))

    def test_07_zero_listener_both(self):
        self.assertTrue(all(v["inbounds"]==[] for v in self.variants.values()))

    def test_08_no_real_private_placeholder_remains_in_generated_json(self):
        self.assertTrue(all(
            "__SYNTHETIC_ONLY" not in v["outbounds"][0]["settings"]["secretKey"]
            for v in self.variants.values()))

    def test_09_direct_geoip_cn(self):
        self.assertEqual(self.variants["base"]["routing"]["rules"][1]["ip"],
                         ["geoip:private","geoip:cn"])

    def test_10_direct_geosite_cn(self):
        self.assertEqual(self.variants["base"]["routing"]["rules"][0]["domain"],
                         ["geosite:cn"])

    def test_11_unknown_uses_first_wg_outbound(self):
        self.assertEqual(self.variants["base"]["outbounds"][0]["protocol"],"wireguard")

    def test_12_wlan_binding_is_only_difference(self):
        a=self.variants["base"].copy()
        b=self.variants["bound_wlan"].copy()
        a.pop("outbounds");b.pop("outbounds")
        self.assertEqual(a,b)
        self.assertEqual(self.variants["base"]["outbounds"][0]["settings"],
                         self.variants["bound_wlan"]["outbounds"][0]["settings"])

    def test_13_alias_mutation_is_rejected(self):
        with self.assertRaisesRegex(GateError,"DYNAMIC_ALIAS_CONFIRMATION_REQUIRED"):
            p1n.make_candidates(materialize_synthetic(self.doc),"xray_tun")

    def test_14_other_physical_name_rejected(self):
        with self.assertRaisesRegex(GateError,"DYNAMIC_ALIAS_CONFIRMATION_REQUIRED"):
            p1n.make_candidates(materialize_synthetic(self.doc),"Ethernet")

    def test_15_inbound_addition_rejected(self):
        fixture=materialize_synthetic(self.doc)
        fixture["inbounds"].append({"port":8888})
        with self.assertRaisesRegex(GateError,"NO_LISTENERS_ALLOWED"):
            p1n.make_candidates(fixture)

    def test_16_real_peer_endpoint_rejected(self):
        fixture=materialize_synthetic(self.doc)
        fixture["outbounds"][0]["settings"]["peers"][0]["endpoint"]="8.8.8.8:443"
        with self.assertRaisesRegex(GateError,"REAL_ENDPOINT_FORBIDDEN"):
            p1n.make_candidates(fixture)

    def test_17_disabled_userspace_rejected(self):
        fixture=materialize_synthetic(self.doc)
        fixture["outbounds"][0]["settings"]["noKernelTun"]=False
        with self.assertRaisesRegex(GateError,"NO_KERNEL_TUN_REQUIRED"):
            p1n.make_candidates(fixture)

    def test_18_default_direct_rejected(self):
        fixture=materialize_synthetic(self.doc)
        fixture["outbounds"].reverse()
        with self.assertRaisesRegex(GateError,"FIRST_OUTBOUND_MUST_BE_WIREGUARD"):
            p1n.make_candidates(fixture)

    def test_19_current_tun_selected_requires_external_bypass(self):
        r=p1n.route_risk_classifier("xray_tun")
        self.assertTrue(r["historicalEndpointRoutesToTun"])
        self.assertTrue(r["physicalInterfaceBindNeeded"])
        self.assertFalse(r["startUserspaceWireGuardAuthorized"])

    def test_20_not_tun_still_cannot_assume_gcp_service(self):
        r=p1n.route_risk_classifier("WLAN")
        self.assertFalse(r["historicalEndpointRoutesToTun"])
        self.assertFalse(r["startUserspaceWireGuardAuthorized"])

    def test_21_even_fabricated_all_true_flags_cannot_authorize(self):
        r=p1n.route_risk_classifier("WLAN",live_peer_confirmed=True,
                                   live_udp_bind_verified=True,
                                   dns_e2e_verified=True,
                                   inperson_permission=True)
        self.assertFalse(r["startUserspaceWireGuardAuthorized"])
        self.assertFalse(r["nativeRoutingChangesAuthorized"])

    def test_22_engine_never_imports_network_mutation_libraries(self):
        tree=ast.parse(ENGINE.read_text(encoding="utf-8"))
        imports={n.module for n in ast.walk(tree) if isinstance(n,ast.ImportFrom)}
        imports|={a.name for n in ast.walk(tree) if isinstance(n,ast.Import)
                  for a in n.names}
        self.assertFalse(imports & {"socket","winreg","psutil","win32api",
                                    "win32com","requests","urllib","ctypes"})

    def test_23_offline_contract_cli(self):
        cp=subprocess.run([sys.executable,str(ENGINE),"--mode","contract"],
                          capture_output=True,text=True,timeout=10)
        self.assertEqual(cp.returncode,0,cp.stderr)
        obj=json.loads(cp.stdout)
        self.assertEqual(obj["result"],"STATIC_CONTRACT_PASS")
        self.assertFalse(obj["liveStartAuthorized"])
        self.assertFalse(obj["wireguardOuterUDPBypassedTunProven"])

    def test_24_core_mode_missing_pid_is_blocked(self):
        cp=subprocess.run([sys.executable,str(ENGINE),"--mode","core-test"],
                          capture_output=True,text=True,timeout=10)
        self.assertEqual(cp.returncode,4,cp.stderr)
        obj=json.loads(cp.stdout)
        self.assertFalse(obj["liveStartAuthorized"])

    def test_25_no_outbound_wireguard_handshake_proven_by_parser(self):
        r=p1n.route_risk_classifier("xray_tun")
        self.assertEqual(r["result"],"BLOCKED_NO_FRESH_GCP_OR_SOCKET_PROOF")


if __name__=="__main__":
    result=unittest.TextTestRunner(verbosity=1).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(PreliveSafetyTests)
    )
    good=result.testsRun-len(result.failures)-len(result.errors)
    print("P1N0_REGRESSIONS_PASS="+str(good))
    print("P1N0_REGRESSIONS_FAIL="+str(len(result.failures)+len(result.errors)))
    print("P1N0_NATIVE_NETWORK_MUTATIONS=False")
    print("P1N0_RESULT="+("OFFLINE_CONTRACT_PASS" if result.wasSuccessful()
                          else "OFFLINE_CONTRACT_FAIL"))
    sys.exit(0 if result.wasSuccessful() else 1)
