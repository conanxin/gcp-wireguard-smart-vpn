#!/usr/bin/env python3
"""P1N-1: inspect current v2rayN TUN egress contract and parse synthetic WG variants.

The running generated runtime JSON is opened only to inspect non-secret
structural fields. No DNS addresses, server endpoints, keys, credentials,
domains, or production routing rules are ever emitted.
No production config is written. Xray run-test parses only synthetic temporary
JSON: no listeners, no TUN creation, no WG UDP dial.
"""
from __future__ import annotations

import argparse
import base64
from copy import deepcopy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time
from typing import Any

from stage_c_p1l_core_version_probe import query_process_image
from stage_c_p1m_offline_userspace_plan import (
    GateError, load_template, validate_template, local_asset_dir, materialize_synthetic,
)

SCHEMA = "stage-c-p1n1-current-tun-wg-contract-v1"
RESERVED_ENDPOINT = "192.0.2.1:443"
TEST_TUN_NAME = "p1n1-synthetic-tun"
EXPECTED_AUTO_FLAGS = {"dns", "misconfigtun"}


def ensure(ok: bool, reason: str) -> None:
    if not ok:
        raise GateError(reason)


def route_risk_classifier(selection_alias: str, *,
                          live_peer_confirmed: bool = False,
                          live_udp_bind_verified: bool = False,
                          dns_e2e_verified: bool = False,
                          inperson_permission: bool = False) -> dict:
    # P1N-1 is an offline gate and never grants permission to start a live peer.
    selected_tun = selection_alias.lower() == "xray_tun"
    return {
        "historicalEndpointRoutesToTun": selected_tun,
        "physicalInterfaceBindNeeded": selected_tun,
        "gcpServerFreshVerified": bool(live_peer_confirmed),
        "udpSocketPhysicalBypassVerified": bool(live_udp_bind_verified),
        "dnsSplitE2EVerified": bool(dns_e2e_verified),
        "onsitePermissionObserved": bool(inperson_permission),
        "nativeRoutingChangesAuthorized": False,
        "startUserspaceWireGuardAuthorized": False,
        "result": "BLOCKED_NO_FRESH_GCP_OR_SOCKET_PROOF",
    }


def inspect_runtime_config(xray_pid: int, v2rayn_pid: int) -> dict:
    ensure(os.name == "nt", "WINDOWS_ONLY")
    xray_image = query_process_image(xray_pid)
    v2rayn_image = query_process_image(v2rayn_pid)
    ensure(xray_image.name.casefold() == "xray.exe" and xray_image.is_file(),
           "CURRENT_XRAY_IMAGE_UNVERIFIED")
    ensure(v2rayn_image.name.casefold() == "v2rayn.exe" and v2rayn_image.is_file(),
           "CURRENT_V2RAYN_IMAGE_UNVERIFIED")
    root = v2rayn_image.parent
    expected_xray = root / "bin" / "xray" / "xray.exe"
    ensure(xray_image.resolve() == expected_xray.resolve(),
           "XRAY_NOT_FROM_CURRENT_V2RAYN_INSTALL")
    config_path = root / "binConfigs" / "config.json"
    ensure(config_path.is_file() and not config_path.is_symlink(),
           "GENERATED_RUNTIME_CONFIG_NOT_FOUND")
    try:
        raw_before = config_path.read_bytes()
        digest_before = hashlib.sha256(raw_before).digest()
        config = json.loads(raw_before.decode("utf-8-sig"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise GateError("GENERATED_RUNTIME_CONFIG_INVALID") from exc

    inbound_list = config.get("inbounds") or []
    tun_list = [x for x in inbound_list if x.get("protocol") == "tun"]
    ensure(len(tun_list) == 1, "EXPECTED_ONE_CURRENT_TUN_INBOUND")
    settings = tun_list[0].get("settings") or {}
    routes = settings.get("autoSystemRoutingTable") or []
    flags = {str(x).lower() for x in (settings.get("autoSystemWfpBlockLeak") or [])}
    outbounds = config.get("outbounds") or []
    wg_count = sum(1 for x in outbounds if x.get("protocol") == "wireguard")
    version = subprocess.run(
        [str(xray_image), "version"], capture_output=True, text=True,
        timeout=12, creationflags=0x08000000,
    )
    version_text = version.stdout + "\n" + version.stderr
    match = re.search(r"(?i)\bXray\s+(?:Core\s+)?(?:v)?(\d+\.\d+(?:\.\d+)?)",
                      version_text)
    ensure(version.returncode == 0 and match is not None,
           "CURRENT_XRAY_VERSION_UNAVAILABLE")

    # Detect if the runtime file changes while this read-only audit is running.
    raw_after = config_path.read_bytes()
    ensure(hashlib.sha256(raw_after).digest() == digest_before,
           "GENERATED_RUNTIME_CONFIG_CHANGED_DURING_AUDIT")
    return {
        "runtimeConfigFound": True,
        "runtimeConfigAgeSeconds": max(0, int(time.time() - config_path.stat().st_mtime)),
        "currentXrayVersion": match.group(1),
        "currentTunInboundCount": len(tun_list),
        "currentTunNameExpected": settings.get("name") == "xray_tun",
        "currentAutoOutboundsInterface": settings.get("autoOutboundsInterface"),
        "currentIPv4DefaultIntoTun": "0.0.0.0/0" in routes,
        "currentWfpDNSBlockEnabled": "dns" in flags,
        "currentWfpMisconfigTunBlockEnabled": "misconfigtun" in flags,
        "currentTunDnsServerCount": len(settings.get("dns") or []),
        "currentOutboundCount": len(outbounds),
        "currentWireguardOutboundCount": wg_count,
        "productionConfigValuesPrinted": False,
        "productionConfigModified": False,
        "nativeNetworkMutationsPerformed": False,
    }


def make_tun_inbound(*, auto_interface: str | None = "auto") -> dict:
    settings: dict[str, Any] = {
        "name": TEST_TUN_NAME,
        "desc": "Wintun",
        "mtu": 1420,
        "gateway": ["198.18.0.1/30"],
        "dns": ["192.0.2.53", "192.0.2.54"],
        "autoSystemRoutingTable": ["0.0.0.0/0"],
        "autoSystemWfpBlockLeak": ["dns", "misconfigtun"],
    }
    if auto_interface is not None:
        settings["autoOutboundsInterface"] = auto_interface
    return {"tag": "P1N1_SYNTHETIC_TUN_ONLY", "protocol": "tun",
            "settings": settings}


def make_variants() -> dict[str, dict]:
    draft = load_template()
    validate_template(draft)
    # The only key material used for run-test is synthetic random bytes.
    synthetic = materialize_synthetic(draft)
    synthetic.pop("_NOTICE", None)
    base = deepcopy(synthetic)
    base["inbounds"] = [make_tun_inbound(auto_interface="auto")]

    explicit = deepcopy(base)
    explicit["outbounds"][0]["streamSettings"] = {
        "sockopt": {"interface": "WLAN"}
    }

    auto_implicit = deepcopy(base)
    # Xray documentation says autoSystemRoutingTable implies auto when
    # autoOutboundsInterface is omitted. Keep this variant for parser comparison.
    auto_implicit["inbounds"][0]["settings"].pop("autoOutboundsInterface", None)

    explicit_only = deepcopy(auto_implicit)
    explicit_only["outbounds"][0]["streamSettings"] = {
        "sockopt": {"interface": "WLAN"}
    }
    return {
        "auto_inherited": base,
        "auto_with_explicit_wlan_override": explicit,
        "implicit_auto_with_explicit_wlan": explicit_only,
        "implicit_auto_without_manual_override": auto_implicit,
    }


def validate_candidate(label: str, cfg: dict) -> None:
    ensure(label in {
        "auto_inherited", "auto_with_explicit_wlan_override",
        "implicit_auto_with_explicit_wlan", "implicit_auto_without_manual_override"
    }, "UNKNOWN_CANDIDATE")
    ensure(cfg.get("inbounds") and len(cfg["inbounds"]) == 1,
           "SYNTHETIC_TUN_INBOUND_REQUIRED")
    inbound = cfg["inbounds"][0]
    ensure(inbound.get("protocol") == "tun", "SYNTHETIC_TUN_PROTOCOL_REQUIRED")
    ensure("listen" not in inbound and "port" not in inbound,
           "SYNTHETIC_TUN_MUST_NOT_HAVE_LISTENER")
    st = inbound.get("settings") or {}
    ensure(st.get("name") == TEST_TUN_NAME, "SYNTHETIC_TUN_NAME_REQUIRED")
    ensure(st.get("autoSystemRoutingTable") == ["0.0.0.0/0"],
           "SYNTHETIC_TUN_ROUTE_SCOPE_CHANGED")
    ensure(set(st.get("autoSystemWfpBlockLeak") or []) == EXPECTED_AUTO_FLAGS,
           "SYNTHETIC_WFP_GUARDS_CHANGED")
    ensure(st.get("autoOutboundsInterface", "auto") == "auto",
           "AUTO_OUTBOUNDS_INTERFACE_MUST_BE_AUTO")
    outbounds = cfg.get("outbounds") or []
    ensure(len(outbounds) == 2, "EXPECTED_WG_AND_DIRECT_OUTBOUNDS")
    wg, direct = outbounds
    ensure(wg.get("protocol") == "wireguard" and
           wg.get("tag") == "GCP_WG_OUTBOUND_DRAFT",
           "WG_MUST_BE_DEFAULT_OUTBOUND")
    ensure(direct.get("protocol") == "freedom" and
           direct.get("tag") == "CN_DIRECT_DRAFT",
           "CN_DIRECT_OUTBOUND_MISSING")
    settings = wg.get("settings") or {}
    ensure(settings.get("noKernelTun") is True, "WG_KERNEL_TUN_MUST_BE_DISABLED")
    ensure(settings.get("secretKey") != "__SYNTHETIC_ONLY_OR_LOCAL_PRIVATE_KEY_REQUIRED__",
           "SYNTHETIC_KEY_NOT_MATERIALIZED")
    peers = settings.get("peers") or []
    ensure(len(peers) == 1 and peers[0].get("endpoint") == RESERVED_ENDPOINT,
           "REAL_PEER_ENDPOINT_FORBIDDEN")
    ensure(peers[0].get("publicKey") !=
           "__SYNTHETIC_ONLY_OR_VERIFIED_SERVER_PUBLIC_KEY_REQUIRED__",
           "SYNTHETIC_PEER_KEY_NOT_MATERIALIZED")
    ipaddress.ip_address(peers[0]["endpoint"].split(":")[0])
    stream = wg.get("streamSettings") or {}
    sockopt = stream.get("sockopt") or {}
    if label in ("auto_with_explicit_wlan_override",
                 "implicit_auto_with_explicit_wlan"):
        ensure(sockopt.get("interface") == "WLAN",
               "EXPLICIT_WLAN_BIND_MISSING")
    else:
        ensure(not sockopt.get("interface"),
               "UNEXPECTED_MANUAL_INTERFACE_OVERRIDE")
    ensure(cfg.get("dns") is None, "UNVERIFIED_GLOBAL_DNS_FORBIDDEN")
    ensure(not any("0.0.0.0/1" == x or "128.0.0.0/1" == x
                   for x in st.get("autoSystemRoutingTable", [])),
           "NATIVE_HALF_ROUTES_FORBIDDEN")
    ensure(all(r.get("outboundTag") == "CN_DIRECT_DRAFT"
               for r in cfg.get("routing", {}).get("rules", [])),
           "SYNTHETIC_ROUTING_RULE_TARGET_CHANGED")


def parse_candidate(image: Path, assets: Path, label: str, cfg: dict) -> dict:
    validate_candidate(label, cfg)
    with tempfile.TemporaryDirectory(prefix="p1n1-synthetic-wg-tun-") as tmp:
        file = Path(tmp) / (label + ".json")
        file.write_text(json.dumps(cfg, separators=(",", ":")), encoding="utf-8")
        env = dict(os.environ)
        env["XRAY_LOCATION_ASSET"] = str(assets)
        proc = subprocess.run(
            [str(image), "run", "-test", "-config", str(file)],
            env=env, capture_output=True, text=True, timeout=28,
            creationflags=0x08000000,
        )
        output = proc.stdout + "\n" + proc.stderr
        return {
            "exitCode": proc.returncode,
            "configurationOK": "Configuration OK." in output,
            "syntaxParsed": proc.returncode == 0 and "Configuration OK." in output,
        }


def evaluate(xray_pid: int, v2rayn_pid: int) -> dict:
    runtime = inspect_runtime_config(xray_pid, v2rayn_pid)
    image = query_process_image(xray_pid)
    assets, asset_report = local_asset_dir(image)
    ensure(assets is not None, "CORE_GEODATA_NOT_FOUND")
    variants = make_variants()
    results = {label: parse_candidate(image, assets, label, cfg)
               for label, cfg in variants.items()}
    all_parsed = all(x["syntaxParsed"] for x in results.values())
    runtime_contract_pass = bool(
        runtime["currentXrayVersion"] == "26.10.21"
        and runtime["currentTunInboundCount"] == 1
        and runtime["currentTunNameExpected"]
        and runtime["currentAutoOutboundsInterface"] == "auto"
        and runtime["currentIPv4DefaultIntoTun"]
        and runtime["currentWfpDNSBlockEnabled"]
        and runtime["currentWfpMisconfigTunBlockEnabled"]
        and runtime["currentWireguardOutboundCount"] == 0
    )
    return {
        "schema": SCHEMA,
        "result": "CURRENT_TUN_CONTRACT_AND_SYNTHETIC_WG_PARSED"
                  if all_parsed and runtime_contract_pass
                  else "BLOCKED_CONTRACT_OR_SYNTAX",
        "runtimeContractPass": runtime_contract_pass,
        "runtime": runtime,
        "geodataPresent": asset_report["assetsFound"],
        "geoipAgeDays": asset_report["geoipAgeDays"],
        "geositeAgeDays": asset_report["geositeAgeDays"],
        "variants": results,
        "allVariantsParsed": all_parsed,
        "existingTunAutoOutboundsInterface": runtime["currentAutoOutboundsInterface"],
        "currentRuntimeContainsWireguardOutbound": runtime["currentWireguardOutboundCount"] > 0,
        "actualWireguardOuterSocketBindingObserved": False,
        "actualOuterUdpBypassedTunProven": False,
        "actualGcpHandshakeProven": False,
        "dnsSplitE2EProven": False,
        "liveStartAuthorized": False,
        "productionConfigModified": False,
        "nativeNetworkMutationsPerformed": False,
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=("contract", "core-test"), default="contract")
    p.add_argument("--xray-pid", type=int)
    p.add_argument("--v2rayn-pid", type=int)
    args = p.parse_args()
    try:
        variants = make_variants()
        for name, cfg in variants.items():
            validate_candidate(name, cfg)
        if args.mode == "contract":
            report = {
                "schema": SCHEMA,
                "result": "STATIC_P1N1_CONTRACT_PASS",
                "variants": sorted(variants),
                "inbounds": "ONE_SYNTHETIC_TUN_NO_SOCKET_LISTENER",
                "noKernelTun": True,
                "endpoint": RESERVED_ENDPOINT,
                "currentRuntimeInspected": False,
                "liveStartAuthorized": False,
                "actualOuterUdpBypassedTunProven": False,
                "nativeNetworkMutationsPerformed": False,
            }
            code = 0
        else:
            ensure(args.xray_pid is not None and args.v2rayn_pid is not None,
                   "CURRENT_XRAY_AND_V2RAYN_PIDS_REQUIRED")
            report = evaluate(args.xray_pid, args.v2rayn_pid)
            code = 0 if report["allVariantsParsed"] and report["runtimeContractPass"] else 2
    except (GateError, OSError, subprocess.TimeoutExpired, KeyError,
            TypeError, ValueError) as exc:
        report = {
            "schema": SCHEMA,
            "result": "BLOCKED_SYNTHETIC_ONLY",
            "reason": str(exc) if isinstance(exc, GateError) else type(exc).__name__,
            "liveStartAuthorized": False,
            "productionConfigModified": False,
            "nativeNetworkMutationsPerformed": False,
        }
        code = 4
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
