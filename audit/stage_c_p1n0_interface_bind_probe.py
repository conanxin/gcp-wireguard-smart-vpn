#!/usr/bin/env python3
"""Stage C P1N-0: Xray WireGuard outer-socket interface-binding SYNTAX probe.

Synthetic-only, no listeners, no real GCP endpoint or client keys, no network
connections except Xray's local run -test parser. No live Xray config modified.
Acceptance of streamSettings.sockopt.interface does NOT establish that an
actual WG UDP socket bypasses an already-running host xray_tun.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from stage_c_p1l_core_version_probe import query_process_image
from stage_c_p1m_offline_userspace_plan import (
    load_template, materialize_synthetic, validate_template, local_asset_dir,
    GateError,
)

INTERFACE = "WLAN"
SCHEMA = "stage-c-p1n0-outer-udp-interface-syntax-v1"


def require(condition: bool, reason: str):
    if not condition:
        raise GateError(reason)


def make_candidates(base: dict, physical_alias: str = INTERFACE) -> dict:
    require(physical_alias == INTERFACE, "DYNAMIC_ALIAS_CONFIRMATION_REQUIRED")
    require(base.get("inbounds") == [], "NO_LISTENERS_ALLOWED")
    require(base.get("outbounds", [{}])[0].get("protocol") == "wireguard",
            "FIRST_OUTBOUND_MUST_BE_WIREGUARD")
    wg = base["outbounds"][0]
    require(wg["settings"]["noKernelTun"] is True,
            "NO_KERNEL_TUN_REQUIRED")
    peer = wg["settings"]["peers"][0]
    require(peer["endpoint"] == "192.0.2.1:443",
            "REAL_ENDPOINT_FORBIDDEN")
    baseline = deepcopy(base)
    candidate = deepcopy(base)
    candidate["outbounds"][0]["streamSettings"] = {
        "sockopt": {"interface": INTERFACE}
    }
    return {"base": baseline, "bound_wlan": candidate}


def route_risk_classifier(selection_alias: str, *,
                          live_peer_confirmed: bool = False,
                          live_udp_bind_verified: bool = False,
                          dns_e2e_verified: bool = False,
                          inperson_permission: bool = False) -> dict:
    # Intentional hard gate: current P1N-0 NEVER allows writes/connectivity,
    # even if fictional caller supplies every condition as true.
    visible_tun = selection_alias.lower() == "xray_tun"
    return {
        "historicalEndpointRoutesToTun": visible_tun,
        "physicalInterfaceBindNeeded": visible_tun,
        "gcpServerFreshVerified": live_peer_confirmed,
        "udpSocketPhysicalBypassVerified": live_udp_bind_verified,
        "dnsSplitE2EVerified": dns_e2e_verified,
        "newSupervisedLiveAuthorization": inperson_permission,
        "nativeRoutingChangesAuthorized": False,
        "startUserspaceWireGuardAuthorized": False,
        "result": "BLOCKED_NO_FRESH_GCP_OR_SOCKET_PROOF",
    }


def parse_xray(image: Path, fixture: Path, assets: Path) -> dict:
    env = dict(os.environ)
    env["XRAY_LOCATION_ASSET"] = str(assets)
    proc = subprocess.run(
        [str(image), "run", "-test", "-config", str(fixture)],
        env=env, capture_output=True, text=True,
        timeout=25, creationflags=0x08000000,
    )
    # No raw console text or ephemeral keys are returned.
    output = proc.stdout + "\n" + proc.stderr
    return {
        "exitCode": proc.returncode,
        "configurationOK": "Configuration OK." in output,
        "syntaxParsed": (proc.returncode == 0 and "Configuration OK." in output),
    }


def evaluate(pid: int) -> dict:
    require(os.name == "nt", "WINDOWS_ONLY")
    require(type(pid) is int and pid > 0, "VALID_RUNNING_XRAY_PID_REQUIRED")
    template = load_template()
    validate_template(template)
    synthetic = materialize_synthetic(template)
    variants = make_candidates(synthetic)
    image = query_process_image(pid)
    require(image.name.casefold() == "xray.exe" and image.is_file(),
            "RUNNING_IMAGE_NOT_XRAY")
    assets, asset_report = local_asset_dir(image)
    require(assets is not None, "GEODATA_NOT_FOUND")
    results: dict[str, dict] = {}
    with tempfile.TemporaryDirectory(prefix="p1n0-no-server-no-endpoint-") as tmp:
        for label, obj in variants.items():
            require(obj["inbounds"] == [], "NO_INBOUND_ALLOWED")
            require(obj["outbounds"][0]["settings"]["peers"][0]["endpoint"]
                    == "192.0.2.1:443", "DOCUMENTATION_ENDPOINT_ONLY")
            path = Path(tmp) / (label + ".json")
            path.write_text(
                json.dumps(obj, separators=(",", ":"), ensure_ascii=False),
                encoding="utf-8",
            )
            results[label] = parse_xray(image, path, assets)
    return {
        "schema": SCHEMA,
        "mode": "SYNTHETIC_CONFIG_PARSER_ONLY",
        "baseSyntax": results["base"],
        "wlanBindSyntax": results["bound_wlan"],
        "allSyntaxParsed": all(r["syntaxParsed"] for r in results.values()),
        "physicalAliasCandidate": INTERFACE,
        "geodataPresent": asset_report["assetsFound"],
        "noKernelTun": True,
        "syntheticEndpoint": "192.0.2.1:443",
        "realWGPeerUsed": False,
        "realClientSecretsRead": False,
        "existingXrayProductionConfigRead": False,
        "newInboundsCreated": 0,
        "nativeNetworkMutations": False,
        "physicalInterfaceBindingActuallyObserved": False,
        "wireguardOuterUDPBypassedTunProven": False,
        "actualGcpHandshakeProven": False,
        "dnsSplitE2EProven": False,
        "liveStartAuthorized": False,
        "result": (
            "SYNTAX_PARSED_RUNTIME_SOCKET_BYPASS_UNVERIFIED"
            if all(r["syntaxParsed"] for r in results.values())
            else "BLOCKED_XRAY_SOCKOPT_SYNTAX"),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("contract", "core-test"),
                        default="contract")
    parser.add_argument("--pid", type=int)
    args = parser.parse_args()
    try:
        draft = load_template()
        validate_template(draft)
        candidates = make_candidates(materialize_synthetic(draft))
        if args.mode == "contract":
            report = {
                "schema": SCHEMA,
                "mode": "OFFLINE_CONTRACT",
                "variants": sorted(candidates),
                "taggedPhysicalInterface": INTERFACE,
                "inbounds": 0,
                "actualGcpHandshakeProven": False,
                "wireguardOuterUDPBypassedTunProven": False,
                "liveStartAuthorized": False,
                "nativeNetworkMutations": False,
                "result": "STATIC_CONTRACT_PASS",
            }
            code = 0
        else:
            require(args.pid is not None, "RUNNING_PID_REQUIRED")
            report = evaluate(args.pid)
            code = 0 if report["allSyntaxParsed"] else 2
    except (GateError, OSError, subprocess.TimeoutExpired,
            KeyError, TypeError, ValueError) as e:
        report = {
            "schema": SCHEMA,
            "result": "BLOCKED_SYNTHETIC_ONLY",
            "reason": str(e) if isinstance(e, GateError) else type(e).__name__,
            "liveStartAuthorized": False,
            "nativeNetworkMutations": False,
        }
        code = 4
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
