#!/usr/bin/env python3
"""P1M: non-deployable, offline Xray userspace-WG routing contract.

Security boundary:
- Reads only this repository's public placeholder JSON and local xray.exe image.
- Never reads production v2rayN config, client WireGuard private key or GCP key.
- Creates random *synthetic-only* keys in an auto-deleted temp directory.
- Calls the running Xray build with "run -test" only, with ZERO inbounds and
  the RFC5737 TEST-NET endpoint 192.0.2.1:443.
- No native Windows route/TUN/WinINET/NRPT writes, listeners or GCP handshake.
"""
from __future__ import annotations

import argparse
import base64
from copy import deepcopy
import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile

from stage_c_p1l_core_version_probe import query_process_image

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = REPO_ROOT / "docs" / "stage-c-p1m-userspace-wg.template.json"
SERVER_READONLY = "BLOCKED_NO_AUTHORIZED_GCP_SSH_TARGET"

PLACEHOLDER_CLIENT = "__SYNTHETIC_ONLY_OR_LOCAL_PRIVATE_KEY_REQUIRED__"
PLACEHOLDER_SERVER = "__SYNTHETIC_ONLY_OR_VERIFIED_SERVER_PUBLIC_KEY_REQUIRED__"
ENDPOINT_TEST_ONLY = "192.0.2.1:443"
EXPECTED_DOMAINS = ["geosite:cn"]
EXPECTED_IP_RULE = ["geoip:private", "geoip:cn"]
DENY_KEYS = {"psk", "password", "passwords", "uuid", "users"}


class GateError(Exception):
    pass


def ensure(value: bool, code: str) -> None:
    if not value:
        raise GateError(code)


def validate_template(doc: dict) -> None:
    """Check policy invariant; syntax parsing is a separate Xray-only gate."""
    ensure(isinstance(doc, dict), "TEMPLATE_NOT_OBJECT")
    ensure(str(doc.get("_NOTICE", "")).startswith("P1M DOCUMENTATION-ONLY"),
           "DOCUMENTATION_ONLY_BANNER_REQUIRED")
    ensure(doc.get("inbounds") == [], "MUST_HAVE_ZERO_INBOUNDS")
    out = doc.get("outbounds")
    ensure(isinstance(out, list) and len(out) == 2, "EXPECTED_TWO_OUTBOUNDS")
    wg, direct = out
    ensure(wg.get("tag") == "GCP_WG_OUTBOUND_DRAFT"
           and wg.get("protocol") == "wireguard",
           "FIRST_OUTBOUND_MUST_BE_FAIL_CLOSED_WG")
    ensure(direct.get("tag") == "CN_DIRECT_DRAFT"
           and direct.get("protocol") == "freedom",
           "SECOND_OUTBOUND_MUST_BE_CN_DIRECT")
    settings = wg.get("settings", {})
    ensure(settings.get("secretKey") == PLACEHOLDER_CLIENT,
           "TEMPLATE_MUST_NOT_CONTAIN_REAL_CLIENT_PRIVATE_KEY")
    ensure(settings.get("noKernelTun") is True, "USERSpace_NO_KERNEL_TUN_REQUIRED")
    ensure(settings.get("address") == ["10.66.66.2"],
           "CLIENT_ADDRESS_HISTORICAL_REFERENCE_ONLY")
    ensure(settings.get("remoteDNS") == ["10.66.66.1"],
           "WG_REMOTE_DNS_REFERENCE_REQUIRED")
    ensure(settings.get("mtu") == 1420, "FIXED_OFFLINE_MTU_PLACEHOLDER")
    peers = settings.get("peers")
    ensure(isinstance(peers, list) and len(peers) == 1, "ONE_MOCK_PEER_REQUIRED")
    peer = peers[0]
    ensure(peer.get("endpoint") == ENDPOINT_TEST_ONLY,
           "REAL_ENDPOINT_FORBIDDEN_IN_SHARED_TEMPLATE")
    ensure(peer.get("publicKey") == PLACEHOLDER_SERVER,
           "SERVER_PUBLIC_KEY_MUST_BE_PLACEHOLDER")
    ensure(peer.get("allowedIPs") == ["0.0.0.0/0"],
           "WG_OUTBOUND_MUST_BE_IPV4_ONLY_IN_OFFLINE_DRAFT")
    ensure(peer.get("keepAlive") == 0,
           "KEEPALIVE_FORBIDDEN_IN_OFFLINE_DRAFT")
    ensure(ipaddress.ip_address(peer["endpoint"].split(":")[0]).is_global is False,
           "MUST_USE_RESERVED_DOCUMENTATION_ENDPOINT")
    routing = doc.get("routing")
    ensure(isinstance(routing, dict)
           and routing.get("domainStrategy") == "AsIs",
           "UNTESTED_DNS_RESOLUTION_STRATEGY_REJECTED")
    rules = routing.get("rules")
    ensure(isinstance(rules, list) and len(rules) == 2,
           "ONLY_TWO_REVIEWED_CN_ROUTES_ALLOWED")
    ensure(rules[0].get("domain") == EXPECTED_DOMAINS
           and rules[0].get("outboundTag") == "CN_DIRECT_DRAFT",
           "CN_DOMAIN_RULE_MISSING_OR_UNSAFE")
    ensure(rules[1].get("ip") == EXPECTED_IP_RULE
           and rules[1].get("outboundTag") == "CN_DIRECT_DRAFT",
           "CN_GEOIP_AND_PRIVATE_RULE_MISSING")
    ensure("dns" not in doc,
           "BUILTIN_DNS_NOT_YET_E2E_VERIFIED_DO_NOT_PRETEND")
    # The inside-WG remoteDNS is explicit; CN direct DNS and core DNS fallback
    # must be tested later, not silently guessed here.
    all_text = json.dumps(doc, sort_keys=True)
    for key in DENY_KEYS:
        ensure(f'"{key}":' not in all_text.lower(),
               "EXTRA_SENSITIVE_FIELD_FORBIDDEN")
    ensure("0.0.0.0/1" not in all_text and "128.0.0.0/1" not in all_text,
           "NATIVE_HALF_ROUTES_NOT_PART_OF_USERSPACE_PLAN")


def load_template() -> dict:
    ensure(TEMPLATE.is_file() and not TEMPLATE.is_symlink(),
           "TEMPLATE_NOT_FOUND_OR_LINK")
    try:
        return json.loads(TEMPLATE.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise GateError("TEMPLATE_JSON_INVALID") from exc


def materialize_synthetic(draft: dict) -> dict:
    """Private synthetic-only key bytes are never printed or persisted in repo."""
    validate_template(draft)
    obj = deepcopy(draft)
    del obj["_NOTICE"]
    settings = obj["outbounds"][0]["settings"]
    settings["secretKey"] = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    settings["peers"][0]["publicKey"] = (
        base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    )
    return obj


def local_asset_dir(image: Path) -> tuple[Path | None, dict]:
    candidates = (image.parent, image.parent.parent, image.parent.parent.parent)
    report = {"assetsFound": False, "geoipAgeDays": None,
              "geositeAgeDays": None, "geoipSHA256Prefix": None,
              "geositeSHA256Prefix": None}
    for base in candidates:
        geoip = base / "geoip.dat"
        geosite = base / "geosite.dat"
        if geoip.is_file() and geosite.is_file():
            age_ip = int((__import__("time").time() - geoip.stat().st_mtime)//86400)
            age_site = int((__import__("time").time() - geosite.stat().st_mtime)//86400)
            report["assetsFound"] = True
            report["geoipAgeDays"] = age_ip
            report["geositeAgeDays"] = age_site
            report["geoipSHA256Prefix"] = hashlib.sha256(geoip.read_bytes()).hexdigest()[:16]
            report["geositeSHA256Prefix"] = hashlib.sha256(geosite.read_bytes()).hexdigest()[:16]
            return base, report
    return None, report


def assess_core(pid: int) -> dict:
    report = {
        "result": "BLOCKED",
        "stage": "P1M_OFFLINE_CORE_POLICY",
        "gcpServerCurrentStatus": SERVER_READONLY,
        "readUserKeys": False,
        "readProductionConfig": False,
        "networkMutationsPerformed": False,
        "realWGHandshake": False,
        "inboundsCreated": 0,
        "realEndpointUsed": False,
        "liveConfigChanged": False,
        "syntaxTestPass": False,
        "dnsE2EVerified": False,
        "wgEndpointLoopProtectionVerified": False,
        "cnDirectPathVerified": False,
        "foreignGcpEgressVerified": False,
        "currentXrayVersion": None,
    }
    ensure(os.name == "nt", "WINDOWS_ONLY")
    ensure(isinstance(pid, int) and pid > 0, "INVALID_XRAY_PID")
    draft = load_template()
    validate_template(draft)
    image = query_process_image(pid)
    ensure(image.name.lower() == "xray.exe" and image.is_file(),
           "CURRENT_PROCESS_NOT_XRAY_BINARY")
    version_check = subprocess.run(
        [str(image), "version"], capture_output=True, text=True,
        timeout=12, creationflags=0x08000000,
    )
    version_text = version_check.stdout + "\n" + version_check.stderr
    version_match = re.search(
        r"(?i)\bXray\s+(?:Core\s+)?(?:v)?(\d+\.\d+(?:\.\d+)?)",
        version_text,
    )
    ensure(version_check.returncode == 0 and bool(version_match),
           "CURRENT_XRAY_VERSION_UNAVAILABLE")
    report["currentXrayVersion"] = version_match.group(1)
    asset, props = local_asset_dir(image)
    report.update(props)
    ensure(asset is not None, "CORE_GEODATA_NOT_FOUND")
    # Synthetic-only: Xray tests geosite/geoip use this child-local asset path,
    # never changes any system-wide variable or v2rayN production environment.
    cfg = materialize_synthetic(draft)
    with tempfile.TemporaryDirectory(prefix="p1m-no-listener-no-gcp-") as directory:
        fixture_path = Path(directory) / "test-only.json"
        fixture_path.write_text(
            json.dumps(cfg, separators=(",", ":"), ensure_ascii=False),
            encoding="utf-8",
        )
        env = dict(os.environ)
        env["XRAY_LOCATION_ASSET"] = str(asset)
        test = subprocess.run(
            [str(image), "run", "-test", "-config", str(fixture_path)],
            env=env, capture_output=True, text=True,
            timeout=28, creationflags=0x08000000,
        )
        output = (test.stdout + "\n" + test.stderr)
        report["parserExitCode"] = test.returncode
        report["configOKMarker"] = ("Configuration OK." in output)
        report["syntaxTestPass"] = bool(
            test.returncode == 0 and report["configOKMarker"]
        )
        report["result"] = (
            "SYNTHETIC_CN_DIRECT_WG_POLICY_PARSED"
            if report["syntaxTestPass"] else
            "CORE_REJECTED_SYNTHETIC_CN_WG_POLICY"
        )
        # Never print raw CLI output or temporary random keys.
    return report


def main() -> int:
    p = argparse.ArgumentParser(
        description="P1M no-network, no-real-keys Xray WG routing syntax gate"
    )
    p.add_argument("--pid", type=int, help="PID of CURRENT running xray.exe")
    p.add_argument("--mode", choices=("contract", "core-test"),
                   default="contract")
    args = p.parse_args()
    try:
        doc = load_template()
        validate_template(doc)
        if args.mode == "contract":
            report = {
                "result": "TEMPLATE_CONTRACT_PASS",
                "templateIsDeployable": False,
                "nativeCNRoutesRequired": False,
                "userSecretIncluded": False,
                "userKeyRead": False,
                "realGCPEndpointIncluded": False,
                "inbounds": 0,
                "outboundTags": [x["tag"] for x in doc["outbounds"]],
                "domainStrategy": doc["routing"]["domainStrategy"],
                "networkMutationsPerformed": False,
                "cnDirectDnsPathE2EVerified": False,
                "wgEndpointLoopProtectionVerified": False,
                "foreignGcpEgressVerified": False,
            }
            code = 0
        else:
            ensure(args.pid is not None, "Xray_RUNNING_PID_REQUIRED")
            report = assess_core(args.pid)
            code = 0 if report["syntaxTestPass"] else 2
    except (GateError, OSError, subprocess.TimeoutExpired, ValueError,
            TypeError, KeyError) as exc:
        report = {
            "result": "BLOCKED_FAIL_CLOSED",
            "reason": str(exc) if isinstance(exc, GateError) else type(exc).__name__,
            "networkMutationsPerformed": False,
            "readUserKeys": False,
            "syntaxTestPass": False,
        }
        code = 4
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
