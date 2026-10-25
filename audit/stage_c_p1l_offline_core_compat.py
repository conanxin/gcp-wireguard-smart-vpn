#!/usr/bin/env python3
"""Stage C P1L: pure offline syntax test with the already-installed Xray binary.

This tool DOES NOT read the production Xray/v2rayN configuration or any real
WireGuard keys. It generates ephemeral synthetic private/public key materials
ONLY in a disposable temp file, asks the exact running Xray binary to parse
that file with "run -test", then removes it.

The synthetic endpoint is an RFC5737 documentation IP. No listeners/TUN,
real GCP peer, handshakes, traffic, route edits or production changes.
Official CLI docs: xray run -test tests config without starting server.
"""
from __future__ import annotations
import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile

from stage_c_p1l_core_version_probe import query_process_image


def mock_config() -> dict:
    # Random test-only keys have absolutely no relation to the user's WG keys.
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [],
        # First outbound is the default when no route matches.
        "outbounds": [
            {"tag": "GCP_WG_SYNTHETIC_ONLY", "protocol": "wireguard", "settings": {
                "secretKey": base64.b64encode(secrets.token_bytes(32)).decode(),
                "address": ["10.66.66.2"],
                "peers": [{"endpoint": "192.0.2.1:443",
                           "publicKey": base64.b64encode(secrets.token_bytes(32)).decode(),
                           "allowedIPs": ["0.0.0.0/0"],
                           "keepAlive": 0}],
                "noKernelTun": True,
                "mtu": 1420,
                "remoteDNS": ["10.66.66.1"],
            }},
            {"tag": "CN_DIRECT_SYNTHETIC_ONLY", "protocol": "freedom"}
        ],
        # Small illustrative rule only, NOT a production CN geosite/geoip list.
        "routing": {"domainStrategy": "AsIs", "rules": [
            {"type": "field", "domain": ["domain:example.cn"],
             "outboundTag": "CN_DIRECT_SYNTHETIC_ONLY"},
            {"type": "field", "ip": ["223.5.5.5/32"],
             "outboundTag": "CN_DIRECT_SYNTHETIC_ONLY"}
        ]}
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--pid", required=True, type=int)
    args = p.parse_args()
    report = {
        "phase": "P1L_OFFLINE_ONLY",
        "configuration": "EPHEMERAL_SYNTHETIC_CONFIG",
        "privateUserKeysRead": False,
        "productionConfigRead": False,
        "productionConfigModified": False,
        "inbounds": 0,
        "noKernelTun": True,
        "peerEndpoint": "192.0.2.1:443",
        "realGCPHandshake": False,
        "networkMutationsPerformed": False,
        "syntaxValidationPass": False,
    }
    if os.name != "nt":
        report["status"] = "WINDOWS_ONLY"
        print(json.dumps(report, sort_keys=True))
        return 3
    try:
        image = query_process_image(args.pid)
        if image.name.casefold() != "xray.exe" or not image.is_file():
            report["status"] = "BLOCKED_WRONG_EXE"
            print(json.dumps(report, sort_keys=True))
            return 4
        with tempfile.TemporaryDirectory(prefix="p1l-offline-fixture-") as folder:
            config = Path(folder) / "synthetic-no-listeners.json"
            config.write_text(json.dumps(mock_config()), encoding="utf-8")
            result = subprocess.run(
                [str(image), "run", "-test", "-config", str(config)],
                capture_output=True, text=True, timeout=25,
                creationflags=0x08000000,
            )
            output = result.stdout + "\n" + result.stderr
            report["coreRunTestExit"] = result.returncode
            report["configurationOK"] = "Configuration OK." in output
            report["syntaxValidationPass"] = (
                result.returncode == 0 and report["configurationOK"]
            )
            report["status"] = (
                "SYNTHETIC_WG_CONFIGURATION_PARSED"
                if report["syntaxValidationPass"] else "SYNTHETIC_CONFIG_REJECTED"
            )
            # Do NOT print raw Xray output: it could someday include secrets
            # from a future change in CLI behavior. Never log temporary keys.
    except (OSError, ValueError, subprocess.TimeoutExpired) as e:
        report["status"] = "BLOCKED_NO_NETWORK_CHANGES"
        report["errorType"] = type(e).__name__
    print(json.dumps(report, sort_keys=True))
    return 0 if report["syntaxValidationPass"] else 2


if __name__ == "__main__":
    sys.exit(main())
