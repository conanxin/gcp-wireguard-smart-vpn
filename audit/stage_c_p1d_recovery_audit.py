#!/usr/bin/env python3
"""Stage C P1D: PURE READ-ONLY analyzer for synthetic P1C route journals.

No PowerShell, Windows routing, WinINET, NRPT, WireGuard, network, subprocess,
or filesystem mutations. It can only interpret an explicitly selected
p1c-fixture-* test folder. Results are advice for SIMULATED recovery only,
never authorization to call native Windows route writers.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
from typing import Any

SCHEMA = "stage-c-p1d-readonly-recovery-audit-v1"
RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{3,64}$")
SAFE_NAME = re.compile(
    r"^(?:mockworld\.json|prefixes\.txt|plan-[A-Za-z0-9_-]+\.json"
    r"|journal-[A-Za-z0-9_-]+\.json)$"
)


def digest_text(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest().upper()


def world_hash(world: dict[str, Any]) -> str:
    """Mirror Stage C P1C PowerShell WorldHash for synthetic fixtures."""
    routes = sorted(
        route_identity(route) for route in world["routes"]
    )
    nrpt = sorted(
        "{id}|{server}|{nss}".format(
            id=entry["id"], server=entry["server"],
            nss=",".join(sorted(entry["namespaces"])),
        )
        for entry in world["nrpt"]
    )
    status = "True" if world["wgActive"] else "False"
    parts = [
        f"physical={world['physicalIndex']}|{world['gateway']}",
        f"proxy={world['proxyEnabled']}|{world['proxyServer']}",
        f"wg={status}",
        "routes=" + ";".join(routes),
        "nrpt=" + ";".join(nrpt),
    ]
    return digest_text("\n".join(parts))


def route_identity(route: dict[str, Any]) -> str:
    return "{prefix}|{ifIndex}|{nextHop}|{metric}|{store}".format(**route)


def audit_event_hash(event: dict[str, Any]) -> str:
    text = "|".join(
        str(event[field])
        for field in ("sequence", "prev", "kind", "file",
                      "fileSha256", "runId")
    )
    return digest_text(text)


def _safe_file(folder: Path, name: str) -> Path:
    if not SAFE_NAME.fullmatch(name):
        raise ValueError("AUDIT_FILENAME_NOT_ALLOWLISTED")
    path = folder / name
    if path.is_symlink() or not path.is_file():
        raise ValueError("AUDIT_FILE_NOT_REGULAR")
    if path.parent != folder:
        raise ValueError("AUDIT_PATH_OUTSIDE_FIXTURE")
    return path


def _read_json(folder: Path, name: str) -> dict[str, Any]:
    path = _safe_file(folder, name)
    obj = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(obj, dict):
        raise ValueError("JSON_NOT_OBJECT")
    return obj


def validate_audit(folder: Path, run_id: str) -> dict[str, str]:
    path = folder / f"audit-{run_id}.ndjson"
    if path.is_symlink() or not path.is_file():
        raise ValueError("AUDIT_MISSING")
    raw = path.read_bytes()
    if not raw or not raw.endswith(b"\n"):
        raise ValueError("AUDIT_TRUNCATED_OR_EMPTY")
    events = raw.decode("utf-8").splitlines()
    previous = "GENESIS"
    final: dict[str, str] = {}
    for n, line in enumerate(events, 1):
        if not line:
            raise ValueError("AUDIT_EMPTY_LINE")
        event = json.loads(line)
        if (not isinstance(event, dict)
            or event.get("runId") != run_id
            or event.get("sequence") != n
            or event.get("prev") != previous
            or event.get("hash") != audit_event_hash(event)):
            raise ValueError("AUDIT_HASH_CHAIN_MISMATCH")
        name = event["file"]
        if not isinstance(name, str) or not SAFE_NAME.fullmatch(name):
            raise ValueError("AUDIT_FILE_OUTSIDE_ALLOWLIST")
        final[name] = event["fileSha256"]
        previous = event["hash"]
    for name, expected in final.items():
        data = _safe_file(folder, name).read_bytes()
        if hashlib.sha256(data).hexdigest().upper() != expected:
            raise ValueError("AUDIT_COMMITTED_FILE_DIGEST_MISMATCH")
    return final


def analyze_fixture(directory: str | Path, run_id: str) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "schema": SCHEMA,
        "analysis": "READ_ONLY",
        "run_id": run_id,
        "decision": "BLOCKED",
        "reasons": [],
        "owned_candidate_routes": 0,
        "native_windows_routes_were_read": False,
        "native_windows_routes_were_mutated": False,
        "native_rollback_authorized": False,
        "live_canary_authorized": False,
        "acl_externally_verified": False,
    }
    reasons: list[str] = summary["reasons"]
    try:
        if not RUN_ID_PATTERN.fullmatch(run_id):
            raise ValueError("INVALID_RUN_ID")
        folder = Path(directory).resolve(strict=True)
        if not folder.is_dir() or not folder.name.startswith("p1c-fixture-"):
            raise ValueError("NOT_P1C_SYNTHETIC_FIXTURE")
        if Path(directory).is_symlink():
            raise ValueError("SYMLINK_FIXTURE_NOT_ACCEPTED")
        final = validate_audit(folder, run_id)
        plan = _read_json(folder, f"plan-{run_id}.json")
        if plan.get("schema") != "stage-c-p1c-route-v1" or plan.get("runId") != run_id:
            raise ValueError("PLAN_SCHEMA_OR_RUN_MISMATCH")
        prefix_file = _safe_file(folder, "prefixes.txt")
        prefixes = [
            p.strip() for p in prefix_file.read_text(encoding="utf-8-sig").splitlines()
            if p.strip()
        ]
        if len(prefixes) == 0 or len(prefixes) != len(set(prefixes)):
            raise ValueError("PREFIX_SET_INVALID")
        if digest_text("\n".join(prefixes)) != plan.get("prefixesHash"):
            raise ValueError("PLAN_PREFIX_HASH_CHANGED")
        world = _read_json(folder, "mockworld.json")
        if f"journal-{run_id}.json" not in final:
            if world_hash(world) != plan.get("worldHash"):
                raise ValueError("UNJOURNALED_WORLD_CHANGES")
            summary["decision"] = "MOCK_PLAN_ONLY"
            return summary
        journal = _read_json(folder, f"journal-{run_id}.json")
        if (journal.get("schema") != "stage-c-p1c-route-v1"
            or journal.get("runId") != run_id
            or journal.get("beforeHash") != plan.get("worldHash")):
            raise ValueError("JOURNAL_PLAN_OR_RUN_MISMATCH")
        entries = journal.get("entries", [])
        if not isinstance(entries, list):
            raise ValueError("INVALID_JOURNAL_ENTRIES")
        originals = set(journal["beforeRoutes"])
        possible_owned: list[dict[str, Any]] = []
        all_routes = world["routes"]
        for entry in entries:
            if entry.get("prefix") not in prefixes:
                raise ValueError("OUT_OF_PLAN_ENTRY_PREFIX")
            if (int(entry["ifIndex"]) != int(journal["beforeIndex"])
                or entry["nextHop"] != journal["beforeGateway"]):
                raise ValueError("ENTRY_INTERFACE_OR_GATEWAY_MISMATCH")
            identity = route_identity(entry)
            if identity in originals:
                raise ValueError("BORROWED_ROUTE_IN_OWNED_JOURNAL")
            same_prefix = [x for x in all_routes if x["prefix"] == entry["prefix"]]
            exact = [x for x in same_prefix if route_identity(x) == identity]
            state = entry["state"]
            if state not in {"INTENT", "VERIFIED", "REMOVED", "NOT_PRESENT"}:
                raise ValueError("INVALID_JOURNAL_STATE")
            if len(same_prefix) > 1 or len(exact) > 1:
                reasons.append("AMBIGUOUS_ROUTE_PREFIX_" + entry["prefix"])
                continue
            if state in {"REMOVED", "NOT_PRESENT"} and exact:
                reasons.append("DELETED_ROUTE_REAPPEARED_" + entry["prefix"])
                continue
            if exact:
                possible_owned.append(exact[0])
            elif state == "VERIFIED":
                reasons.append("VERIFIED_ROUTE_ABSENT_" + entry["prefix"])
        summary["owned_candidate_routes"] = len(possible_owned)
        if reasons:
            summary["decision"] = "MOCK_MANUAL_REVIEW_REQUIRED"
            return summary
        projected = copy.deepcopy(world)
        for route in possible_owned:
            projected["routes"].remove(route)
        if world_hash(projected) != journal["beforeHash"]:
            reasons.append("PROJECTED_BASELINE_HASH_MISMATCH")
            summary["decision"] = "MOCK_MANUAL_REVIEW_REQUIRED"
            return summary
        if journal.get("status") == "MOCK_ROLLBACK_VERIFIED":
            if possible_owned:
                raise ValueError("ROLLED_BACK_JOURNAL_BUT_OWNED_ROUTES_PRESENT")
            summary["decision"] = "MOCK_ALREADY_RESTORED"
        else:
            summary["decision"] = "MOCK_RECOVERY_CANDIDATE_READONLY"
        return summary
    except (ValueError, KeyError, TypeError, OSError,
            json.JSONDecodeError, UnicodeDecodeError) as exc:
        reasons.append(str(exc))
        summary["decision"] = "BLOCKED"
        return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", required=True, help="P1C synthetic fixture only")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    result = analyze_fixture(args.fixture, args.run_id)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["decision"] in {
        "MOCK_PLAN_ONLY", "MOCK_ALREADY_RESTORED",
        "MOCK_RECOVERY_CANDIDATE_READONLY"
    } else 3


if __name__ == "__main__":
    raise SystemExit(main())
