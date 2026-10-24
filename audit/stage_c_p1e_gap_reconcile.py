#!/usr/bin/env python3
"""P1E conservative synthetic crash-gap reconciler for P1C journals.

This tool NEVER reads or changes Windows native routes, DNS, WinINET, WG,
NRPT, xray, GCP or registry. It inspects only explicitly selected P1C mock
filesystem fixtures. Opt-in mock repair appends one audit event only if:
- the audit event chain itself is intact;
- exactly mockworld.json differs from the last committed file digests;
- the latest journal has an unverified INTENT whose exact route is present;
- removing only the strictly owned simulation routes projects the ORIGINAL
  saved world SHA256; and
- no third-party same-prefix collision or divergent proxy/NRPT/gateway exists.

This is a mock crash consistency repair, not an automatic Windows route
rollback, and not authorized for native networking.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from stage_c_p1d_recovery_audit import (
    audit_event_hash, digest_text, route_identity, world_hash
)

SCHEMA = "stage-c-p1e-synthetic-gap-v1"
RID = re.compile(r"^[A-Za-z0-9_-]{3,64}$")
FILE_NAME = re.compile(r"^(mockworld\.json|prefixes\.txt|plan-[A-Za-z0-9_-]+\.json|journal-[A-Za-z0-9_-]+\.json)$")
ACCEPTED_JOURNAL_STATE = {"INTENT", "VERIFIED", "REMOVED", "NOT_PRESENT"}


def _sandbox(folder: Path, allow_test_fixture: bool = False) -> Path:
    if folder.is_symlink():
        raise ValueError("SYMLINK_FIXTURE_NOT_ALLOWED")
    resolved = folder.resolve(strict=True)
    if not resolved.is_dir() or not resolved.name.startswith("p1c-fixture-"):
        raise ValueError("NOT_P1C_FIXTURE")
    if not allow_test_fixture:
        name = resolved.parent.name
        ancestor = [x.name for x in resolved.parents]
        if name != "P1CMock" or "GcpWGStageC" not in ancestor or "Local" not in ancestor or "AppData" not in ancestor:
            raise ValueError("NOT_P1C_PROTECTED_LOCALAPPDATA_LOCATION")
    return resolved


def _plain_file(folder: Path, name: str) -> Path:
    if not FILE_NAME.fullmatch(name):
        raise ValueError("FILE_NAME_OUTSIDE_ALLOWLIST")
    path = folder / name
    if path.is_symlink() or not path.is_file() or path.parent != folder:
        raise ValueError("NOT_REGULAR_FIXTURE_FILE")
    return path


def _json(folder: Path, name: str) -> dict:
    obj = json.loads(_plain_file(folder, name).read_text(encoding="utf-8-sig"))
    if not isinstance(obj, dict):
        raise ValueError("JSON_NOT_OBJECT")
    return obj


def _intact_chain(folder: Path, rid: str) -> tuple[list[dict], dict[str, str], bytes]:
    audit_path = folder / f"audit-{rid}.ndjson"
    if audit_path.is_symlink() or not audit_path.is_file():
        raise ValueError("AUDIT_MISSING")
    raw = audit_path.read_bytes()
    if not raw or not raw.endswith(b"\n"):
        raise ValueError("AUDIT_MISSING_OR_TRUNCATED_NEWLINE")
    events: list[dict] = []
    latest: dict[str, str] = {}
    prev = "GENESIS"
    for n, row in enumerate(raw.decode("utf-8").splitlines(), 1):
        if not row:
            raise ValueError("AUDIT_BLANK_LINE")
        event = json.loads(row)
        if (not isinstance(event, dict) or event.get("sequence") != n or
            event.get("runId") != rid or event.get("prev") != prev or
            event.get("hash") != audit_event_hash(event)):
            raise ValueError("AUDIT_CHAIN_CORRUPT")
        name = event.get("file")
        if not isinstance(name, str) or not FILE_NAME.fullmatch(name):
            raise ValueError("AUDIT_UNSAFE_FILENAME")
        latest[name] = event["fileSha256"]
        events.append(event)
        prev = event["hash"]
    return events, latest, raw


def assess(folder: str | Path, run_id: str, *, allow_test_fixture: bool = False) -> dict[str, Any]:
    outcome: dict[str, Any] = {
        "schema": SCHEMA, "mode": "READ_ONLY",
        "decision": "BLOCKED", "run_id": run_id, "reason": "",
        "mock_intent_candidates": 0, "audit_repair_authorized": False,
        "native_route_mutation": False, "live_canary_authorized": False,
        "window_route_delete_executed": False,
    }
    try:
        if not RID.fullmatch(run_id):
            raise ValueError("INVALID_RUN_ID")
        root = _sandbox(Path(folder), allow_test_fixture)
        events, latest, _ = _intact_chain(root, run_id)
        missing_or_bad: list[str] = []
        for name, old_digest in latest.items():
            raw_file = _plain_file(root, name)
            current = hashlib.sha256(raw_file.read_bytes()).hexdigest().upper()
            if current != old_digest:
                missing_or_bad.append(name)
        if not missing_or_bad:
            outcome["decision"] = "ALREADY_AUDITED"
            return outcome
        if missing_or_bad != ["mockworld.json"]:
            raise ValueError("NON_WORLD_COMMITTED_FILE_MISMATCH")
        plan = _json(root, f"plan-{run_id}.json")
        journal = _json(root, f"journal-{run_id}.json")
        world = _json(root, "mockworld.json")
        prefixes = [
            row.strip() for row in _plain_file(root, "prefixes.txt").read_text(encoding="utf-8-sig").splitlines()
            if row.strip()
        ]
        if (plan.get("schema") != "stage-c-p1c-route-v1" or
            plan.get("runId") != run_id or
            journal.get("schema") != "stage-c-p1c-route-v1" or
            journal.get("runId") != run_id or
            plan.get("worldHash") != journal.get("beforeHash") or
            plan.get("prefixesHash") != digest_text("\n".join(prefixes))):
            raise ValueError("PLAN_JOURNAL_PRESTATE_MISMATCH")
        entries = journal.get("entries")
        if not isinstance(entries, list) or not entries:
            raise ValueError("MISSING_JOURNAL_INTENTS")
        originals = set(journal.get("beforeRoutes", []))
        target_prefixes = set(prefixes)
        now = world.get("routes")
        if not isinstance(now, list):
            raise ValueError("WORLD_ROUTES_INVALID")
        remaining = copy.deepcopy(world)
        intent_count = 0
        for item in entries:
            prefix = item.get("prefix")
            if prefix not in target_prefixes:
                raise ValueError("OUT_OF_PLAN_PREFIX")
            if (int(item.get("ifIndex", -1)) != int(journal.get("beforeIndex", -2)) or
                item.get("nextHop") != journal.get("beforeGateway") or
                item.get("state") not in ACCEPTED_JOURNAL_STATE):
                raise ValueError("OWNERSHIP_OR_JOURNAL_STATE_INVALID")
            identity = route_identity(item)
            if identity in originals:
                raise ValueError("BORROWED_ROUTE_IN_INTENT")
            matching_prefix = [x for x in now if x.get("prefix") == prefix]
            exact = [x for x in matching_prefix if route_identity(x) == identity]
            if len(matching_prefix) != len(exact) or len(exact) > 1:
                raise ValueError("AMBIGUOUS_ROUTE_PREFIX")
            if item["state"] == "INTENT":
                if len(exact) != 1:
                    raise ValueError("UNVERIFIED_INTENT_ROUTE_ABSENT_OR_DUPLICATE")
                intent_count += 1
            if exact:
                remaining["routes"].remove(exact[0])
        if intent_count != 1:
            raise ValueError("GAP_INTENT_COUNT_NOT_EXACTLY_ONE")
        if world_hash(remaining) != journal["beforeHash"]:
            raise ValueError("PROJECTED_BASELINE_HASH_MISMATCH")
        if events[-1].get("kind") not in {"FILE_COMMITTED", "PLAN_DESIRED_PREFIXES", "PLAN_BASELINE_WORLD"}:
            raise ValueError("AUDIT_EVENT_LAST_KIND_INVALID")
        outcome["mock_intent_candidates"] = intent_count
        outcome["decision"] = "MOCK_AUDIT_GAP_RECONCILABLE"
        return outcome
    except (ValueError, KeyError, OSError, TypeError, UnicodeDecodeError,
            json.JSONDecodeError) as exc:
        outcome["reason"] = str(exc)
        return outcome


def repair_mock_audit(folder: str | Path, run_id: str, *, allow_test_fixture: bool = False) -> dict[str, Any]:
    """Append a *synthetic-world* audit event. Never touch Windows OS routes."""
    result = assess(folder, run_id, allow_test_fixture=allow_test_fixture)
    if result["decision"] != "MOCK_AUDIT_GAP_RECONCILABLE":
        return result
    root = _sandbox(Path(folder), allow_test_fixture)
    events, latest, old_audit = _intact_chain(root, run_id)
    world_bytes = _plain_file(root, "mockworld.json").read_bytes()
    latest_digest = hashlib.sha256(world_bytes).hexdigest().upper()
    appended = {
        "sequence": len(events)+1, "prev": events[-1]["hash"],
        "kind": "P1E_GAP_RECONCILED_WORLD", "file": "mockworld.json",
        "fileSha256": latest_digest, "runId": run_id,
    }
    appended["hash"] = audit_event_hash(appended)
    event_bytes = (json.dumps(appended, separators=(",", ":"))+"\n").encode("utf-8")
    audit_file = root / f"audit-{run_id}.ndjson"
    if audit_file.read_bytes() != old_audit:
        return {**result, "decision": "BLOCKED", "reason": "AUDIT_CHANGED_DURING_REPAIR"}
    # Mock-only append; no native route or service interaction.
    with open(audit_file, "ab") as handle:
        handle.write(event_bytes)
        handle.flush()
        os.fsync(handle.fileno())
    result["decision"] = "MOCK_AUDIT_GAP_REPAIRED"
    result["mode"] = "MOCK_FILE_APPEND_ONLY"
    result["audit_repair_authorized"] = True
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--mode", choices=["inspect", "repair-mock-audit"], default="inspect")
    args = parser.parse_args()
    result = (
        assess(args.fixture, args.run_id)
        if args.mode == "inspect"
        else repair_mock_audit(args.fixture, args.run_id)
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["decision"] in {"ALREADY_AUDITED", "MOCK_AUDIT_GAP_RECONCILABLE",
                                       "MOCK_AUDIT_GAP_REPAIRED"} else 3


if __name__ == "__main__":
    raise SystemExit(main())
