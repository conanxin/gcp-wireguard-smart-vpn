#!/usr/bin/env python3
"""P1J: indistinguishable native-route histories and receipt crash-window model.

Pure Python 3.12. No Windows API, native route write/delete, network calls,
scheduler, native watchdog, or external command execution. This model makes
the mismatch between a native route's identity and its ownership explicit.

The synthetic "truthOwner" attribute is an oracle for the TEST ONLY and is
stripped before each route reaches the P1I native CIM evidence contract.
"""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys
from typing import Any

from stage_c_p1i_native_contract import (
    InvalidEvidence, assess_scenario, parse_snapshot,
)

SCHEMA = "stage-c-p1j-observability-pair-v1"
RUN_ID = "1234567890abcdef1234567890abcdef"
SOURCE_DIGEST = "a" * 64
DEFAULT_PREFIX = "198.51.100.77/32"
NATIVE_VISIBLE_FIELDS = (
    "DestinationPrefix", "InterfaceIndex", "NextHop", "RouteMetric", "Store",
    "Protocol", "CompartmentId", "InstanceID", "InterfaceAlias",
)

RESTING_ENV = {
    "PhysicalDefaultCount": 1,
    "PhysicalInterfaceIndex": 9,
    "PhysicalNextHop": "192.168.0.1",
    "WinINETProxyEnable": 1,
    "WinINETProxyServer": "127.0.0.1:7897",
    "NRPTCount": 25,
    "WGServiceCount": 0,
    "XrayProcessCount": 1,
    "HalfDefaultRouteCount": 0,
}

# Each window represents a completed or partially completed durable receipt.
# The classifier does NOT infer a native deletion authorization from receipts.
WINDOWS = {
    "BEFORE_INTENT": ("PLANNED", False, False, False, False),
    "INTENT_ONLY": ("INTENT", False, True, False, False),
    "CALL_ENTERED_NO_ACK": ("INTENT", True, True, False, False),
    "API_RETURN_NOT_PERSISTED": ("API_RETURNED", True, True, False, False),
    "CALL_ACK_DURABLE": ("API_RETURNED", True, True, True, False),
    "POSTREAD_NOT_COMMITTED": ("API_RETURNED", True, True, True, True),
    "VERIFIED_RECEIPT": ("POSTREAD_VERIFIED", True, True, True, True),
    "ROLLBACK_INTENT_PENDING": ("ROLLBACK_INTENT", True, True, True, True),
    "DELETE_ACK_NOT_PERSISTED": ("ROLLBACK_INTENT", False, True, True, True),
    "ROLLBACK_CLOSED_BUT_ROUTE_PRESENT": ("ROLLED_BACK", True, True, True, True),
    "ROLLBACK_CLOSED_AND_ABSENT": ("ROLLED_BACK", False, True, True, True),
}

# How an externally created same-identity object could enter the visible world.
# It is deliberately NOT exported into native route observations.
RACES = (
    "EXTERNAL_INSERT_BEFORE_POSTREAD",
    "EXTERNAL_REPLACE_AFTER_POSTREAD",
    "EXTERNAL_RECREATE_AFTER_PARENT_EXIT",
    "EXTERNAL_REPLACE_DURING_RECOVERY",
)


def canonical(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")


def fingerprint(data: Any) -> str:
    return hashlib.sha256(canonical(data)).hexdigest().upper()


def ensure(ok: bool, reason: str) -> None:
    if not ok:
        raise InvalidEvidence(reason)


def route(prefix: str = DEFAULT_PREFIX, *, instance: str = "native-opaque") -> dict[str, Any]:
    try:
        n = ipaddress.IPv4Network(prefix, strict=True)
    except ValueError as exc:
        raise InvalidEvidence("INVALID_TEST_TARGET_CIDR") from exc
    ensure(str(n) == prefix, "NONCANONICAL_TEST_TARGET_CIDR")
    return {
        "DestinationPrefix": prefix, "InterfaceIndex": 9,
        "NextHop": "192.168.0.1", "RouteMetric": 5,
        "Store": "ActiveStore", "Protocol": "NetMgmt",
        "CompartmentId": 1, "InstanceID": instance,
        "InterfaceAlias": "WLAN",
    }


def _default_route() -> dict:
    result = route("0.0.0.0/0", instance="physical-default")
    result["RouteMetric"] = 0
    return result


def hide_truth(row: dict) -> dict:
    # Crucial: no ownership/actor fields survive normalization. A same-identity
    # external route looks exactly like a program-created native route.
    return {field: row[field] for field in NATIVE_VISIBLE_FIELDS}


def native_snapshot(hidden_rows: list[dict],
                    env: dict | None = None) -> dict:
    visible = [hide_truth(item) for item in hidden_rows]
    a = [item for item in visible if item["Store"] == "ActiveStore"]
    p = [item for item in visible if item["Store"] == "PersistentStore"]
    return {
        "schema": "stage-c-p1i-native-cim-snapshot-v1",
        "nativeAccess": "READ_ONLY_GET",
        "cmdlet": "Get-NetRoute",
        "networkMutationsPerformed": False,
        "nativeWriteAuthorized": False,
        "sampleStoreString": "ActiveStore",
        "sampleHasPolicyStoreProperty": False,
        "cimClass": "MSFT_NetRoute",
        "activeRouteCount": len(a),
        "persistentRouteCount": len(p),
        "activeRoutes": a,
        "persistentRoutes": p,
        "environment": deepcopy(RESTING_ENV if env is None else env),
    }


def hidden_object(prefix: str, owner: str,
                  instance: str = "native-opaque") -> dict:
    ensure(owner in ("PROJECT", "EXTERNAL", "BASELINE"), "INVALID_ORACLE_OWNER")
    obj = route(prefix, instance=instance)
    obj["truthOwner"] = owner
    # These markers must never be part of a snapshot or used for a decision.
    obj["simOwnerToken"] = f"ORACLE_ONLY_{owner}"
    return obj


def observation_worlds(prefix: str, *, race: str, target_present: bool,
                       instance_current: str = "native-opaque") -> dict:
    ensure(race in RACES, "UNKNOWN_RACE_INJECTION")
    baseline = hidden_object("0.0.0.0/0", "BASELINE", instance="physical-default")
    baseline["RouteMetric"] = 0
    native = hidden_object(prefix, "PROJECT")
    external = hidden_object(prefix, "EXTERNAL")
    # Postread can be exactly the same whether an external route already
    # replaced our route or replacement occurs after the first enumeration.
    project_post = [baseline, native]
    other_post = [baseline, external] if race == RACES[0] else [baseline, native]
    project_current = ([baseline, hidden_object(prefix, "PROJECT", instance_current)]
                       if target_present else [baseline])
    other_current = ([baseline, hidden_object(prefix, "EXTERNAL", instance_current)]
                     if target_present else [baseline])
    return {
        "project": {"before": [baseline], "post": project_post,
                    "current": project_current},
        "external": {"before": [baseline], "post": other_post,
                     "current": other_current},
        "oracleProjectOwner": "PROJECT" if target_present else "NONE",
        "oracleOtherOwner": "EXTERNAL" if target_present else "NONE",
        "race": race,
    }


def fixture_from_worlds(worlds: dict, key: str, *, prefix: str,
                        window: str) -> dict:
    ensure(window in WINDOWS, "UNKNOWN_CRASH_WINDOW")
    phase, visible, intent, call, postread = WINDOWS[window]
    timeline = worlds[key]
    # Observations must reflect what was available at each stage.
    # After closed/absent native read, a route could still have existed at
    # the postread; current enumeration is the only thing that is absent.
    post = timeline["post"] if visible or phase in ("ROLLED_BACK", "ROLLBACK_INTENT") else timeline["before"]
    current = timeline["current"] if visible else timeline["before"]
    witness = route(prefix)
    witness.update({
        "runId": RUN_ID, "batch": 1, "phase": phase,
        "intentPersisted": intent, "nativeCallReturned": call,
        "postReadVerified": postread,
    })
    return {
        "schema": "stage-c-p1i-native-evidence-fixture-v1",
        "runId": RUN_ID,
        "datasetSHA256": SOURCE_DIGEST,
        "batchSize": 1,
        "entries": [witness],
        "before": native_snapshot(timeline["before"]),
        "post": native_snapshot(post),
        "current": native_snapshot(current),
    }


def adjudication(report: dict) -> str:
    ensure(report.get("nativeDeleteAuthorized") is False and
           report.get("nativeApplyAuthorized") is False and
           report.get("networkMutationsPerformed") is False,
           "P1I_REPORT_UNSAFE_AUTHORIZATION")
    if report["blockedWitnesses"]:
        return "BLOCKED_NO_NATIVE_DELETE"
    if report["reviewOnlyWitnesses"]:
        return "MANUAL_REVIEW_ONLY_OWNERSHIP_UNPROVEN"
    return "NO_TARGET_TO_DELETE"


def evaluate_pair(prefix: str = DEFAULT_PREFIX, *,
                  race: str = RACES[1], window: str = "VERIFIED_RECEIPT",
                  instance_current: str = "native-opaque") -> dict:
    ensure(race in RACES, "UNKNOWN_RACE_INJECTION")
    ensure(window in WINDOWS, "UNKNOWN_CRASH_WINDOW")
    present = WINDOWS[window][1]
    worlds = observation_worlds(prefix, race=race, target_present=present,
                                 instance_current=instance_current)
    scenarios = [
        fixture_from_worlds(worlds, key, prefix=prefix, window=window)
        for key in ("project", "external")
    ]
    proof_hashes = [fingerprint(x) for x in scenarios]
    # Critical invariant: two different hidden histories give the very same
    # observable snapshots, run receipts and route identity.
    ensure(proof_hashes[0] == proof_hashes[1],
           "RACE_HISTORIES_NOT_OBSERVATIONALLY_EQUIVALENT")
    evaluations = [assess_scenario(x) for x in scenarios]
    ensure(fingerprint(evaluations[0]) == fingerprint(evaluations[1]),
           "NATIVE_CLASSIFIER_DEPENDS_ON_HIDDEN_OWNER")
    outcome = adjudication(evaluations[0])
    return {
        "schema": SCHEMA,
        "result": "INDISTINGUISHABLE_HISTORY_CONFIRMED",
        "race": race,
        "crashWindow": window,
        "observableFingerprintProject": proof_hashes[0],
        "observableFingerprintExternal": proof_hashes[1],
        "observationallyIndistinguishable": True,
        "oracleOwnerProject": worlds["oracleProjectOwner"],
        "oracleOwnerExternal": worlds["oracleOtherOwner"],
        "p1iClassification": evaluations[0]["claims"][0]["classification"],
        "p1iReviewOnly": evaluations[0]["reviewOnlyWitnesses"],
        "p1iBlocked": evaluations[0]["blockedWitnesses"],
        "decision": outcome,
        "nativeDeleteAuthorized": False,
        "nativeApplyAuthorized": False,
        "networkMutationsPerformed": False,
    }


def batch_corpus(prefixes: list[str], *, batch_size: int = 512,
                 external_ordinals: set[int] | None = None,
                 receipt_gap_ordinals: set[int] | None = None) -> dict:
    ensure(1 <= batch_size <= 512, "INVALID_BATCH_SIZE")
    ensure(prefixes and len(set(prefixes)) == len(prefixes),
           "EMPTY_OR_DUPLICATE_SOURCE")
    for p in prefixes:
        route(p)  # strict & canonical
    replaced = set(external_ordinals or ())
    gaps = set(receipt_gap_ordinals or ())
    ensure(all(0 <= i < len(prefixes) for i in replaced | gaps),
           "BAD_CORPUS_FAULT_INDEX")
    base = _default_route()
    before = [base]
    post = [base] + [route(p, instance=f"post-{i}") for i, p in enumerate(prefixes)]
    current = [base] + [
        route(p, instance=f"current-{i}") for i, p in enumerate(prefixes)
    ]
    # Hidden truth after a replacement cannot be read from native snapshots.
    simulated_truth = {i: "EXTERNAL" for i in sorted(replaced)}
    entries = []
    for i, prefix in enumerate(prefixes):
        row = route(prefix)
        row.update({
            "runId": RUN_ID, "batch": (i // batch_size) + 1,
            "phase": "API_RETURNED" if i in gaps else "POSTREAD_VERIFIED",
            "intentPersisted": True,
            "nativeCallReturned": True,
            "postReadVerified": False if i in gaps else True,
        })
        entries.append(row)
    scenario = {
        "schema": "stage-c-p1i-native-evidence-fixture-v1",
        "runId": RUN_ID, "datasetSHA256": SOURCE_DIGEST,
        "batchSize": batch_size, "entries": entries,
        "before": native_snapshot(before),
        "post": native_snapshot(post),
        "current": native_snapshot(current),
    }
    report = assess_scenario(scenario)
    ensure(report["nativeDeleteAuthorized"] is False, "UNSAFE_CORPUS_NATIVE_DELETE")
    return {
        "result": "BATCH_NATIVE_EVIDENCE_ONLY",
        "sourceCount": len(prefixes),
        "batchCount": report["batchCount"],
        "oracleExternalReplacements": len(simulated_truth),
        "incompletePostreadReceipts": len(gaps),
        "reviewOnlyWitnesses": report["reviewOnlyWitnesses"],
        "blockedWitnesses": report["blockedWitnesses"],
        "unprovenNativeOwnership": len(report["claims"]),
        "classificationCounts": report["classificationCounts"],
        "nativeDeleteAuthorized": False,
        "networkMutationsPerformed": False,
    }


def load_cidrs(path: str) -> list[str]:
    p = Path(path)
    ensure(p.is_file() and not p.is_symlink(), "CIDR_SOURCE_MISSING")
    lines = [x.strip() for x in p.read_text(encoding="utf-8-sig").splitlines() if x.strip()]
    ensure(lines, "CIDR_SOURCE_EMPTY")
    ensure(len(lines) == len(set(lines)), "DUPLICATE_CIDR_SOURCE")
    for value in lines:
        route(value)
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(
        description="P1J native route identity race, crash window, no-write mock")
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--pair", action="store_true")
    choice.add_argument("--matrix", action="store_true")
    choice.add_argument("--corpus", help="Path to unchanged CIDR source file")
    parser.add_argument("--race", choices=RACES, default=RACES[1])
    parser.add_argument("--window", choices=tuple(WINDOWS),
                        default="VERIFIED_RECEIPT")
    parser.add_argument("--prefix", default=DEFAULT_PREFIX)
    args = parser.parse_args()
    try:
        if args.pair:
            report = evaluate_pair(args.prefix, race=args.race, window=args.window)
        elif args.matrix:
            reports = [evaluate_pair(args.prefix, race=race, window=window)
                       for race in RACES for window in WINDOWS]
            report = {
                "schema": "stage-c-p1j-crash-window-matrix-v1",
                "result": "ALL_NATIVE_RACE_WINDOWS_FAIL_CLOSED",
                "cases": len(reports),
                "crashWindows": len(WINDOWS),
                "raceCases": len(RACES),
                "allObservablePairsEquivalent": all(
                    x["observationallyIndistinguishable"] for x in reports),
                "pairsWithPresentTargetAndDifferentHiddenOwners": sum(
                    x["oracleOwnerProject"] != x["oracleOwnerExternal"]
                    for x in reports),
                "pairsWithAbsentTargetNoDeleteNeeded": sum(
                    x["oracleOwnerProject"] == "NONE" for x in reports),
                "unsafeNativeDeleteApprovals": sum(
                    bool(x["nativeDeleteAuthorized"]) for x in reports),
                "decisions": dict(Counter(x["decision"] for x in reports)),
                "nativeDeleteAuthorized": False,
                "networkMutationsPerformed": False,
            }
        else:
            corpus = load_cidrs(args.corpus)
            # Explicit failures in 7th / last simulated batch; P1H's 512 limit.
            report = batch_corpus(
                corpus, batch_size=512,
                external_ordinals={min(len(corpus)-1, 3072), len(corpus)-1},
                receipt_gap_ordinals={min(len(corpus)-1, 3073)},
            )
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
        return 0
    except (InvalidEvidence, OSError, ValueError, KeyError, TypeError) as e:
        print(json.dumps({
            "result": "BLOCKED_INVALID_FIXTURE",
            "reason": str(e) if isinstance(e, InvalidEvidence) else type(e).__name__,
            "nativeDeleteAuthorized": False,
            "networkMutationsPerformed": False,
        }, ensure_ascii=False, sort_keys=True))
        return 4


if __name__ == "__main__":
    sys.exit(main())
