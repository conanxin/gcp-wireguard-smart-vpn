#!/usr/bin/env python3
"""P1I: read-only Windows CIM route contract and native evidence reconciliation.

Never imports network APIs, invokes system commands, or mutates network state.
An exact native route match is NOT a proof of ownership and NEVER authorizes
a native delete. Synthetic simOwnerToken from P1H is explicitly ignored.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys
from typing import Any

SNAPSHOT_SCHEMA = "stage-c-p1i-native-cim-snapshot-v1"
SCENARIO_SCHEMA = "stage-c-p1i-native-evidence-fixture-v1"
ENV_FIELDS = (
    "PhysicalDefaultCount", "PhysicalInterfaceIndex", "PhysicalNextHop",
    "WinINETProxyEnable", "WinINETProxyServer", "NRPTCount",
    "WGServiceCount", "XrayProcessCount", "HalfDefaultRouteCount",
)
PHASES = {
    "PLANNED", "INTENT", "API_RETURNED", "POSTREAD_VERIFIED",
    "ROLLBACK_INTENT", "ROLLED_BACK",
}
REQUIRED_KEYS = {
    "DestinationPrefix", "InterfaceIndex", "NextHop", "RouteMetric",
    "Store", "Protocol", "CompartmentId",
}


class InvalidEvidence(ValueError):
    pass


def _ensure(condition: bool, code: str) -> None:
    if not condition:
        raise InvalidEvidence(code)


def _ipv4_network(s: Any) -> str:
    _ensure(isinstance(s, str), "CIDR_NOT_STRING")
    try:
        n = ipaddress.IPv4Network(s, strict=True)
    except (ValueError, ipaddress.AddressValueError) as exc:
        raise InvalidEvidence("INVALID_OR_NONCANONICAL_IPV4_CIDR") from exc
    _ensure(str(n) == s, "NONCANONICAL_IPV4_CIDR")
    return s


def _ipv4_address(s: Any) -> str:
    _ensure(isinstance(s, str), "NEXT_HOP_NOT_STRING")
    try:
        return str(ipaddress.IPv4Address(s))
    except (ValueError, ipaddress.AddressValueError) as exc:
        raise InvalidEvidence("INVALID_NEXT_HOP") from exc


def _integer(value: Any, minimum: int = 0) -> int:
    _ensure(type(value) is int and value >= minimum, "INVALID_NATIVE_NUMERIC_FIELD")
    return value


def _route(row: dict[str, Any]) -> dict[str, Any]:
    _ensure(isinstance(row, dict), "CIM_ROUTE_NOT_OBJECT")
    _ensure(REQUIRED_KEYS.issubset(row), "NATIVE_CIM_FIELDS_INCOMPLETE")
    # PolicyStore is a cmdlet query parameter, NOT the property on this host.
    store = row["Store"]
    _ensure(store in ("ActiveStore", "PersistentStore"), "INVALID_CIM_STORE")
    if "PolicyStore" in row and row["PolicyStore"] not in (None, "", store):
        raise InvalidEvidence("STORE_POLICY_STORE_CONTRADICTION")
    protocol = row["Protocol"]
    _ensure(isinstance(protocol, str) and bool(protocol), "NATIVE_PROTOCOL_MISSING")
    return {
        "prefix": _ipv4_network(row["DestinationPrefix"]),
        "ifIndex": _integer(row["InterfaceIndex"], 1),
        "hop": _ipv4_address(row["NextHop"]),
        "metric": _integer(row["RouteMetric"]),
        "store": store,
        "protocol": protocol,
        "compartment": _integer(row["CompartmentId"]),
        # Native InstanceID, Alias and simulated simOwnerToken are NOT durable
        # ownership identifiers. InstanceID is used only for diagnostic info.
        "instanceID": str(row.get("InstanceID") or ""),
    }


def _key(r: dict[str, Any]) -> tuple:
    return (
        r["store"], r["prefix"], r["ifIndex"], r["hop"],
        r["metric"], r["compartment"], r["protocol"],
    )


def _digest_route_keys(routes: list[dict[str, Any]]) -> str:
    values = [list(_key(r)) for r in routes]
    values.sort(key=lambda x: json.dumps(x, separators=(",", ":")))
    serialized = json.dumps(values, ensure_ascii=False, separators=(",", ":")).encode()
    return hashlib.sha256(serialized).hexdigest().upper()


def parse_snapshot(data: dict[str, Any]) -> dict[str, Any]:
    _ensure(isinstance(data, dict), "SNAPSHOT_NOT_OBJECT")
    _ensure(data.get("schema") == SNAPSHOT_SCHEMA, "WRONG_SNAPSHOT_SCHEMA")
    _ensure(data.get("nativeAccess") == "READ_ONLY_GET", "SNAPSHOT_ACCESS_NOT_READONLY")
    _ensure(data.get("networkMutationsPerformed") is False, "SNAPSHOT_MUTATION_FLAG")
    _ensure(data.get("nativeWriteAuthorized") is False, "SNAPSHOT_WRITE_AUTHORIZED")
    _ensure(data.get("cmdlet") == "Get-NetRoute", "SNAPSHOT_SOURCE_NOT_GET_ROUTE")
    _ensure(isinstance(data.get("environment"), dict), "ENVIRONMENT_MISSING")
    env = data["environment"]
    for field in ENV_FIELDS:
        _ensure(field in env, "ENVIRONMENT_FIELD_MISSING")
    for name in ("activeRoutes", "persistentRoutes"):
        _ensure(isinstance(data.get(name), list), "ROUTE_COLLECTION_NOT_ARRAY")
    active = [_route(r) for r in data["activeRoutes"]]
    persistent = [_route(r) for r in data["persistentRoutes"]]
    _ensure(
        len(active) == data.get("activeRouteCount") and
        len(persistent) == data.get("persistentRouteCount"),
        "ROUTE_SNAPSHOT_COUNT_MISMATCH",
    )
    _ensure(all(r["store"] == "ActiveStore" for r in active), "WRONG_ACTIVE_STORE")
    _ensure(all(r["store"] == "PersistentStore" for r in persistent), "WRONG_PERSISTENT_STORE")
    routes = active + persistent
    return {"routes": routes, "environment": {x: env[x] for x in ENV_FIELDS},
            "countActive": len(active), "countPersistent": len(persistent),
            "routeIdentityDigest": _digest_route_keys(routes),
            "sampleStoreString": data.get("sampleStoreString", ""),
            "sampleHasPolicyStoreProperty": data.get("sampleHasPolicyStoreProperty"),
            "cimClass": data.get("cimClass")}


def _prefix_rows(snapshot: dict[str, Any], prefix: str) -> list[dict[str, Any]]:
    return [row for row in snapshot["routes"] if row["prefix"] == prefix]


def _unrelated_counts(snapshot: dict[str, Any], prefixes: set[str]) -> Counter:
    return Counter(_key(x) for x in snapshot["routes"] if x["prefix"] not in prefixes)


def _claim(entry: dict[str, Any], index: int, batch_size: int) -> dict[str, Any]:
    _ensure(isinstance(entry, dict), "CLAIM_NOT_OBJECT")
    _ensure(type(entry.get("batch")) is int and
            entry["batch"] == index // batch_size + 1, "BATCH_INDEX_MISMATCH")
    _ensure(isinstance(entry.get("runId"), str) and
            re.fullmatch(r"[a-f0-9]{32}", entry["runId"]) is not None,
            "INVALID_CLAIM_RUN_ID")
    phase = entry.get("phase")
    _ensure(phase in PHASES, "UNKNOWN_RECEIPT_PHASE")
    _ensure(type(entry.get("intentPersisted")) is bool, "BAD_INTENT_EVIDENCE_FLAG")
    _ensure(type(entry.get("nativeCallReturned")) is bool, "BAD_CALL_EVIDENCE_FLAG")
    _ensure(type(entry.get("postReadVerified")) is bool, "BAD_POSTREAD_EVIDENCE_FLAG")
    # Adapter witness is route *expectation*, never a native ownership token.
    route = _route({
        "DestinationPrefix": entry.get("DestinationPrefix"),
        "InterfaceIndex": entry.get("InterfaceIndex"),
        "NextHop": entry.get("NextHop"),
        "RouteMetric": entry.get("RouteMetric"),
        "Store": entry.get("Store"),
        "Protocol": entry.get("Protocol"),
        "CompartmentId": entry.get("CompartmentId"),
    })
    _ensure(route["store"] == "ActiveStore", "PERSISTENT_TARGET_NOT_AUTHORIZED")
    return {"expected": route, "runId": entry["runId"], "phase": phase,
            "batch": entry["batch"], "intent": entry["intentPersisted"],
            "call": entry["nativeCallReturned"],
            "postRead": entry["postReadVerified"]}


def assess_scenario(scenario: dict[str, Any]) -> dict[str, Any]:
    _ensure(isinstance(scenario, dict) and
            scenario.get("schema") == SCENARIO_SCHEMA, "WRONG_SCENARIO_SCHEMA")
    _ensure(isinstance(scenario.get("entries"), list) and
            bool(scenario["entries"]), "CLAIM_ENTRIES_EMPTY")
    batch_size = _integer(scenario.get("batchSize"), 1)
    _ensure(batch_size <= 512, "BATCH_SIZE_TOO_LARGE")
    _ensure(isinstance(scenario.get("runId"), str) and
            re.fullmatch(r"[a-f0-9]{32}", scenario["runId"]) is not None,
            "INVALID_SCENARIO_RUN_ID")
    _ensure(isinstance(scenario.get("datasetSHA256"), str) and
            re.fullmatch(r"[a-fA-F0-9]{64}", scenario["datasetSHA256"]) is not None,
            "INVALID_FROZEN_DATASET_HASH")
    snapshots = [parse_snapshot(scenario[k]) for k in ("before", "post", "current")]
    before, post, current = snapshots
    witnesses = [_claim(e, i, batch_size) for i, e in enumerate(scenario["entries"])]
    _ensure(all(w["runId"] == scenario["runId"] for w in witnesses),
            "RUN_ID_CROSS_RUN_MISMATCH")
    prefixes = [w["expected"]["prefix"] for w in witnesses]
    _ensure(len(set(prefixes)) == len(prefixes), "DUPLICATE_PLAN_PREFIX")
    prefix_set = set(prefixes)

    env_changed = (
        before["environment"] != post["environment"] or
        before["environment"] != current["environment"]
    )
    physical_gate_invalid = (
        before["environment"]["PhysicalDefaultCount"] != 1 or
        before["environment"]["PhysicalInterfaceIndex"] in (0, None, "") or
        not before["environment"]["PhysicalNextHop"]
    )
    unrelated_changed = (
        _unrelated_counts(before, prefix_set) != _unrelated_counts(post, prefix_set) or
        _unrelated_counts(before, prefix_set) != _unrelated_counts(current, prefix_set)
    )

    indexed = []
    for s in snapshots:
        by_prefix = defaultdict(list)
        for route in s["routes"]:
            by_prefix[route["prefix"]].append(route)
        indexed.append(by_prefix)
    claims = []
    counts: Counter = Counter()
    for witness in witnesses:
        expected = witness["expected"]
        prefix = expected["prefix"]
        b_rows, p_rows, c_rows = [mapping.get(prefix, []) for mapping in indexed]
        c_active = [r for r in c_rows if r["store"] == "ActiveStore"]
        p_active = [r for r in p_rows if r["store"] == "ActiveStore"]
        persistent = any(
            r["store"] == "PersistentStore" for r in b_rows + p_rows + c_rows
        )
        changed_instance_id = bool(
            len(p_active) == len(c_active) == 1
            and p_active[0]["instanceID"] != c_active[0]["instanceID"]
            and _key(p_active[0]) == _key(c_active[0])
        )
        if env_changed or physical_gate_invalid:
            reason = "ENVIRONMENT_OR_PHYSICAL_GATE_DRIFT"
        elif unrelated_changed:
            reason = "UNRELATED_ROUTE_WORLD_DRIFT"
        elif persistent:
            reason = "PERSISTENT_PREFIX_CONFLICT"
        elif b_rows:
            reason = "PREEXISTING_PREFIX_NOT_OWNED"
        elif len(p_rows) > 1 or len(c_rows) > 1:
            reason = "DUPLICATE_TARGET_PREFIX"
        elif (p_rows and _key(p_rows[0]) != _key(expected) or
              c_rows and _key(c_rows[0]) != _key(expected)):
            reason = "NATIVE_IDENTITY_DRIFT"
        elif not witness["intent"]:
            reason = "MISSING_DURABLE_INTENT"
        elif witness["phase"] == "ROLLED_BACK":
            reason = ("CLOSED_NO_TARGET_PRESENT" if not c_rows
                      else "CLOSED_RECEIPT_ROUTE_STILL_PRESENT")
        elif witness["phase"] == "ROLLBACK_INTENT":
            reason = ("ROLLBACK_GAP_NO_TARGET" if not c_rows
                      else "ROLLBACK_GAP_PRESENT_OWNERSHIP_UNPROVEN")
        elif witness["phase"] in ("PLANNED", "INTENT"):
            reason = ("UNRESOLVED_INTENT_WITH_ROUTE" if p_rows or c_rows
                      else "ABSENT_NO_NATIVE_DELETE_NEEDED")
        elif not witness["call"]:
            reason = "MISSING_NATIVE_CALL_RESULT"
        elif not witness["postRead"]:
            reason = ("CRASH_GAP_MISSING_POSTREAD" if p_rows or c_rows
                      else "ABSENT_WITH_UNVERIFIED_WRITE")
        elif witness["phase"] not in ("POSTREAD_VERIFIED",):
            reason = "RECEIPT_PHASE_INCONSISTENT"
        elif len(p_rows) == 1 and len(c_rows) == 1:
            reason = "EXACT_ROUTE_WITNESSED_OWNERSHIP_UNPROVEN"
        elif not c_rows:
            reason = "TARGET_ABSENT_AFTER_RECEIPT"
        else:
            reason = "INSUFFICIENT_NATIVE_EVIDENCE"
        counts[reason] += 1
        claims.append({
            "prefix": prefix, "batch": witness["batch"],
            "receiptPhase": witness["phase"], "classification": reason,
            "beforeCount": len(b_rows), "postCount": len(p_rows),
            "currentCount": len(c_rows),
            "instanceIdChangedOnReEnumeration": changed_instance_id,
            "nativeOwnershipProven": False,
            "nativeDeleteAllowed": False,
        })
    review_count = counts["EXACT_ROUTE_WITNESSED_OWNERSHIP_UNPROVEN"]
    harmless = counts["ABSENT_NO_NATIVE_DELETE_NEEDED"] + counts["CLOSED_NO_TARGET_PRESENT"]
    blocked = len(claims) - review_count - harmless
    return {
        "schema": "stage-c-p1i-evidence-report-v1",
        "result": "NATIVE_EVIDENCE_BLOCKED" if blocked else "READ_ONLY_EVIDENCE_CLASSIFIED",
        "prefixCount": len(claims),
        "batchCount": (len(claims) + batch_size - 1) // batch_size,
        "reviewOnlyWitnesses": review_count,
        "blockedWitnesses": blocked,
        "absentOrClosedWitnesses": harmless,
        "nativeReEnumerationInstanceIdChanges": sum(
            x["instanceIdChangedOnReEnumeration"] for x in claims
        ),
        "environmentDrift": env_changed,
        "unrelatedRouteDrift": unrelated_changed,
        "classificationCounts": dict(sorted(counts.items())),
        "nativeApplyAuthorized": False,
        "nativeDeleteAuthorized": False,
        "networkMutationsPerformed": False,
        "claims": claims,
    }


def load_json(path: str) -> dict:
    file = Path(path)
    _ensure(file.is_file() and not file.is_symlink(), "EVIDENCE_FILE_MISSING_OR_SYMLINK")
    try:
        data = json.loads(file.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        raise InvalidEvidence("EVIDENCE_JSON_PARSE_FAILED") from exc
    _ensure(isinstance(data, dict), "EVIDENCE_ROOT_NOT_OBJECT")
    return data


def main() -> int:
    p = argparse.ArgumentParser(description="Stage C P1I no-write native CIM evidence inspector")
    choice = p.add_mutually_exclusive_group(required=True)
    choice.add_argument("--snapshot-json")
    choice.add_argument("--scenario-json")
    args = p.parse_args()
    try:
        if args.snapshot_json:
            s = parse_snapshot(load_json(args.snapshot_json))
            report = {
                "schema": "stage-c-p1i-inspect-report-v1",
                "result": "READ_ONLY_NATIVE_CIM_INSPECTED",
                "cimClass": s["cimClass"],
                "storeField": "Store",
                "policyStorePropertyExposed": s["sampleHasPolicyStoreProperty"],
                "activeRoutes": s["countActive"],
                "persistentRoutes": s["countPersistent"],
                "physicalDefaultCount": s["environment"]["PhysicalDefaultCount"],
                "routeIdentityDigest": s["routeIdentityDigest"],
                "nativeApplyAuthorized": False,
                "nativeDeleteAuthorized": False,
                "networkMutationsPerformed": False,
            }
            code = 0
        else:
            report = assess_scenario(load_json(args.scenario_json))
            code = 2 if report["blockedWitnesses"] else 0
        print(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return code
    except InvalidEvidence as exc:
        print(json.dumps({
            "result": "BLOCKED_INVALID_EVIDENCE", "reason": str(exc),
            "nativeApplyAuthorized": False,
            "nativeDeleteAuthorized": False,
            "networkMutationsPerformed": False,
        }, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return 4


if __name__ == "__main__":
    sys.exit(main())
