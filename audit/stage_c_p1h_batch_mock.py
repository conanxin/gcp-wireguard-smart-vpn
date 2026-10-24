#!/usr/bin/env python3
"""Stage C P1H: synthetic-only batched CN route ledger, never OS network writes.

A run lives strictly inside an explicitly named p1h-fixture-* directory under
the user's P1HMock root. All route/world objects are synthetic JSON data.
The synthetic owner token DOES NOT exist on Windows native route objects.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import time
import uuid

SCHEMA = "stage-c-p1h-batch-fixture-v1"
ROOT = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / ".local" / "state")) / "GcpWGStageC" / "P1HMock"
ROOT = ROOT.resolve()
MAX_BATCH = 512


class Blocked(RuntimeError):
    pass


def canonical(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(obj: object) -> str:
    return hashlib.sha256(canonical(obj)).hexdigest()


def emit(key: str, value: object) -> None:
    print(f"P1H_{key}={value}", flush=True)


def sandbox_path(value: str) -> Path:
    given = Path(value).expanduser()
    if given.is_symlink():
        raise Blocked("SYMLINK_SANDBOX_DENIED")
    dest = given.resolve()
    if dest.parent != ROOT or not re.fullmatch(r"p1h-fixture-[a-zA-Z0-9_-]{6,64}", dest.name):
        raise Blocked("SANDBOX_OUTSIDE_DEDICATED_ROOT")
    if ROOT.is_symlink() or dest.is_symlink():
        raise Blocked("REPARSE_OR_SYMLINK_DENIED")
    return dest


@contextlib.contextmanager
def writer_lock(sandbox: Path):
    sandbox.mkdir(parents=True, exist_ok=True)
    lockfile = sandbox / ".writer.lock"
    with open(lockfile, "a+b") as handle:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"X")
            handle.flush()
        handle.seek(0)
        if os.name == "nt":
            import msvcrt
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise Blocked("EXCLUSIVE_WRITER_BUSY") from exc
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise Blocked("EXCLUSIVE_WRITER_BUSY") from exc
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def event(state: dict, kind: str, batch: int | None = None, **details: object) -> None:
    prev = state["audit"][-1]["sha"] if state["audit"] else "GENESIS"
    row = {"seq": len(state["audit"]) + 1, "prev": prev,
           "kind": kind, "batch": batch, "details": details}
    row["sha"] = digest(row)
    state["audit"].append(row)


def write_state(sandbox: Path, state: dict) -> None:
    state["seal"] = digest({k: v for k, v in state.items() if k != "seal"})
    dest = sandbox / "state.json"
    tmp = sandbox / f".state-{os.getpid()}-{uuid.uuid4().hex}.tmp"
    try:
        with open(tmp, "wb") as handle:
            handle.write(canonical(state) + b"\n")
            handle.flush()
        # Fixture durability is process-crash-level only, not power-loss safe.
        os.replace(tmp, dest)
    finally:
        if tmp.exists():
            tmp.unlink()


def read_state(sandbox: Path) -> dict:
    target = sandbox / "state.json"
    if target.is_symlink() or not target.is_file():
        raise Blocked("STATE_MISSING_OR_SYMLINK")
    try:
        state = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        raise Blocked("STATE_PARSE_FAILED") from exc
    if not isinstance(state, dict) or state.get("schema") != SCHEMA:
        raise Blocked("STATE_SCHEMA_MISMATCH")
    seal = state.get("seal")
    if not isinstance(seal, str) or seal != digest({k: v for k, v in state.items() if k != "seal"}):
        raise Blocked("STATE_SEAL_MISMATCH")
    prior = "GENESIS"
    for position, row in enumerate(state["audit"], 1):
        if row["seq"] != position or row["prev"] != prior:
            raise Blocked("AUDIT_CHAIN_SEQUENCE_OR_PARENT_MISMATCH")
        if row.get("sha") != digest({k: v for k, v in row.items() if k != "sha"}):
            raise Blocked("AUDIT_CHAIN_HASH_MISMATCH")
        prior = row["sha"]
    if len(state["entries"]) != len(state["prefixes"]):
        raise Blocked("PLAN_ENTRY_COUNT_MISMATCH")
    if len({r["prefix"] for r in state["entries"]}) != len(state["entries"]):
        raise Blocked("PLAN_DUPLICATE_ENTRY")
    if [r["prefix"] for r in state["entries"]] != state["prefixes"]:
        raise Blocked("PLAN_ENTRY_ORDER_MISMATCH")
    if digest(state["prefixes"]) != state["planHash"]:
        raise Blocked("PLAN_FINGERPRINT_MISMATCH")
    if state["dataset"]["selectedCount"] != len(state["entries"]):
        raise Blocked("DATASET_SELECTED_COUNT_MISMATCH")
    return state


def validate_dataset(path: Path) -> tuple[list[str], str]:
    if path.is_symlink() or not path.is_file():
        raise Blocked("DATASET_FILE_MISSING_OR_LINK")
    raw = path.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    networks = []
    seen = set()
    try:
        for line in raw.decode("utf-8-sig").splitlines():
            value = line.strip()
            if not value:
                continue
            net = ipaddress.ip_network(value, strict=True)
            if not isinstance(net, ipaddress.IPv4Network) or str(net) != value:
                raise ValueError("invalid or noncanonical IPv4 network")
            if value in seen:
                raise ValueError("duplicate prefix")
            seen.add(value)
            networks.append(net)
    except (UnicodeError, ValueError) as exc:
        raise Blocked("DATASET_MALFORMED_OR_DUPLICATE") from exc
    if not networks:
        raise Blocked("DATASET_EMPTY")
    if len(list(ipaddress.collapse_addresses(networks))) != len(networks):
        raise Blocked("DATASET_OVERLAP_OR_MERGEABLE")
    return [str(n) for n in networks], sha


def check_source(state: dict) -> None:
    path = Path(state["dataset"]["path"])
    if not path.is_file() or path.is_symlink():
        raise Blocked("FROZEN_SOURCE_UNAVAILABLE")
    if hashlib.sha256(path.read_bytes()).hexdigest() != state["dataset"]["sha256"]:
        raise Blocked("FROZEN_SOURCE_SHA_CHANGED")


def batches(state: dict) -> list[list[dict]]:
    n = state["dataset"]["batchSize"]
    return [state["entries"][i:i + n] for i in range(0, len(state["entries"]), n)]


def route_for(entry: dict) -> dict:
    return dict(entry["route"])


def route_matches(row: dict, entry: dict) -> bool:
    return row == route_for(entry)


def verify_mock_world(state: dict) -> None:
    """Full-run preflight, done before removing ANY route."""
    if state["environment"] != state["originalEnvironment"]:
        raise Blocked("ENVIRONMENT_GATEWAY_OR_PROXY_DRIFT")
    planned = set(state["prefixes"])
    external = [row for row in state["world"] if row["prefix"] not in planned]
    if sorted(map(canonical, external)) != sorted(map(canonical, state["baselineWorld"])):
        raise Blocked("UNRELATED_FOREIGN_WORLD_DRIFT")
    for entry in state["entries"]:
        matches = [r for r in state["world"] if r["prefix"] == entry["prefix"]]
        status = entry["status"]
        if status in ("PLANNED", "RESTORED"):
            if matches:
                raise Blocked("ROUTE_PRESENT_WHEN_EXPECTED_ABSENT")
        elif status == "VERIFIED":
            if len(matches) != 1 or not route_matches(matches[0], entry):
                raise Blocked("OWNED_ROUTE_MISSING_OR_MODIFIED")
        elif status in ("INTENT", "ROLLBACK_INTENT"):
            if len(matches) > 1 or (matches and not route_matches(matches[0], entry)):
                raise Blocked("INTENT_ROUTE_AMBIGUOUS_OR_FOREIGN")
        else:
            raise Blocked("UNKNOWN_ENTRY_STATUS")


def store_event(sandbox: Path, state: dict, kind: str, batch: int | None = None, **details: object) -> None:
    event(state, kind, batch, **details)
    write_state(sandbox, state)


def fault_if(where: str, args: argparse.Namespace, batch_index: int) -> None:
    if args.fault == where and args.fault_batch == batch_index:
        emit("INJECTED_CRASH", where)
        emit("INJECTED_BATCH", batch_index)
        os._exit(77)


def init(sandbox: Path, args: argparse.Namespace) -> None:
    if (sandbox / "state.json").exists():
        raise Blocked("RUN_ALREADY_EXISTS_NO_OVERWRITE")
    networks, sha = validate_dataset(Path(args.dataset).expanduser().resolve())
    if args.limit < 0 or args.limit > len(networks):
        raise Blocked("INVALID_PLAN_LIMIT")
    selected = networks[:args.limit] if args.limit else networks
    if not 1 <= args.batch_size <= MAX_BATCH:
        raise Blocked("BATCH_LIMIT_EXCEEDED")
    run_id = uuid.uuid4().hex
    entries = []
    for index, prefix in enumerate(selected):
        entries.append({"prefix": prefix, "status": "PLANNED", "route": {
            "prefix": prefix, "interfaceIndex": args.interface_index,
            "nextHop": args.gateway, "metric": args.metric, "store": "ActiveStore",
            "simOwnerToken": f"P1H_FIXTURE_ONLY_{run_id}_{index}"
        }})
    borrowed = []
    if args.borrowed_prefix:
        b = str(ipaddress.IPv4Network(args.borrowed_prefix, strict=True))
        if b in selected:
            raise Blocked("PREEXISTING_PREFIX_NOT_ADOPTABLE")
        borrowed = [{"prefix": b, "interfaceIndex": args.interface_index,
                     "nextHop": args.gateway, "metric": 101,
                     "store": "ActiveStore", "simOwnerToken": "THIRD_PARTY"}]
    env = {"gateway": args.gateway, "interfaceIndex": args.interface_index,
           "proxy": "127.0.0.1:7897", "wg": "OFF", "nrpt": "EXISTING_UNTOUCHED"}
    state = {"schema": SCHEMA, "runId": run_id, "mode": "MOCK_ONLY",
             "phase": "READY",
             "dataset": {"path": str(Path(args.dataset).resolve()), "sha256": sha,
                         "sourceCount": len(networks), "selectedCount": len(selected),
                         "batchSize": args.batch_size},
             "prefixes": selected, "planHash": digest(selected),
             "entries": entries, "world": list(borrowed),
             "baselineWorld": list(borrowed), "originalEnvironment": dict(env),
             "environment": dict(env), "audit": []}
    store_event(sandbox, state, "PLAN_FROZEN", sourceCount=len(networks), selected=len(selected),
                batches=len(batches(state)), sha256=sha)
    emit("MODE", "MOCK_ONLY")
    emit("RUN_ID", run_id)
    emit("FROZEN_SOURCE_COUNT", len(networks))
    emit("PLAN_PREFIXES", len(selected))
    emit("BATCHES", len(batches(state)))
    emit("RESULT", "MOCK_PLAN_READY")


def apply(sandbox: Path, state: dict, args: argparse.Namespace) -> None:
    if state["phase"] not in ("READY", "APPLYING", "APPLIED"):
        raise Blocked("APPLY_BLOCKED_BY_RUN_PHASE")
    check_source(state)
    verify_mock_world(state)
    if state["phase"] == "APPLIED":
        if any(e["status"] != "VERIFIED" for e in state["entries"]):
            raise Blocked("APPLIED_PHASE_HAS_UNVERIFIED_ENTRIES")
        emit("RESULT", "IDEMPOTENT_ALREADY_APPLIED")
        return
    for batch_index, entries in enumerate(batches(state), 1):
        if all(e["status"] == "VERIFIED" for e in entries):
            continue
        if not all(e["status"] == "PLANNED" for e in entries):
            raise Blocked("UNCLOSED_INTENT_REQUIRES_RECOVERY")
        state["phase"] = "APPLYING"
        for row in entries:
            row["status"] = "INTENT"
        store_event(sandbox, state, "BATCH_INTENT", batch_index, count=len(entries))
        fault_if("after_intent", args, batch_index)
        state["world"].extend(route_for(row) for row in entries)
        store_event(sandbox, state, "WORLD_BATCH_ADDED", batch_index, count=len(entries))
        fault_if("after_world", args, batch_index)
        for row in entries:
            row["status"] = "VERIFIED"
        store_event(sandbox, state, "BATCH_VERIFIED", batch_index, count=len(entries))
        fault_if("after_verified", args, batch_index)
    state["phase"] = "APPLIED"
    store_event(sandbox, state, "ALL_BATCHES_VERIFIED", verified=len(state["entries"]))
    emit("VERIFIED_ROUTES", len(state["entries"]))
    emit("RESULT", "MOCK_APPLY_VERIFIED_REQUIRES_ROLLBACK")


def recover(sandbox: Path, state: dict, args: argparse.Namespace) -> None:
    check_source(state)
    verify_mock_world(state)
    if state["phase"] == "RESTORED":
        if state["world"] != state["baselineWorld"]:
            raise Blocked("RESTORED_BUT_WORLD_DRIFT")
        emit("RESTORED_COUNT", len(state["entries"]))
        emit("RESULT", "IDEMPOTENT_ALREADY_RESTORED")
        return
    for batch_index in range(len(batches(state)), 0, -1):
        entries = batches(state)[batch_index - 1]
        if all(e["status"] in ("PLANNED", "RESTORED") for e in entries):
            continue
        if any(e["status"] not in ("INTENT", "VERIFIED", "ROLLBACK_INTENT")
               for e in entries):
            raise Blocked("MIXED_BATCH_STATUS_UNKNOWN")
        for row in entries:
            row["status"] = "ROLLBACK_INTENT"
        state["phase"] = "ROLLING_BACK"
        store_event(sandbox, state, "BATCH_ROLLBACK_INTENT", batch_index, count=len(entries))
        fault_if("after_remove_intent", args, batch_index)
        tokens = {row["route"]["simOwnerToken"] for row in entries}
        original_count = len(state["world"])
        state["world"] = [r for r in state["world"] if r["simOwnerToken"] not in tokens]
        removed_count = original_count - len(state["world"])
        store_event(sandbox, state, "WORLD_BATCH_REMOVED", batch_index, removed=removed_count)
        fault_if("after_remove_world", args, batch_index)
        for row in entries:
            row["status"] = "RESTORED"
        store_event(sandbox, state, "BATCH_ROLLBACK_VERIFIED", batch_index, count=len(entries))
    # Planned entries were never written; mark them restored for final uniformity.
    for row in state["entries"]:
        if row["status"] == "PLANNED":
            row["status"] = "RESTORED"
    if state["world"] != state["baselineWorld"]:
        raise Blocked("BASELINE_WORLD_NOT_RESTORED")
    state["phase"] = "RESTORED"
    store_event(sandbox, state, "BASELINE_RESTORED", restored=len(state["entries"]))
    emit("RESTORED_COUNT", len(state["entries"]))
    emit("BASELINE_EQUAL", "True")
    emit("RESULT", "MOCK_BATCH_ROLLBACK_VERIFIED")


def status(state: dict) -> None:
    check_source(state)
    verify_mock_world(state)
    counts = {}
    for row in state["entries"]:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    emit("RUN_ID", state["runId"])
    emit("MODE", state["mode"])
    emit("PHASE", state["phase"])
    emit("SOURCE_COUNT", state["dataset"]["sourceCount"])
    emit("PLAN_COUNT", len(state["entries"]))
    emit("BATCH_COUNT", len(batches(state)))
    emit("ENTRY_COUNTS", json.dumps(counts, sort_keys=True, separators=(",", ":")))
    emit("WORLD_ROUTE_COUNT", len(state["world"]))
    emit("BORROWED_ROUTE_COUNT", len(state["baselineWorld"]))
    emit("AUDIT_EVENTS", len(state["audit"]))
    emit("NETWORK_MUTATIONS", "NONE")
    emit("RESULT", "MOCK_LEDGER_INTEGRITY_PASS")


def inject(sandbox: Path, state: dict, args: argparse.Namespace) -> None:
    if state["phase"] == "RESTORED":
        raise Blocked("CANNOT_INJECT_AFTER_RESTORE")
    first = state["entries"][0]
    kind = args.kind
    if kind == "foreign_collision":
        state["world"].append({"prefix": first["prefix"], "interfaceIndex": 99,
                               "nextHop": "10.0.0.10", "metric": 25, "store": "ActiveStore",
                               "simOwnerToken": "FOREIGN_SAME_PREFIX"})
    elif kind == "persistent_collision":
        state["world"].append({"prefix": first["prefix"], "interfaceIndex": 9,
                               "nextHop": "192.168.0.1", "metric": 5, "store": "PersistentStore",
                               "simOwnerToken": "FOREIGN_PERSISTENT"})
    elif kind == "foreign_unrelated":
        state["world"].append({"prefix": "203.0.113.128/25", "interfaceIndex": 33,
                               "nextHop": "10.0.0.1", "metric": 20, "store": "ActiveStore",
                               "simOwnerToken": "FOREIGN_UNRELATED"})
    elif kind == "owned_identity_drift":
        found = next((r for r in state["world"] if r["prefix"] == first["prefix"] and
                      r["simOwnerToken"] == first["route"]["simOwnerToken"]), None)
        if found is None:
            raise Blocked("OWNED_ROUTE_NOT_YET_PRESENT")
        found["nextHop"] = "10.255.255.1"
    elif kind == "gateway_drift":
        state["environment"]["gateway"] = "10.255.255.1"
    elif kind == "audit_tamper":
        target = sandbox / "state.json"
        text = target.read_text(encoding="utf-8")
        target.write_text(text.replace('"mode":"MOCK_ONLY"', '"mode":"MOCK_TAMPER"', 1),
                          encoding="utf-8")
        emit("RESULT", "MOCK_AUDIT_TAMPER_INJECTED")
        return
    else:
        raise Blocked("UNKNOWN_INJECTION")
    store_event(sandbox, state, "INJECT_SYNTHETIC_EXTERNAL_CHANGE", injection=kind)
    emit("RESULT", "MOCK_EXTERNAL_CHANGE_INJECTED")


def main() -> int:
    parser = argparse.ArgumentParser(description="P1H offline route ledger — fixture only, no native network")
    parser.add_argument("--sandbox", required=True, help="p1h-fixture-* under P1HMock root")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("init")
    p.add_argument("--dataset", required=True)
    p.add_argument("--batch-size", type=int, default=4)
    p.add_argument("--limit", type=int, default=0, help="0=all; otherwise first N from frozen corpus")
    p.add_argument("--gateway", default="192.168.0.1")
    p.add_argument("--interface-index", type=int, default=9)
    p.add_argument("--metric", type=int, default=5)
    p.add_argument("--borrowed-prefix", default="203.0.113.0/24")
    for command in ("apply", "recover"):
        t = sub.add_parser(command)
        t.add_argument("--fault", default="", choices=("", "after_intent", "after_world",
            "after_verified", "after_remove_intent", "after_remove_world"))
        t.add_argument("--fault-batch", type=int, default=1)
    sub.add_parser("status")
    q = sub.add_parser("inject")
    q.add_argument("--kind", required=True, choices=("foreign_collision", "persistent_collision", "foreign_unrelated",
        "owned_identity_drift", "gateway_drift", "audit_tamper"))
    h = sub.add_parser("hold-lock")
    h.add_argument("--seconds", type=float, default=2.0)
    args = parser.parse_args()
    try:
        sandbox = sandbox_path(args.sandbox)
        if args.command == "status":
            status(read_state(sandbox))
        elif args.command == "hold-lock":
            with writer_lock(sandbox):
                emit("LOCK", "HELD")
                time.sleep(min(max(args.seconds, 0), 8))
                emit("RESULT", "MOCK_LOCK_RELEASED")
        else:
            with writer_lock(sandbox):
                if args.command == "init":
                    init(sandbox, args)
                elif args.command == "apply":
                    apply(sandbox, read_state(sandbox), args)
                elif args.command == "recover":
                    recover(sandbox, read_state(sandbox), args)
                elif args.command == "inject":
                    inject(sandbox, read_state(sandbox), args)
        return 0
    except Blocked as exc:
        emit("BLOCK_REASON", str(exc))
        emit("RESULT", "BLOCKED_FAIL_CLOSED")
        return 2
    except (OSError, ValueError, KeyError, TypeError) as exc:
        emit("BLOCK_REASON", type(exc).__name__)
        emit("RESULT", "BLOCKED_INCOMPLETE")
        return 4


if __name__ == "__main__":
    sys.exit(main())
