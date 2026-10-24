#!/usr/bin/env python3
"""Stage C P1: PURE IN-MEMORY transaction model. NO Windows native mutators.

This module has no subprocess, PowerShell, socket, registry, OS routing, or
WireGuard APIs. It models future Stage C design and deliberately cannot apply
routes or change network state on the user's computer.

A Windows route has no reliable script-created ownership tag. The model uses
a run-scoped ledger and strict identity checks, and marks ambiguity as
INCOMPLETE rather than deleting unknown routes.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from copy import deepcopy
import hashlib
import ipaddress
import json
from typing import Iterable

SCHEMA = "stage-c-p1-sim-v1"
CN_DNS = "223.5.5.5"
XRAY_PROXY = "127.0.0.1:7897"
NO_NATIVE_MUTATORS = True


@dataclass(frozen=True, order=True)
class Route:
    prefix: str
    if_index: int
    gateway: str
    metric: int = 5
    store: str = "ActiveStore"

    def identity(self) -> tuple[str, int, str, int, str]:
        return (self.prefix, self.if_index, self.gateway,
                self.metric, self.store)


@dataclass(frozen=True)
class NrptRule:
    rule_id: str
    namespaces: tuple[str, ...]
    servers: tuple[str, ...]


@dataclass
class World:
    routes: list[Route]
    nrpt: list[NrptRule]
    physical_index: int = 13
    physical_gateway: str = "192.0.2.1"
    proxy_enabled: int = 1
    proxy_server: str = XRAY_PROXY
    xray_running: bool = True
    xray_tun: bool = False
    wg_active: bool = False
    wg_half_routes: bool = False
    timer_armed: bool = False

    def nrpt_digest(self) -> str:
        return sha256_json([
            {"id": x.rule_id,
             "ns": sorted(x.namespaces, key=str.casefold),
             "servers": list(x.servers)}
            for x in sorted(self.nrpt, key=lambda r: r.rule_id)
        ])

    def fingerprint(self) -> str:
        return sha256_json({
            "routes": sorted([r.identity() for r in self.routes]),
            "nrpt_digest": self.nrpt_digest(),
            "physical_index": self.physical_index,
            "physical_gateway": self.physical_gateway,
            "proxy_enabled": self.proxy_enabled,
            "proxy_server": self.proxy_server,
            "xray_running": self.xray_running,
            "xray_tun": self.xray_tun,
            "wg_active": self.wg_active,
            "wg_half_routes": self.wg_half_routes,
            "timer_armed": self.timer_armed,
        })


@dataclass(frozen=True)
class Plan:
    snapshot_hash: str
    nrpt_hash: str
    targets: tuple[str, ...]
    add: tuple[Route, ...]
    borrowed: tuple[Route, ...]
    blockers: tuple[str, ...]
    full_dataset: bool

    def metadata(self) -> dict:
        return {
            "schema": SCHEMA,
            "mode": "SIMULATION_PLAN_ONLY",
            "native_mutators": False,
            "snapshot_sha256": self.snapshot_hash,
            "nrpt_sha256": self.nrpt_hash,
            "target_count": len(self.targets),
            "routes_to_add": len(self.add),
            "preexisting_physical_routes_to_keep": len(self.borrowed),
            "blockers": list(self.blockers),
            "full_dataset": self.full_dataset,
            "live_approved": False,
        }


@dataclass
class Journal:
    run_id: str
    initial_sha256: str
    nrpt_sha256: str
    owned: list[Route] = field(default_factory=list)
    wg_created: bool = False
    proxy_changed: bool = False
    armed: bool = False
    events: list[str] = field(default_factory=list)


@dataclass
class Outcome:
    status: str
    state: World
    journal: Journal
    success_marker: bool
    baseline_restored: bool
    reasons: list[str]

    def summary(self) -> dict:
        return {
            "status": self.status,
            "success_marker": self.success_marker,
            "baseline_restored": self.baseline_restored,
            "owned_route_count": len(self.journal.owned),
            "events": self.journal.events,
            "reasons": self.reasons,
            "final_fingerprint": self.state.fingerprint(),
        }


def sha256_json(x: object) -> str:
    raw = json.dumps(x, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def canonical_cidrs(lines: Iterable[str]) -> tuple[str, ...]:
    """Reject malformed/non-canonical/duplicate/overlapping IPv4 entries."""
    result: list[ipaddress.IPv4Network] = []
    for raw in lines:
        value = raw.strip()
        if not value:
            continue
        net = ipaddress.ip_network(value, strict=True)
        if not isinstance(net, ipaddress.IPv4Network):
            raise ValueError("NON_IPV4_CIDR")
        result.append(net)
    if not result:
        raise ValueError("EMPTY_CIDR_DATASET")
    if len(set(result)) != len(result):
        raise ValueError("DUPLICATE_CIDR")
    ordered = sorted(result, key=lambda n: (int(n.network_address), n.prefixlen))
    highest_end = -1
    for n in ordered:
        begin = int(n.network_address)
        end = int(n.broadcast_address)
        if begin <= highest_end:
            raise ValueError("OVERLAPPING_CIDR")
        highest_end = end
    return tuple(str(n) for n in ordered)


def canonical_namespaces(lines: Iterable[str]) -> tuple[str, ...]:
    # Apex and dot-prefixed suffix are DIFFERENT Windows NRPT entries.
    values: list[str] = []
    for raw in lines:
        s = raw.strip().lower()
        if not s:
            continue
        if any(c.isspace() for c in s) or "/" in s or "\\" in s:
            raise ValueError("INVALID_NRPT_NAMESPACE")
        if s.startswith("..") or s in {".", ""}:
            raise ValueError("INVALID_NRPT_NAMESPACE")
        values.append(s)
    if not values:
        raise ValueError("EMPTY_NRPT_DATASET")
    if len(set(values)) != len(values):
        raise ValueError("DUPLICATE_NRPT_NAMESPACE")
    return tuple(sorted(values))


def validate_nrpt(rules: list[NrptRule], expected: tuple[str, ...]) -> list[str]:
    problems: list[str] = []
    ids: set[str] = set()
    all_ns: set[str] = set()
    duplicates = 0
    for rule in rules:
        if not rule.rule_id or rule.rule_id in ids:
            problems.append("DUPLICATE_OR_BLANK_RULE_ID")
        ids.add(rule.rule_id)
        if len(rule.servers) != 1 or rule.servers[0] != CN_DNS:
            problems.append("WRONG_NRPT_NAMESERVER")
        if not rule.namespaces:
            problems.append("EMPTY_RULE_NAMESPACE")
        for ns in rule.namespaces:
            key = ns.strip().lower()
            if key in all_ns:
                duplicates += 1
            all_ns.add(key)
    target = set(expected)
    if all_ns != target:
        problems.append(f"NRPT_SET_DIFF_MISSING_{len(target-all_ns)}"
                        f"_EXTRA_{len(all_ns-target)}")
    if duplicates:
        problems.append(f"NRPT_DUPLICATE_ROWS_{duplicates}")
    return sorted(set(problems))


def create_plan(world: World, prefixes: Iterable[str],
                namespaces: Iterable[str],
                *, full_dataset: bool = False) -> Plan:
    targets = canonical_cidrs(prefixes)
    nss = canonical_namespaces(namespaces)
    blockers: list[str] = validate_nrpt(world.nrpt, nss)
    if world.xray_tun:
        blockers.append("XRAY_TUN_CONFLICT")
    if not world.xray_running:
        blockers.append("XRAY_PROCESS_NOT_RUNNING")
    if world.proxy_enabled not in (0, 1):
        blockers.append("PROXY_STATE_UNKNOWN")
    if world.proxy_enabled == 1 and world.proxy_server != XRAY_PROXY:
        blockers.append("UNEXPECTED_PROXY_SERVER")
    if world.physical_index <= 0 or not world.physical_gateway:
        blockers.append("PHYSICAL_GATEWAY_MISSING")
    if world.timer_armed:
        blockers.append("ANOTHER_TIMER_ARMED")
    if world.wg_active or world.wg_half_routes:
        # This gate models the *whole* XRAY_ONLY -> SMART_ON -> XRAY_ONLY
        # life cycle. Attaching to an existing WG tunnel is a future mode.
        blockers.append("WG_PRESTATE_NOT_OFF")
    add: list[Route] = []
    borrowed: list[Route] = []
    for p in targets:
        same_prefix = [r for r in world.routes if r.prefix == p]
        intended = [r for r in same_prefix
                    if r.if_index == world.physical_index
                    and r.gateway == world.physical_gateway]
        competing = [r for r in same_prefix if r not in intended]
        if competing:
            blockers.append("CONFLICTING_ROUTE_" + p)
        if intended:
            # Pre-existing means NOT owned by this run. Never plan deletion.
            borrowed.extend(intended)
        elif not competing:
            add.append(Route(p, world.physical_index,
                             world.physical_gateway))
    return Plan(
        snapshot_hash=world.fingerprint(), nrpt_hash=world.nrpt_digest(),
        targets=targets, add=tuple(add), borrowed=tuple(borrowed),
        blockers=tuple(sorted(set(blockers))), full_dataset=full_dataset,
    )


def route_for_ip(world: World, ip: str) -> str:
    target = ipaddress.ip_address(ip)
    if not isinstance(target, ipaddress.IPv4Address):
        raise ValueError("IPV4_ONLY_MODEL")
    candidates: list[tuple[int, int, str]] = []
    for r in world.routes:
        if target in ipaddress.ip_network(r.prefix, strict=True):
            destination = ("PHYSICAL" if r.if_index == world.physical_index
                           and r.gateway == world.physical_gateway
                           else "OTHER")
            candidates.append((ipaddress.ip_network(r.prefix).prefixlen,
                               -r.metric, destination))
    if world.wg_active and world.wg_half_routes:
        candidates.append((1, -5, "WIREGUARD"))
    candidates.append((0, -100, "PHYSICAL"))
    return max(candidates)[2]


def _remove_owned(world: World, journal: Journal, reasons: list[str]) -> None:
    """Never delete based on CIDR alone. Validate exact key and ambiguity."""
    for route in reversed(journal.owned):
        exact = [r for r in world.routes if r.identity() == route.identity()]
        same_prefix = [r for r in world.routes if r.prefix == route.prefix]
        if len(exact) != 1 or len(same_prefix) != 1:
            reasons.append("OWNED_ROUTE_AMBIGUOUS_" + route.prefix)
            continue
        world.routes.remove(exact[0])


def simulate(world: World, plan: Plan, *,
             run_id: str = "SIM-001",
             failure_at_route: int | None = None,
             fail_proxy_disable: bool = False,
             fail_proxy_restore: bool = False,
             external_nrpt_change_at: int | None = None,
             gateway_change_at: int | None = None,
             route_conflict_at: int | None = None,
             watchdog_timeout_at: int | None = None) -> Outcome:
    """Pure mock. ALWAYS attempts rollback; never executes Windows commands."""
    state = deepcopy(world)
    journal = Journal(run_id, world.fingerprint(), world.nrpt_digest())
    reasons: list[str] = []
    if plan.blockers:
        return Outcome("BLOCKED", state, journal, False, True,
                       list(plan.blockers))
    if state.fingerprint() != plan.snapshot_hash:
        return Outcome("BLOCKED_STALE_SNAPSHOT", state, journal, False,
                       False, ["BASELINE_FINGERPRINT_CHANGED"])
    if state.nrpt_digest() != plan.nrpt_hash:
        return Outcome("BLOCKED_NRPT_DRIFT", state, journal, False,
                       False, ["NRPT_CHANGED"])
    completed = False
    timer_fired = False
    try:
        state.timer_armed = True
        journal.armed = True
        journal.events.append("TIMER_ARMED")
        state.wg_active = True
        state.wg_half_routes = True
        journal.wg_created = True
        journal.events.append("TARGET_WG_SIMULATED_ON")
        if fail_proxy_disable:
            raise RuntimeError("PROXY_DISABLE_FAILED")
        if state.proxy_enabled == 1:
            state.proxy_enabled = 0
            journal.proxy_changed = True
            journal.events.append("PROXY_TEMPORARILY_DISABLED")
        for index, r in enumerate(plan.add, 1):
            if failure_at_route == index:
                raise RuntimeError(f"ROUTE_APPLY_FAILED_AT_{index}")
            if gateway_change_at == index:
                state.physical_gateway = "192.168.200.1"
                raise RuntimeError("GATEWAY_DRIFT")
            if any(x.prefix == r.prefix for x in state.routes):
                raise RuntimeError("ROUTE_COLLISION_BEFORE_WRITE")
            state.routes.append(r)
            journal.owned.append(r)
            if route_conflict_at == index:
                state.routes.append(replace(r, metric=r.metric + 1))
                raise RuntimeError("EXTERNAL_ROUTE_COLLISION")
            if external_nrpt_change_at == index:
                state.nrpt[0] = replace(state.nrpt[0],
                                        servers=("8.8.8.8",))
                raise RuntimeError("NRPT_EXTERNAL_DRIFT")
            if watchdog_timeout_at == index:
                timer_fired = True
                journal.events.append("INDEPENDENT_TIMER_SIMULATED_FIRE")
                raise TimeoutError("WATCHDOG_TIMEOUT")
        if state.nrpt_digest() != plan.nrpt_hash:
            raise RuntimeError("NRPT_CHANGED_AFTER_APPLY")
        if world.proxy_enabled == 1 and state.proxy_enabled != 0:
            raise RuntimeError("PROXY_NOT_DISABLED")
        if len(journal.owned) != len(plan.add):
            raise RuntimeError("MISSING_LEDGER_ROWS")
        # Prove model routing decisions, not merely existence of route rows.
        if route_for_ip(state, "8.8.8.8") != "WIREGUARD":
            raise RuntimeError("FOREIGN_ROUTE_NOT_WIREGUARD")
        journal.events.append("MODEL_FOREIGN_IPV4_VIA_WG")
        cn_probe = ipaddress.ip_address("223.5.5.5")
        if any(cn_probe in ipaddress.ip_network(p) for p in plan.targets):
            if route_for_ip(state, "223.5.5.5") != "PHYSICAL":
                raise RuntimeError("CN_ROUTE_NOT_PHYSICAL")
            journal.events.append("MODEL_CN_IPV4_VIA_PHYSICAL")
        journal.events.append("SMART_SIMULATED_COMMIT")
        completed = True
    except (RuntimeError, TimeoutError) as exc:
        reasons.append(str(exc))
        journal.events.append("SIMULATED_FAILURE")
    finally:
        _remove_owned(state, journal, reasons)
        if journal.wg_created:
            state.wg_active = False
            state.wg_half_routes = False
            journal.events.append("TARGET_WG_SIMULATED_OFF")
        if journal.proxy_changed:
            if fail_proxy_restore:
                reasons.append("PROXY_RESTORE_FAILED")
            elif state.proxy_enabled == 0 and state.proxy_server == world.proxy_server:
                state.proxy_enabled = world.proxy_enabled
                journal.events.append("PROXY_ORIGINAL_RESTORED")
            else:
                reasons.append("PROXY_EXTERNAL_DRIFT_NOT_OVERWRITTEN")
        if journal.armed:
            state.timer_armed = False
            journal.events.append("TIMER_DISARMED")
        if state.nrpt_digest() != journal.nrpt_sha256:
            reasons.append("NRPT_DRIFT_NOT_OVERWRITTEN")
    restored = (state.fingerprint() == journal.initial_sha256)
    if not restored:
        reasons.append("BASELINE_NOT_FULLY_RESTORED")
    if not restored:
        status = "ROLLBACK_INCOMPLETE"
    elif timer_fired:
        status = "TIMEOUT_ROLLED_BACK"
    elif completed:
        status = "PASS_MOCK_ONLY"
    else:
        status = "FAILED_ROLLED_BACK"
    journal.events.append("VERIFY_BASELINE_" + ("PASS" if restored else "FAIL"))
    # A failure never yields success even if rollback was completely successful.
    return Outcome(status, state, journal, completed and restored, restored,
                   sorted(set(reasons)))


def fixture_world(prefixes: list[str], namespaces: tuple[str, ...],
                  *, preexisting: list[Route] | None = None) -> World:
    rules = [
        NrptRule("GCP-WG-SMART-FULLCN-001", namespaces, (CN_DNS,))
    ]
    return World(routes=list(preexisting or []), nrpt=rules)


def load_dataset(repo: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    from pathlib import Path
    base = Path(repo) / "data"
    cidrs = canonical_cidrs(
        (base / "cn-ipv4-cidrs.txt").read_text(encoding="utf-8-sig").splitlines())
    namespaces = canonical_namespaces(
        (base / "cn-nrpt-namespaces.txt").read_text(encoding="utf-8-sig").splitlines())
    return cidrs, namespaces


def snapshot_plan(repo: str) -> dict:
    """Static full-dataset assessment, simulated xray-only baseline."""
    cidrs, ns = load_dataset(repo)
    chunks = [ns[i:i+500] for i in range(0, len(ns), 500)]
    state = World(
        routes=[],
        nrpt=[NrptRule(f"GCP-WG-SMART-FULLCN-{i:03d}", c, (CN_DNS,))
              for i, c in enumerate(chunks, 1)]
    )
    plan = create_plan(state, cidrs, ns, full_dataset=True)
    result = plan.metadata()
    result["nrpt_rule_count"] = len(state.nrpt)
    result["route_samples"] = list(plan.targets[:3])
    return result


if __name__ == "__main__":
    import argparse
    from pathlib import Path
    parser = argparse.ArgumentParser(
        description="Only offline planning; never mutates Windows network state")
    parser.add_argument("--repo", default=str(Path(__file__).resolve().parent.parent))
    args = parser.parse_args()
    print(json.dumps(snapshot_plan(args.repo), indent=2, sort_keys=True))
