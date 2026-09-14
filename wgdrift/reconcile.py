"""Stage 5: safe reconciliation.

Turns mechanism findings into a plan of small, individually reversible
operations, applies them in a lockout-safe order, verifies with a fresh
snapshot, and rolls back if administrators lost access.

Ordering rules:
  1. routing first (forwarding on, routes present) - these only ADD paths
  2. WireGuard: policy peers are added/corrected BEFORE rogue peers are
     removed, so an admin whose IP was stolen gets it back in the same
     step that takes it from the thief
  3. nftables last, as one atomic table replacement

Verification: after applying, the loop re-collects and re-analyses. If the
admin peers cannot reach what the policy grants them (or handshakes are
blocked) and they could before, every executed op is undone in reverse.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_network

from . import nftables, nftgen, routing, wireguard
from .drift import Report, analyse
from .policy import Policy
from .snapshot import take


@dataclass
class Op:
    mechanism: str
    description: str
    argv: list[str]
    stdin: str | None = None
    rollback: list[tuple[list[str], str | None]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"mechanism": self.mechanism, "description": self.description,
                "command": " ".join(self.argv) + (" <<script" if self.stdin else "")}


@dataclass
class ApplyResult:
    executed: list[Op]
    failed: Op | None
    error: str | None
    rolled_back: bool
    before: Report
    after: Report | None

    @property
    def success(self) -> bool:
        return self.failed is None and not self.rolled_back

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "executed": [o.to_dict() for o in self.executed],
            "failed": self.failed.to_dict() if self.failed else None,
            "error": self.error,
            "rolled_back": self.rolled_back,
            "findings_before": len(self.before.findings),
            "findings_after": len(self.after.findings) if self.after else None,
            "admins_ok_after": self.after.admins_ok() if self.after else None,
        }


# --- planning -----------------------------------------------------------------

def plan(report: Report) -> list[Op]:
    policy, snap = report.policy, report.snapshot
    g, wgif = policy.gateway, policy.gateway.interface
    ops: list[Op] = []
    kinds = {f.kind for f in report.findings}

    # 1. routing
    if "ip_forward_off" in kinds:
        ops.append(Op("routing", "enable net.ipv4.ip_forward",
                      ["sysctl-write", str(routing.IP_FORWARD), "1\n"],
                      rollback=[(["sysctl-write", str(routing.IP_FORWARD), "0\n"], None)]))
    if "wg_link_down" in kinds:
        ops.append(Op("routing", f"bring {wgif} up", ["ip", "link", "set", wgif, "up"],
                      rollback=[(["ip", "link", "set", wgif, "down"], None)]))
    for f in report.findings:
        if f.kind == "tunnel_route_missing":
            ops.append(Op("routing", f"add route {f.details['dst']} dev {f.details['dev']}",
                          ["ip", "-4", "route", "add", f.details["dst"], "dev", f.details["dev"]],
                          rollback=[(["ip", "-4", "route", "del", f.details["dst"], "dev", f.details["dev"]], None)]))
        elif f.kind == "protected_route_missing" and f.fixable:
            ops.append(Op("routing", f"add route {f.details['dst']} dev {f.details['dev']}",
                          ["ip", "-4", "route", "add", f.details["dst"], "dev", f.details["dev"]],
                          rollback=[(["ip", "-4", "route", "del", f.details["dst"], "dev", f.details["dev"]], None)]))

    # 2. WireGuard: fix policy peers first, remove rogues last
    if snap.wg is not None:
        if "wg_listen_port" in kinds:
            ops.append(Op("wireguard", f"set listen-port {g.listen_port}",
                          ["wg", "set", wgif, "listen-port", str(g.listen_port)],
                          rollback=[(["wg", "set", wgif, "listen-port", str(snap.wg.listen_port)], None)]))
        for f in report.findings:
            if f.kind == "wg_peer_missing":
                ops.append(Op("wireguard", f"add peer {f.subject} allowed-ips {','.join(f.details['want'])}",
                              ["wg", "set", wgif, "peer", f.details["public_key"], "allowed-ips", ",".join(f.details["want"])],
                              rollback=[(["wg", "set", wgif, "peer", f.details["public_key"], "remove"], None)]))
            elif f.kind == "wg_allowed_ips":
                ops.append(Op("wireguard", f"set peer {f.subject} allowed-ips {','.join(f.details['want'])}",
                              ["wg", "set", wgif, "peer", f.details["public_key"], "allowed-ips", ",".join(f.details["want"])],
                              rollback=[(["wg", "set", wgif, "peer", f.details["public_key"], "allowed-ips",
                                          ",".join(f.details["live"]) or "0.0.0.0/32"], None)]))
        for f in report.findings:
            if f.kind == "wg_rogue_peer":
                restore = ["wg", "set", wgif, "peer", f.details["public_key"],
                           "allowed-ips", ",".join(f.details["allowed_ips"]) or "0.0.0.0/32"]
                if f.details.get("endpoint"):
                    restore += ["endpoint", f.details["endpoint"]]
                ops.append(Op("wireguard", f"remove rogue peer {f.subject[:16]}…",
                              ["wg", "set", wgif, "peer", f.details["public_key"], "remove"],
                              rollback=[(restore, None)]))

    # 3. nftables: replace the managed table atomically
    if kinds & {"nft_table_missing", "nft_chain_missing", "nft_rules_drift"}:
        managed = nftgen.build(policy)
        previous = nftables.list_table_text(nftgen.FAMILY, g.nft_table)
        if previous is None:
            rb = f"table {nftgen.FAMILY} {g.nft_table} {{}}\ndelete table {nftgen.FAMILY} {g.nft_table}\n"
        else:
            rb = f"table {nftgen.FAMILY} {g.nft_table} {{}}\ndelete table {nftgen.FAMILY} {g.nft_table}\n{previous}"
        ops.append(Op("nftables", f"replace table inet {g.nft_table} from policy",
                      ["nft", "-f", "-"], stdin=nftgen.render_replace_script(managed),
                      rollback=[(["nft", "-f", "-"], rb)]))
    return ops


# --- execution ------------------------------------------------------------------

def _exec(argv: list[str], stdin: str | None) -> None:
    if argv[0] == "sysctl-write":
        from pathlib import Path
        Path(argv[1]).write_text(argv[2])
    elif argv[0] == "ip":
        routing._ip(argv[1:])
    elif argv[0] == "wg":
        wireguard._wg(argv[1:])
    elif argv[0] == "nft":
        nftables._nft(argv[1:], stdin=stdin)
    else:
        raise RuntimeError(f"unknown executor {argv[0]}")


def apply(report: Report, ops: list[Op], *, dry_run: bool = False, log=None) -> ApplyResult:
    log = log or (lambda *_: None)
    policy: Policy = report.policy
    executed: list[Op] = []
    admins_before = report.admins_ok()

    if dry_run:
        for op in ops:
            log(f"would run: {op.description}")
        return ApplyResult([], None, None, False, report, None)

    def rollback(reason: str) -> None:
        log(f"ROLLBACK: {reason}")
        for op in reversed(executed):
            for argv, stdin in op.rollback:
                try:
                    _exec(argv, stdin)
                    log(f"  undid: {op.description}")
                except Exception as e:  # keep undoing the rest
                    log(f"  rollback of '{op.description}' failed: {e}")

    for op in ops:
        try:
            log(f"apply: {op.description}")
            _exec(op.argv, op.stdin)
            executed.append(op)
        except Exception as e:
            rollback(f"'{op.description}' failed: {e}")
            after = analyse(take(policy), policy)
            return ApplyResult(executed, op, str(e), True, report, after)

    after = analyse(take(policy), policy)
    if admins_before and not after.admins_ok():
        rollback("administrators lost access after reconciliation")
        after = analyse(take(policy), policy)
        return ApplyResult(executed, None, "admin lockout detected; changes reverted", True, report, after)
    return ApplyResult(executed, None, None, False, report, after)
