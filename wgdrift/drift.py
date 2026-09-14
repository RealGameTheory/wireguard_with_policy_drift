"""Stage 4: drift detection.

Two layers of findings:

  * mechanism findings - the CAUSE: something in WireGuard, routing or
    nftables differs from what the policy implies. These are what the
    reconciler fixes.
  * access findings    - the EFFECT: a (peer, target, service) that is
    reachable but should not be (fail-open) or unreachable but should be
    (fail-closed / lockout).

Severity is about consequence, not mechanism: any admin lockout and any
unauthorised access is critical.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_network

from . import nftgen
from .policy import Policy
from .reachability import Reach, compute, listen_port_open
from .snapshot import Snapshot

CRITICAL, HIGH, MEDIUM, INFO = "critical", "high", "medium", "info"
_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, INFO: 3}


@dataclass
class Finding:
    kind: str
    severity: str
    mechanism: str                 # wireguard routing nftables access
    subject: str
    message: str
    fixable: bool = True
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return self.__dict__


@dataclass
class Report:
    snapshot: Snapshot
    policy: Policy
    reaches: list[Reach]
    findings: list[Finding]

    @property
    def clean(self) -> bool:
        return not self.findings

    @property
    def worst(self) -> str | None:
        return min((f.severity for f in self.findings), key=_ORDER.get, default=None)

    def by_mechanism(self, mech: str) -> list[Finding]:
        return [f for f in self.findings if f.mechanism == mech]

    def admins_ok(self) -> bool:
        """Every intended admin flow is reachable and handshakes can arrive."""
        for r in self.reaches:
            p = self.policy.peer_by_name(r.name) if r.name else None
            if p and self.policy.is_admin(p) and r.src == p.tunnel_ip:
                if self.policy.allowed(p, r.target, r.service) and not r.reachable:
                    return False
        return listen_port_open(self.snapshot, self.policy).ok

    def to_dict(self) -> dict:
        return {
            "taken_at": self.snapshot.taken_at,
            "clean": self.clean,
            "worst": self.worst,
            "admins_ok": self.admins_ok(),
            "findings": [f.to_dict() for f in self.findings],
            "reachability": [r.to_dict() for r in self.reaches],
            "snapshot_errors": self.snapshot.errors,
        }


def _wireguard(snap: Snapshot, policy: Policy) -> list[Finding]:
    g, out = policy.gateway, []
    if snap.wg is None:
        out.append(Finding("wg_interface_missing", CRITICAL, "wireguard", g.interface,
                           f"WireGuard interface {g.interface} does not exist; every peer is locked out",
                           fixable=False))
        return out
    if snap.wg.listen_port != g.listen_port:
        out.append(Finding("wg_listen_port", HIGH, "wireguard", g.interface,
                           f"listen port is {snap.wg.listen_port}, policy says {g.listen_port}",
                           details={"live": snap.wg.listen_port, "want": g.listen_port}))
    if g.public_key and snap.wg.public_key != g.public_key:
        out.append(Finding("wg_gateway_key", CRITICAL, "wireguard", g.interface,
                           "gateway private key differs from the one the policy expects; clients will "
                           "fail to handshake", fixable=False))
    live = {p.public_key: p for p in snap.wg.peers}
    for pp in policy.peers:
        lp = live.get(pp.public_key)
        admin = policy.is_admin(pp)
        if lp is None:
            out.append(Finding("wg_peer_missing", CRITICAL if admin else HIGH, "wireguard", pp.name,
                               f"peer {pp.name} is in the policy but not on {g.interface}"
                               + (" (ADMIN LOCKOUT)" if admin else ""),
                               details={"public_key": pp.public_key, "want": [str(n) for n in pp.allowed_ips]}))
            continue
        want = set(pp.allowed_ips)
        have = set(n for n in lp.allowed_ips if n.version == 4)
        if have != want:
            extra, missing = have - want, want - have
            sev = CRITICAL if extra or admin else HIGH
            msg = f"peer {pp.name} allowed-ips are {sorted(map(str, have)) or '[]'}, policy says {sorted(map(str, want))}"
            if extra:
                msg += "; the extra prefixes let this key impersonate other addresses"
            out.append(Finding("wg_allowed_ips", sev, "wireguard", pp.name, msg,
                               details={"public_key": pp.public_key, "live": sorted(map(str, have)),
                                        "want": sorted(map(str, want))}))
        owner = snap.wg.owner_of(pp.tunnel_ip)
        if owner is not None and owner is not lp:
            thief = policy.peer_by_key(owner.public_key)
            out.append(Finding("wg_ip_stolen", CRITICAL, "wireguard", pp.name,
                               f"{pp.name}'s address {pp.tunnel_ip} is bound to "
                               f"{thief.name if thief else 'unknown key ' + owner.public_key[:12] + '…'}",
                               details={"victim": pp.name, "holder": owner.public_key}))
    for key, lp in live.items():
        if policy.peer_by_key(key) is None:
            out.append(Finding("wg_rogue_peer", CRITICAL, "wireguard", key,
                               f"unknown key {key[:16]}… is configured on {g.interface} with allowed-ips "
                               f"{[str(n) for n in lp.allowed_ips]}",
                               details={"public_key": key, "allowed_ips": [str(n) for n in lp.allowed_ips],
                                        "endpoint": lp.endpoint, "latest_handshake": lp.latest_handshake}))
    return out


def _routing(snap: Snapshot, policy: Policy) -> list[Finding]:
    g, rt, out = policy.gateway, snap.routing, []
    if not rt.ip_forward:
        out.append(Finding("ip_forward_off", CRITICAL, "routing", "net.ipv4.ip_forward",
                           "IP forwarding is disabled; nothing is forwarded for anyone (total lockout)"))
    link = rt.link(g.interface)
    if link is not None and not link.up:
        out.append(Finding("wg_link_down", CRITICAL, "routing", g.interface,
                           f"{g.interface} exists but is administratively down", fixable=True))
    r = rt.lookup(g.tunnel_network.network_address + 1)
    if link is not None and (r is None or r.dev != g.interface or not g.tunnel_network.subnet_of(r.dst)):
        out.append(Finding("tunnel_route_missing", CRITICAL, "routing", str(g.tunnel_network),
                           f"no route for {g.tunnel_network} via {g.interface} (have: {r or 'none'}); "
                           "return traffic to peers cannot be delivered",
                           details={"dst": str(g.tunnel_network), "dev": g.interface}))
    for net in g.protected_networks:
        r = rt.lookup(net.network_address + 1)
        if r is None or r.dev is None:
            out.append(Finding("protected_route_missing", HIGH, "routing", str(net),
                               f"no route to protected network {net}",
                               fixable=rt.interface_for(net) is not None,
                               details={"dst": str(net), "dev": getattr(rt.interface_for(net), "name", None)}))
        elif r.dev == g.interface:
            out.append(Finding("protected_route_via_tunnel", CRITICAL, "routing", str(net),
                               f"route to {net} goes through {g.interface} ({r}); traffic loops into the tunnel",
                               fixable=False))
    if rt.nonstandard_rules():
        out.append(Finding("policy_routing_rules", MEDIUM, "routing", "ip rule",
                           f"{len(rt.nonstandard_rules())} non-standard policy routing rule(s) present; "
                           "reachability is computed on the main table only", fixable=False,
                           details={"rules": rt.nonstandard_rules()}))
    return out


def _nftables(snap: Snapshot, policy: Policy) -> list[Finding]:
    g, out = policy.gateway, []
    managed = nftgen.build(policy)
    if not snap.nft.has_table(nftgen.FAMILY, g.nft_table):
        out.append(Finding("nft_table_missing", CRITICAL, "nftables", f"inet {g.nft_table}",
                           f"managed table inet {g.nft_table} does not exist; the forward path is unfiltered"))
        return out
    for d in nftgen.diff(managed, snap.nft):
        if d.clean:
            continue
        if d.policy_live is None:
            out.append(Finding("nft_chain_missing", CRITICAL, "nftables", f"{g.nft_table} {d.chain}",
                               f"chain {d.chain} is missing from table inet {g.nft_table}"))
            continue
        parts = []
        if d.policy_live != d.policy_want:
            parts.append(f"policy is {d.policy_live}, want {d.policy_want}")
        if not d.hook_ok:
            parts.append("hook/type differ")
        if d.missing:
            parts.append(f"{len(d.missing)} intended rule(s) missing: " + "; ".join(r.text() for r in d.missing))
        if d.extra:
            parts.append(f"{len(d.extra)} unexpected rule(s): " + "; ".join(r.text() for r in d.extra))
        sev = CRITICAL if (d.extra or d.policy_live != d.policy_want) and d.chain == "forward" else HIGH
        out.append(Finding("nft_rules_drift", sev, "nftables", f"{g.nft_table} {d.chain}",
                           f"chain {d.chain}: " + "; ".join(parts),
                           details={"missing": [r.text() for r in d.missing], "extra": [r.text() for r in d.extra],
                                    "policy_live": d.policy_live, "policy_want": d.policy_want}))
    foreign = [c for c in snap.nft.base_chains("forward") if c.table != g.nft_table]
    if foreign:
        out.append(Finding("nft_foreign_forward_chains", INFO, "nftables", "forward hook",
                           "other forward-hook chains exist: " + ", ".join(f"{c.family} {c.table} {c.name}" for c in foreign)
                           + "; they are included in reachability but not managed", fixable=False))
    return out


def _access(reaches: list[Reach], policy: Policy, snap: Snapshot) -> list[Finding]:
    out = []
    for r in reaches:
        pp = policy.peer_by_key(r.key)
        if pp is None:
            if r.reachable:
                out.append(Finding("unauthorized_access", CRITICAL, "access", r.key[:16] + "…",
                                   f"unknown key can reach {r.target.name} {r.service} from {r.src}",
                                   details=r.to_dict()))
            continue
        allowed = policy.allowed(pp, r.target, r.service)
        if r.src != pp.tunnel_ip:
            # a source the policy never gave this peer
            if r.reachable:
                victim = policy.peer_for_ip(r.src)
                out.append(Finding("unauthorized_access", CRITICAL, "access", pp.name,
                                   f"{pp.name} can reach {r.target.name} {r.service} using address {r.src}"
                                   + (f" (which belongs to {victim.name})" if victim else ""),
                                   details=r.to_dict()))
            continue
        if r.reachable and not allowed:
            out.append(Finding("unauthorized_access", CRITICAL, "access", pp.name,
                               f"{pp.name} ({pp.role}) can reach {r.target.name} {r.service} but policy forbids it",
                               details=r.to_dict()))
        elif allowed and not r.reachable:
            admin = policy.is_admin(pp)
            out.append(Finding("missing_access", CRITICAL if admin else HIGH, "access", pp.name,
                               f"{pp.name} ({pp.role}) cannot reach {r.target.name} {r.service}: blocked by "
                               f"{r.blocked_by()} ({getattr(r, r.blocked_by()).detail})"
                               + (" (ADMIN LOCKOUT)" if admin else ""),
                               details=r.to_dict()))
    if not listen_port_open(snap, policy).ok:
        out.append(Finding("listen_port_blocked", CRITICAL, "access", f"udp/{policy.gateway.listen_port}",
                           f"nftables input hook drops UDP {policy.gateway.listen_port}; no peer can handshake",
                           details={"decision": listen_port_open(snap, policy).detail}))
    warned = sorted({w for r in reaches for w in r.warnings})
    if warned:
        out.append(Finding("nft_uncertain", MEDIUM, "nftables", "evaluator",
                           "some rules could not be evaluated: " + " | ".join(warned[:5]), fixable=False,
                           details={"warnings": warned}))
    return out


def analyse(snap: Snapshot, policy: Policy) -> Report:
    reaches = compute(snap, policy)
    findings = _wireguard(snap, policy) + _routing(snap, policy) + _nftables(snap, policy) \
        + _access(reaches, policy, snap)
    for e in snap.errors:
        findings.append(Finding("collector_error", HIGH, "collector", "snapshot", e, fixable=False))
    findings.sort(key=lambda f: (_ORDER[f.severity], f.mechanism, f.subject))
    return Report(snap, policy, reaches, findings)
