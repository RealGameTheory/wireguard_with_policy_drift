"""Stage 2: effective reachability.

For every (peer, source IP, target, service) the gateway could see, decide
whether a NEW connection would actually get through, by asking each
mechanism in the order the kernel does:

  1. WireGuard  - does the kernel accept `src` from this key? (AllowedIPs,
                  longest prefix across all peers, so a stolen IP shows up
                  as belonging to the thief)
  2. Routing    - is forwarding on, is there a route to the target that
                  leaves on a non-tunnel interface, and a return route to
                  `src` via the tunnel?
  3. nftables   - what verdict do the forward-hook base chains give?

Nothing here is simulated: the inputs are the live snapshot and the only
computation is the same lookup logic the kernel applies.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network

from .models import WGPeer
from .nftables import Packet, evaluate
from .policy import Peer, Policy, Service, Target
from .snapshot import Snapshot


@dataclass(frozen=True)
class Stage:
    ok: bool
    detail: str


@dataclass
class Reach:
    key: str                          # WireGuard public key (or policy key if absent from kernel)
    name: str | None                  # policy peer name, None for unknown keys
    src: IPv4Address
    target: Target
    service: Service
    wireguard: Stage
    routing: Stage
    nftables: Stage
    warnings: list[str] = field(default_factory=list)

    @property
    def reachable(self) -> bool:
        return self.wireguard.ok and self.routing.ok and self.nftables.ok

    @property
    def uncertain(self) -> bool:
        return bool(self.warnings)

    def blocked_by(self) -> str | None:
        for name, st in (("wireguard", self.wireguard), ("routing", self.routing), ("nftables", self.nftables)):
            if not st.ok:
                return name
        return None

    def to_dict(self) -> dict:
        return {
            "peer": self.name or self.key, "key": self.key, "src": str(self.src),
            "target": self.target.name, "dst": str(self.target.address), "service": str(self.service),
            "reachable": self.reachable, "blocked_by": self.blocked_by(),
            "stages": {"wireguard": self.wireguard.__dict__, "routing": self.routing.__dict__,
                       "nftables": self.nftables.__dict__},
            "warnings": self.warnings,
        }


def _first_host(net: IPv4Network) -> IPv4Address:
    return net.network_address if net.prefixlen >= 31 else net.network_address + 1


def candidate_sources(snap: Snapshot, policy: Policy) -> list[tuple[str, str | None, IPv4Address, str]]:
    """(key, name, src, why) for every source address the gateway would
    attribute to some key, plus policy peers the kernel does not know."""
    out: list[tuple[str, str | None, IPv4Address, str]] = []
    seen: set[tuple[str, IPv4Address]] = set()

    def add(key: str, name: str | None, src: IPv4Address, why: str) -> None:
        if (key, src) not in seen:
            seen.add((key, src))
            out.append((key, name, src, why))

    live_peers: tuple[WGPeer, ...] = snap.wg.peers if snap.wg else ()
    for lp in live_peers:
        name = (policy.peer_by_key(lp.public_key) or Peer("", "", IPv4Address("0.0.0.0"), "")).name or None
        # every policy tunnel IP this key would be accepted for (covers stolen IPs)
        for pp in policy.peers:
            if snap.wg and snap.wg.owner_of(pp.tunnel_ip) is lp:
                add(lp.public_key, name, pp.tunnel_ip, f"kernel binds {pp.tunnel_ip} ({pp.name}'s address) to this key")
        # plus a representative of each AllowedIPs entry (covers widened prefixes)
        for net in lp.allowed_ips:
            if net.version == 4:
                add(lp.public_key, name, _first_host(net), f"allowed-ips {net}")
    # every policy peer is always evaluated from its own address, so a peer
    # that is missing, unbound or whose address was taken shows up as
    # missing_access rather than silently disappearing from the matrix
    for pp in policy.peers:
        add(pp.public_key, pp.name, pp.tunnel_ip, "policy address")
    return out


def _wg_stage(snap: Snapshot, policy: Policy, key: str, src: IPv4Address) -> Stage:
    if snap.wg is None:
        return Stage(False, f"interface {policy.gateway.interface} does not exist")
    peer = snap.wg.peer(key)
    if peer is None:
        return Stage(False, "key not configured on the interface")
    owner = snap.wg.owner_of(src)
    if owner is None:
        return Stage(False, f"{src} is in no peer's allowed-ips")
    if owner is not peer:
        who = policy.peer_by_key(owner.public_key)
        return Stage(False, f"{src} is bound to {(who.name if who else owner.public_key[:12] + '…')}, not this key")
    return Stage(True, f"{src} bound to this key")


def _routing_stage(snap: Snapshot, policy: Policy, src: IPv4Address, dst: IPv4Address) -> tuple[Stage, str | None]:
    rt, wgif = snap.routing, policy.gateway.interface
    link = rt.link(wgif)
    if link is None or not link.up:
        return Stage(False, f"{wgif} is down or missing"), None
    if not rt.ip_forward:
        return Stage(False, "net.ipv4.ip_forward = 0"), None
    fwd = rt.lookup(dst)
    if fwd is None or fwd.dev is None:
        return Stage(False, f"no route to {dst}"), None
    if fwd.dev == wgif:
        return Stage(False, f"route to {dst} points back into {wgif} ({fwd})"), fwd.dev
    out_link = rt.link(fwd.dev)
    if out_link is None or not out_link.up:
        return Stage(False, f"egress interface {fwd.dev} is down"), fwd.dev
    back = rt.lookup(src)
    if back is None or back.dev != wgif:
        return Stage(False, f"return route to {src} is {back or 'missing'}, not via {wgif}"), fwd.dev
    return Stage(True, f"{dst} via {fwd.dev}, return via {wgif}"), fwd.dev


def _nft_stage(snap: Snapshot, policy: Policy, src: IPv4Address, target: Target,
               service: Service, oif: str | None) -> tuple[Stage, list[str]]:
    pkt = Packet(saddr=src, daddr=target.address, proto=service.proto, iif=policy.gateway.interface,
                 oif=oif, dport=service.port)
    d = evaluate(snap.nft, "forward", pkt)
    return Stage(d.accepted, str(d)), d.warnings


def compute(snap: Snapshot, policy: Policy) -> list[Reach]:
    out: list[Reach] = []
    for key, name, src, _why in candidate_sources(snap, policy):
        wg = _wg_stage(snap, policy, key, src)
        for target in policy.targets:
            rt, oif = _routing_stage(snap, policy, src, target.address)
            for svc in target.services:
                nft, warnings = _nft_stage(snap, policy, src, target, svc, oif)
                out.append(Reach(key, name, src, target, svc, wg, rt, nft, warnings))
    return out


def listen_port_open(snap: Snapshot, policy: Policy) -> Stage:
    """Can handshakes reach the gateway? Evaluates the input hook for a UDP
    packet to the listen port arriving on the default-route interface."""
    rt = snap.routing
    default = rt.lookup("0.0.0.0")
    iif = default.dev if default else None
    pkt = Packet(saddr=IPv4Address("198.51.100.1"), daddr=IPv4Address("0.0.0.0"), proto="udp",
                 iif=iif, dport=policy.gateway.listen_port)
    # daddr is irrelevant for our rules but a rule matching a specific
    # gateway address would evaluate to false; use the WAN address when known.
    if iif and rt.link(iif) and rt.link(iif).addresses:
        pkt = Packet(pkt.saddr, rt.link(iif).addresses[0].ip, "udp", iif, None, policy.gateway.listen_port)
    d = evaluate(snap.nft, "input", pkt)
    return Stage(d.accepted, str(d))
