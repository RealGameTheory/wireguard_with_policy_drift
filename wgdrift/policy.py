"""Stage 3: the declarative policy.

A policy file is the administrator's statement of intent. Everything the
loop does is derived from it: which peers exist, which IP each key owns,
which targets and services are protected, and which roles may reach what.

    version: 1
    gateway:
      interface: wg0
      listen_port: 51820
      tunnel_network: 10.10.0.0/24
      protected_networks: [10.100.0.0/24]
      nft_table: wgdrift             # nftables table wgdrift owns (family inet)
    peers:
      - {name: alice, public_key: ..., tunnel_ip: 10.10.0.2, role: admin}
    targets:
      - {name: app, address: 10.100.0.10, services: [tcp/8080, icmp]}
    roles:
      admin:
        allow: [{dst: 10.100.0.0/24}]
      developer:
        allow: [{dst: 10.100.0.10/32, proto: tcp, ports: [8080]}]
    safety:
      admin_peers: [alice]           # reconciliation must never lock these out
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from pathlib import Path

import yaml

PROTOS = ("tcp", "udp", "icmp")


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Service:
    proto: str
    port: int | None = None

    @classmethod
    def parse(cls, s: str) -> "Service":
        s = str(s).strip().lower()
        if s == "icmp":
            return cls("icmp")
        m = re.fullmatch(r"(tcp|udp)/(\d{1,5})", s)
        if not m or not 0 < int(m.group(2)) < 65536:
            raise PolicyError(f"bad service {s!r}; use tcp/PORT, udp/PORT or icmp")
        return cls(m.group(1), int(m.group(2)))

    def __str__(self) -> str:
        return self.proto if self.port is None else f"{self.proto}/{self.port}"


@dataclass(frozen=True)
class Target:
    name: str
    address: IPv4Address
    services: tuple[Service, ...]


@dataclass(frozen=True)
class AllowRule:
    dst: IPv4Network
    proto: str = "any"                    # any tcp udp icmp
    ports: tuple[int, ...] = ()

    def permits(self, address: IPv4Address, service: Service) -> bool:
        if address not in self.dst:
            return False
        if self.proto == "any":
            return True
        if self.proto != service.proto:
            return False
        return not self.ports or service.port in self.ports


@dataclass(frozen=True)
class Role:
    name: str
    allow: tuple[AllowRule, ...]

    def permits(self, address: IPv4Address, service: Service) -> bool:
        return any(r.permits(address, service) for r in self.allow)


@dataclass(frozen=True)
class Peer:
    name: str
    public_key: str
    tunnel_ip: IPv4Address
    role: str

    @property
    def allowed_ips(self) -> tuple[IPv4Network, ...]:
        return (ip_network(f"{self.tunnel_ip}/32"),)


@dataclass(frozen=True)
class Gateway:
    interface: str
    listen_port: int
    tunnel_network: IPv4Network
    protected_networks: tuple[IPv4Network, ...]
    nft_table: str = "wgdrift"
    public_key: str | None = None


@dataclass(frozen=True)
class Intent:
    peer: Peer
    target: Target
    service: Service
    allowed: bool


@dataclass
class Policy:
    gateway: Gateway
    peers: tuple[Peer, ...]
    targets: tuple[Target, ...]
    roles: dict[str, Role]
    admin_peers: tuple[str, ...]
    source: str = "<memory>"
    version: int = 1

    # -- lookups ----------------------------------------------------------
    def peer_by_key(self, key: str) -> Peer | None:
        return next((p for p in self.peers if p.public_key == key), None)

    def peer_by_name(self, name: str) -> Peer | None:
        return next((p for p in self.peers if p.name == name), None)

    def peer_for_ip(self, ip: IPv4Address) -> Peer | None:
        return next((p for p in self.peers if p.tunnel_ip == ip), None)

    def target_by_address(self, ip: IPv4Address) -> Target | None:
        return next((t for t in self.targets if t.address == ip), None)

    def is_admin(self, peer: Peer) -> bool:
        return peer.name in self.admin_peers

    # -- intent -------------------------------------------------------------
    def allowed(self, peer: Peer, target: Target, service: Service) -> bool:
        return self.roles[peer.role].permits(target.address, service)

    def intents(self) -> list[Intent]:
        return [
            Intent(p, t, s, self.allowed(p, t, s))
            for p in self.peers for t in self.targets for s in t.services
        ]

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "gateway": {
                "interface": self.gateway.interface,
                "listen_port": self.gateway.listen_port,
                "tunnel_network": str(self.gateway.tunnel_network),
                "protected_networks": [str(n) for n in self.gateway.protected_networks],
                "nft_table": self.gateway.nft_table,
            },
            "peers": [{"name": p.name, "public_key": p.public_key,
                       "tunnel_ip": str(p.tunnel_ip), "role": p.role} for p in self.peers],
            "targets": [{"name": t.name, "address": str(t.address),
                         "services": [str(s) for s in t.services]} for t in self.targets],
            "admin_peers": list(self.admin_peers),
        }


# --- loading / validation -------------------------------------------------------

def _key_ok(k: str) -> bool:
    try:
        return len(k) == 44 and len(base64.b64decode(k, validate=True)) == 32
    except Exception:
        return False


def _req(d: dict, key: str, where: str):
    if not isinstance(d, dict) or key not in d:
        raise PolicyError(f"{where}: missing required field '{key}'")
    return d[key]


def _net(v, where: str) -> IPv4Network:
    try:
        n = ip_network(str(v), strict=False)
    except ValueError as e:
        raise PolicyError(f"{where}: {e}")
    if n.version != 4:
        raise PolicyError(f"{where}: only IPv4 is supported")
    return n


def _addr(v, where: str) -> IPv4Address:
    s = str(v).split("/")[0]
    try:
        a = ip_address(s)
    except ValueError as e:
        raise PolicyError(f"{where}: {e}")
    if a.version != 4:
        raise PolicyError(f"{where}: only IPv4 is supported")
    return a


def from_dict(doc: dict, source: str = "<memory>") -> Policy:
    if not isinstance(doc, dict):
        raise PolicyError("policy must be a mapping")
    version = int(doc.get("version", 1))
    if version != 1:
        raise PolicyError(f"unsupported policy version {version}")

    g = _req(doc, "gateway", "policy")
    gateway = Gateway(
        interface=str(_req(g, "interface", "gateway")),
        listen_port=int(_req(g, "listen_port", "gateway")),
        tunnel_network=_net(_req(g, "tunnel_network", "gateway"), "gateway.tunnel_network"),
        protected_networks=tuple(_net(n, "gateway.protected_networks") for n in _req(g, "protected_networks", "gateway")),
        nft_table=str(g.get("nft_table", "wgdrift")),
        public_key=g.get("public_key"),
    )
    if not re.fullmatch(r"[A-Za-z0-9_]{1,15}", gateway.interface):
        raise PolicyError(f"gateway.interface {gateway.interface!r} is not a valid interface name")
    if not 0 < gateway.listen_port < 65536:
        raise PolicyError("gateway.listen_port out of range")
    if not re.fullmatch(r"[A-Za-z0-9_]{1,64}", gateway.nft_table):
        raise PolicyError("gateway.nft_table must be an identifier")

    roles: dict[str, Role] = {}
    for name, body in (doc.get("roles") or {}).items():
        rules = []
        for i, r in enumerate(_req(body, "allow", f"roles.{name}") or []):
            proto = str(r.get("proto", "any")).lower()
            if proto not in ("any", *PROTOS):
                raise PolicyError(f"roles.{name}.allow[{i}]: bad proto {proto!r}")
            ports = tuple(int(p) for p in (r.get("ports") or []))
            if ports and proto not in ("tcp", "udp"):
                raise PolicyError(f"roles.{name}.allow[{i}]: ports need proto tcp or udp")
            rules.append(AllowRule(_net(_req(r, "dst", f"roles.{name}.allow[{i}]"), "dst"), proto, ports))
        roles[str(name)] = Role(str(name), tuple(rules))
    if not roles:
        raise PolicyError("policy defines no roles")

    peers: list[Peer] = []
    for i, p in enumerate(doc.get("peers") or []):
        where = f"peers[{i}]"
        peer = Peer(
            name=str(_req(p, "name", where)),
            public_key=str(_req(p, "public_key", where)),
            tunnel_ip=_addr(_req(p, "tunnel_ip", where), f"{where}.tunnel_ip"),
            role=str(_req(p, "role", where)),
        )
        if not _key_ok(peer.public_key):
            raise PolicyError(f"{where} ({peer.name}): public_key is not a valid WireGuard key")
        if peer.role not in roles:
            raise PolicyError(f"{where} ({peer.name}): unknown role {peer.role!r}")
        if peer.tunnel_ip not in gateway.tunnel_network:
            raise PolicyError(f"{where} ({peer.name}): tunnel_ip {peer.tunnel_ip} not in {gateway.tunnel_network}")
        peers.append(peer)
    for attr in ("name", "public_key", "tunnel_ip"):
        seen = [getattr(p, attr) for p in peers]
        dup = {x for x in seen if seen.count(x) > 1}
        if dup:
            raise PolicyError(f"duplicate peer {attr}: {', '.join(map(str, dup))}")

    targets: list[Target] = []
    for i, t in enumerate(doc.get("targets") or []):
        where = f"targets[{i}]"
        svcs = tuple(Service.parse(s) for s in (t.get("services") or ["icmp"]))
        target = Target(str(_req(t, "name", where)), _addr(_req(t, "address", where), f"{where}.address"), svcs)
        if not any(target.address in n for n in gateway.protected_networks):
            raise PolicyError(f"{where} ({target.name}): address {target.address} is not inside any protected network")
        targets.append(target)
    names = [t.name for t in targets]
    if len(set(names)) != len(names):
        raise PolicyError("duplicate target names")
    if not targets:
        raise PolicyError("policy defines no targets; nothing to protect")

    safety = doc.get("safety") or {}
    admin_peers = tuple(str(a) for a in (safety.get("admin_peers") or []))
    for a in admin_peers:
        if not any(p.name == a for p in peers):
            raise PolicyError(f"safety.admin_peers: unknown peer {a!r}")

    return Policy(gateway, tuple(peers), tuple(targets), roles, admin_peers, source, version)


def load(path: str | Path) -> Policy:
    path = Path(path)
    try:
        doc = yaml.safe_load(path.read_text())
    except OSError as e:
        raise PolicyError(f"cannot read policy: {e}")
    except yaml.YAMLError as e:
        raise PolicyError(f"{path}: invalid YAML: {e}")
    return from_dict(doc, str(path))
