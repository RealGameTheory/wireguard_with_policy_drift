"""Data model for the live WireGuard state of a gateway.

Everything here is immutable and free of secrets: private keys and preshared
keys are never stored, only whether a preshared key is present. That matters
because these objects get serialised into drift reports and logs.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from ipaddress import IPv4Network, IPv6Network, ip_network
from typing import Iterable

Network = IPv4Network | IPv6Network

# WireGuard peers re-handshake at least every REKEY_AFTER_TIME (120s) while
# traffic flows, and a session is rejected after REJECT_AFTER_TIME (180s).
# A peer whose last handshake is older than this is not currently connected.
HANDSHAKE_STALE_AFTER = 180


def parse_networks(items: Iterable[str]) -> tuple[Network, ...]:
    """Parse CIDR strings, tolerating host addresses without a prefix."""
    return tuple(ip_network(s.strip(), strict=False) for s in items if s.strip())


@dataclass(frozen=True)
class WGPeer:
    public_key: str
    allowed_ips: tuple[Network, ...] = ()
    endpoint: str | None = None
    latest_handshake: int = 0  # unix seconds, 0 == never
    rx_bytes: int = 0
    tx_bytes: int = 0
    persistent_keepalive: int | None = None
    has_preshared_key: bool = False

    def handshake_age(self, now: float | None = None) -> float | None:
        if self.latest_handshake == 0:
            return None
        return (now if now is not None else time.time()) - self.latest_handshake

    def is_connected(self, now: float | None = None) -> bool:
        age = self.handshake_age(now)
        return age is not None and age < HANDSHAKE_STALE_AFTER

    def to_dict(self) -> dict:
        return {
            "public_key": self.public_key,
            "allowed_ips": [str(n) for n in self.allowed_ips],
            "endpoint": self.endpoint,
            "latest_handshake": self.latest_handshake,
            "rx_bytes": self.rx_bytes,
            "tx_bytes": self.tx_bytes,
            "persistent_keepalive": self.persistent_keepalive,
            "has_preshared_key": self.has_preshared_key,
        }


@dataclass(frozen=True)
class WGInterface:
    name: str
    public_key: str
    listen_port: int
    fwmark: int | None = None
    peers: tuple[WGPeer, ...] = field(default_factory=tuple)

    def peer(self, public_key: str) -> WGPeer | None:
        for p in self.peers:
            if p.public_key == public_key:
                return p
        return None

    def bindings(self) -> dict[str, tuple[Network, ...]]:
        """The key-to-IP binding WireGuard enforces: for each public key, the
        set of source networks the kernel will accept from that key (and route
        to it). This is the WireGuard contribution to effective reachability."""
        return {p.public_key: p.allowed_ips for p in self.peers}

    def owner_of(self, address) -> WGPeer | None:
        """Which peer does the kernel route/accept `address` for? WireGuard
        uses longest-prefix match across all peers' AllowedIPs."""
        addr = ip_network(address, strict=False)
        best: tuple[int, WGPeer] | None = None
        for p in self.peers:
            for n in p.allowed_ips:
                if n.version == addr.version and addr.subnet_of(n):
                    if best is None or n.prefixlen > best[0]:
                        best = (n.prefixlen, p)
        return best[1] if best else None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "public_key": self.public_key,
            "listen_port": self.listen_port,
            "fwmark": self.fwmark,
            "peers": [p.to_dict() for p in self.peers],
        }
