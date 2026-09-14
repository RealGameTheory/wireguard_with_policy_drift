"""Stage 1: one consistent read of all three mechanisms."""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from . import nftables, routing, wireguard
from .models import WGInterface
from .policy import Policy


@dataclass
class Snapshot:
    taken_at: float
    wg: WGInterface | None             # None if the interface does not exist
    routing: routing.RoutingState
    nft: nftables.Ruleset
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "taken_at": self.taken_at,
            "wireguard": self.wg.to_dict() if self.wg else None,
            "routing": self.routing.to_dict(),
            "nftables": self.nft.to_dict(),
            "errors": self.errors,
        }


def take(policy: Policy) -> Snapshot:
    errors: list[str] = []
    wg: WGInterface | None = None
    try:
        wg = wireguard.collect(policy.gateway.interface)[0]
    except wireguard.WireGuardError as e:
        # "Unable to access interface: No such device" is the normal error for
        # a missing interface; anything else is still worth surfacing.
        if "No such device" not in str(e):
            errors.append(f"wireguard: {e}")
    rt = routing.collect()
    nft = nftables.collect()
    return Snapshot(time.time(), wg, rt, nft, errors)
