"""Stage 1 collector for the Linux routing subsystem.

Reads, via iproute2's JSON output:
  * the main IPv4 routing table        (`ip -j -4 route show table main`)
  * policy routing rules               (`ip -j -4 rule show`)
  * links and their addresses          (`ip -j -4 addr show`)
  * net.ipv4.ip_forward                (/proc/sys/net/ipv4/ip_forward)

Only the main table is modelled. If non-standard policy rules exist the
snapshot records them so the drift stage can flag the result as uncertain.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, ip_address, ip_network
from pathlib import Path
from typing import Sequence

IP_FORWARD = Path("/proc/sys/net/ipv4/ip_forward")
STANDARD_RULE_TABLES = {"local", "main", "default"}


class RoutingError(RuntimeError):
    pass


def _ip(args: Sequence[str]) -> str:
    if shutil.which("ip") is None:
        raise RoutingError("`ip` binary not found; install iproute2")
    proc = subprocess.run(["ip", *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RoutingError(f"ip {' '.join(args)}: {proc.stderr.strip()}")
    return proc.stdout


@dataclass(frozen=True)
class Route:
    dst: IPv4Network
    dev: str | None
    via: IPv4Address | None = None
    metric: int = 0
    protocol: str | None = None
    scope: str | None = None
    table: str = "main"

    def __str__(self) -> str:
        s = "default" if self.dst.prefixlen == 0 else str(self.dst)
        if self.via:
            s += f" via {self.via}"
        if self.dev:
            s += f" dev {self.dev}"
        if self.metric:
            s += f" metric {self.metric}"
        return s


@dataclass(frozen=True)
class Link:
    name: str
    up: bool
    addresses: tuple[IPv4Interface, ...] = ()
    operstate: str = ""

    def has_address_in(self, net: IPv4Network) -> bool:
        return any(a.ip in net for a in self.addresses)


@dataclass(frozen=True)
class RoutingState:
    ip_forward: bool
    routes: tuple[Route, ...] = ()
    links: tuple[Link, ...] = ()
    rules: tuple[dict, ...] = ()

    def lookup(self, dst) -> Route | None:
        """Longest-prefix match in the main table, lowest metric wins ties.
        Mirrors what the kernel does for a forwarded packet (main table only)."""
        addr = ip_address(dst)
        best: Route | None = None
        for r in self.routes:
            if addr in r.dst and (
                best is None
                or r.dst.prefixlen > best.dst.prefixlen
                or (r.dst.prefixlen == best.dst.prefixlen and r.metric < best.metric)
            ):
                best = r
        return best

    def link(self, name: str) -> Link | None:
        return next((l for l in self.links if l.name == name), None)

    def interface_for(self, net: IPv4Network) -> Link | None:
        """The link that is directly connected to `net`, if any."""
        return next((l for l in self.links if l.has_address_in(net)), None)

    def nonstandard_rules(self) -> list[dict]:
        return [r for r in self.rules if r.get("table") not in STANDARD_RULE_TABLES]

    def to_dict(self) -> dict:
        return {
            "ip_forward": self.ip_forward,
            "routes": [str(r) for r in self.routes],
            "links": [
                {"name": l.name, "up": l.up, "operstate": l.operstate,
                 "addresses": [str(a) for a in l.addresses]}
                for l in self.links
            ],
            "nonstandard_rules": self.nonstandard_rules(),
        }


# --- parsers ---------------------------------------------------------------

def parse_routes(text: str) -> tuple[Route, ...]:
    out = []
    for e in json.loads(text or "[]"):
        dst = e.get("dst", "default")
        net = ip_network("0.0.0.0/0") if dst == "default" else ip_network(dst, strict=False)
        if net.version != 4:
            continue
        out.append(
            Route(
                dst=net,
                dev=e.get("dev"),
                via=ip_address(e["gateway"]) if e.get("gateway") else None,
                metric=int(e.get("metric", 0) or 0),
                protocol=e.get("protocol"),
                scope=e.get("scope"),
                table=e.get("table", "main"),
            )
        )
    return tuple(out)


def parse_links(text: str) -> tuple[Link, ...]:
    out = []
    for e in json.loads(text or "[]"):
        addrs = tuple(
            IPv4Interface(f'{a["local"]}/{a.get("prefixlen", 32)}')
            for a in e.get("addr_info", [])
            if a.get("family") == "inet"
        )
        flags = e.get("flags", [])
        # wg0 reports operstate UNKNOWN (no carrier concept); the UP flag is
        # the reliable signal that the interface is administratively up.
        out.append(Link(name=e["ifname"], up="UP" in flags, addresses=addrs,
                        operstate=e.get("operstate", "")))
    return tuple(out)


def parse_rules(text: str) -> tuple[dict, ...]:
    return tuple(json.loads(text or "[]"))


def read_ip_forward() -> bool:
    try:
        return IP_FORWARD.read_text().strip() == "1"
    except OSError as e:
        raise RoutingError(f"cannot read {IP_FORWARD}: {e}")


def collect() -> RoutingState:
    return RoutingState(
        ip_forward=read_ip_forward(),
        routes=parse_routes(_ip(["-j", "-4", "route", "show", "table", "main"])),
        links=parse_links(_ip(["-j", "-4", "addr", "show"])),
        rules=parse_rules(_ip(["-j", "-4", "rule", "show"])),
    )


class RoutingController:
    """Write path for the reconciler. Each call is one `ip`/sysctl change."""

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.executed: list[list[str]] = []

    def _run(self, argv: list[str]) -> None:
        self.executed.append(argv)
        if self.dry_run:
            return
        if argv[0] == "sysctl-write":
            Path(argv[1]).write_text(argv[2])
            return
        _ip(argv[1:])

    def enable_forwarding(self) -> None:
        self._run(["sysctl-write", str(IP_FORWARD), "1\n"])

    def add_route(self, dst: IPv4Network, dev: str, via: IPv4Address | None = None) -> None:
        argv = ["ip", "-4", "route", "add", str(dst)]
        if via:
            argv += ["via", str(via)]
        self._run(argv + ["dev", dev])

    def del_route(self, dst: IPv4Network, dev: str | None = None) -> None:
        argv = ["ip", "-4", "route", "del", str(dst)]
        if dev:
            argv += ["dev", dev]
        self._run(argv)
