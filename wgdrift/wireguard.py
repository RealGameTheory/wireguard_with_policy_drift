"""Stage 1 collector for WireGuard: read (and, for the reconciler, write)
the kernel's live WireGuard state.

Reading goes through `wg show all dump`, which is the only stable,
machine-readable interface wireguard-tools offers. It prints one
tab-separated line per interface followed by one per peer:

  <iface> <private-key> <public-key> <listen-port> <fwmark>
  <iface> <public-key> <preshared-key> <endpoint> <allowed-ips> \
          <latest-handshake> <rx-bytes> <tx-bytes> <persistent-keepalive>

The private key and preshared key are discarded immediately after parsing.
"""
from __future__ import annotations

import shutil
import subprocess
from typing import Sequence

from .models import WGInterface, WGPeer, parse_networks

NONE = "(none)"


class WireGuardError(RuntimeError):
    pass


def _opt(value: str) -> str | None:
    return None if value in (NONE, "", "off") else value


def _fwmark(value: str) -> int | None:
    return None if value == "off" else int(value, 0)


def _keepalive(value: str) -> int | None:
    return None if value == "off" else int(value)


def parse_dump(text: str, interface: str | None = None) -> list[WGInterface]:
    """Parse `wg show all dump` output (or `wg show <iface> dump` when
    `interface` is given, in which case lines lack the leading name column).
    """
    partial: dict[str, dict] = {}
    order: list[str] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            continue
        fields = raw.split("\t")
        if interface is not None:
            fields = [interface, *fields]
        name = fields[0]
        if len(fields) == 5:  # interface header
            _, _private, public, port, fwmark = fields
            partial[name] = {
                "public_key": public,
                "listen_port": int(port),
                "fwmark": _fwmark(fwmark),
                "peers": [],
            }
            order.append(name)
        elif len(fields) == 9:  # peer
            if name not in partial:
                raise WireGuardError(f"line {lineno}: peer before interface header")
            _, public, psk, endpoint, allowed, hs, rx, tx, ka = fields
            partial[name]["peers"].append(
                WGPeer(
                    public_key=public,
                    allowed_ips=parse_networks(allowed.split(",")) if allowed != NONE else (),
                    endpoint=_opt(endpoint),
                    latest_handshake=int(hs),
                    rx_bytes=int(rx),
                    tx_bytes=int(tx),
                    persistent_keepalive=_keepalive(ka),
                    has_preshared_key=psk != NONE,
                )
            )
        else:
            raise WireGuardError(f"line {lineno}: unexpected field count {len(fields)}")
    return [
        WGInterface(name=n, peers=tuple(partial[n].pop("peers")), **partial[n]) for n in order
    ]


def _wg(args: Sequence[str], *, check: bool = True) -> str:
    if shutil.which("wg") is None:
        raise WireGuardError("`wg` binary not found; install wireguard-tools")
    proc = subprocess.run(["wg", *args], capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise WireGuardError(f"wg {' '.join(args)}: {proc.stderr.strip()}")
    return proc.stdout


def collect(interface: str | None = None) -> list[WGInterface]:
    """Read live WireGuard state from the kernel. Requires CAP_NET_ADMIN."""
    if interface is None:
        return parse_dump(_wg(["show", "all", "dump"]))
    return parse_dump(_wg(["show", interface, "dump"]), interface=interface)


class WireGuardController:
    """Minimal write path for the reconciler (stage 5).

    Every mutation is a single `wg set` invocation so it is atomic from the
    kernel's point of view and trivially reversible. With `dry_run=True` the
    commands are recorded instead of executed, which lets the reconciler
    show its plan before touching anything.
    """

    def __init__(self, interface: str, dry_run: bool = False):
        self.interface = interface
        self.dry_run = dry_run
        self.executed: list[list[str]] = []

    def _run(self, args: list[str]) -> None:
        self.executed.append(["wg", *args])
        if not self.dry_run:
            _wg(args)

    def set_peer(
        self,
        public_key: str,
        allowed_ips: Sequence[str],
        *,
        endpoint: str | None = None,
        persistent_keepalive: int | None = None,
    ) -> None:
        """Add the peer or replace its AllowedIPs (and optionally endpoint)."""
        args = ["set", self.interface, "peer", public_key, "allowed-ips", ",".join(allowed_ips)]
        if endpoint:
            args += ["endpoint", endpoint]
        if persistent_keepalive is not None:
            args += ["persistent-keepalive", str(persistent_keepalive)]
        self._run(args)

    def remove_peer(self, public_key: str) -> None:
        self._run(["set", self.interface, "peer", public_key, "remove"])

    def set_listen_port(self, port: int) -> None:
        self._run(["set", self.interface, "listen-port", str(port)])
