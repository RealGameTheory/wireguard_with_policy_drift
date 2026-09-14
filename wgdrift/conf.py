"""Parser and renderer for wg-quick style configuration files.

The gateway's on-disk `wg0.conf` is what an administrator *thinks* is
running; `wgdrift.wireguard.collect()` is what actually runs. Comparing the
two is the first, cheapest form of drift detection, and the lab renders its
configs through the same renderer so they are byte-for-byte reproducible.
"""
from __future__ import annotations

from dataclasses import dataclass, field

_LIST_KEYS = {"allowedips", "address", "dns"}


@dataclass
class PeerConf:
    public_key: str
    allowed_ips: list[str] = field(default_factory=list)
    endpoint: str | None = None
    persistent_keepalive: int | None = None
    preshared_key: str | None = None
    name: str | None = None  # from a preceding "# Name: x" comment

    def to_wg_show(self) -> dict:
        return {"public_key": self.public_key, "allowed_ips": list(self.allowed_ips)}


@dataclass
class InterfaceConf:
    private_key: str | None = None
    address: list[str] = field(default_factory=list)
    listen_port: int | None = None
    fwmark: int | None = None
    mtu: int | None = None
    table: str | None = None
    hooks: dict[str, list[str]] = field(default_factory=dict)  # PostUp etc.
    peers: list[PeerConf] = field(default_factory=list)

    def peer(self, public_key: str) -> PeerConf | None:
        return next((p for p in self.peers if p.public_key == public_key), None)


def parse(text: str) -> InterfaceConf:
    conf = InterfaceConf()
    section: str | None = None
    current: PeerConf | None = None
    pending_name: str | None = None

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            body = line.lstrip("#").strip()
            if body.lower().startswith("name:"):
                pending_name = body.split(":", 1)[1].strip()
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            if section == "peer":
                current = PeerConf(public_key="", name=pending_name)
                conf.peers.append(current)
                pending_name = None
            continue
        if "=" not in line:
            raise ValueError(f"malformed line: {raw!r}")
        key, _, value = line.partition("=")
        key = key.strip().lower()
        value = value.split("#", 1)[0].strip()

        if section == "interface":
            if key == "privatekey":
                conf.private_key = value
            elif key == "address":
                conf.address += [v.strip() for v in value.split(",")]
            elif key == "listenport":
                conf.listen_port = int(value)
            elif key == "fwmark":
                conf.fwmark = int(value, 0)
            elif key == "mtu":
                conf.mtu = int(value)
            elif key == "table":
                conf.table = value
            elif key in ("preup", "postup", "predown", "postdown", "dns", "saveconfig"):
                conf.hooks.setdefault(key, []).append(value)
            else:
                raise ValueError(f"unknown [Interface] key: {key}")
        elif section == "peer" and current is not None:
            if key == "publickey":
                current.public_key = value
            elif key == "allowedips":
                current.allowed_ips += [v.strip() for v in value.split(",")]
            elif key == "endpoint":
                current.endpoint = value
            elif key == "persistentkeepalive":
                current.persistent_keepalive = int(value)
            elif key == "presharedkey":
                current.preshared_key = value
            else:
                raise ValueError(f"unknown [Peer] key: {key}")
        else:
            raise ValueError(f"key outside of a section: {raw!r}")
    return conf


_HOOK_NAMES = {
    "preup": "PreUp", "postup": "PostUp", "predown": "PreDown",
    "postdown": "PostDown", "dns": "DNS", "saveconfig": "SaveConfig",
}


def render(conf: InterfaceConf) -> str:
    out = ["[Interface]"]
    if conf.private_key:
        out.append(f"PrivateKey = {conf.private_key}")
    for a in conf.address:
        out.append(f"Address = {a}")
    if conf.listen_port is not None:
        out.append(f"ListenPort = {conf.listen_port}")
    if conf.fwmark is not None:
        out.append(f"FwMark = {conf.fwmark:#x}")
    if conf.mtu is not None:
        out.append(f"MTU = {conf.mtu}")
    if conf.table is not None:
        out.append(f"Table = {conf.table}")
    for key, values in conf.hooks.items():
        for v in values:
            out.append(f"{_HOOK_NAMES[key]} = {v}")
    for p in conf.peers:
        out.append("")
        if p.name:
            out.append(f"# Name: {p.name}")
        out.append("[Peer]")
        out.append(f"PublicKey = {p.public_key}")
        if p.preshared_key:
            out.append(f"PresharedKey = {p.preshared_key}")
        if p.allowed_ips:
            out.append(f"AllowedIPs = {', '.join(p.allowed_ips)}")
        if p.endpoint:
            out.append(f"Endpoint = {p.endpoint}")
        if p.persistent_keepalive is not None:
            out.append(f"PersistentKeepalive = {p.persistent_keepalive}")
    return "\n".join(out) + "\n"
