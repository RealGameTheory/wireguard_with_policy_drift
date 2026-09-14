#!/usr/bin/env python3
"""Render lab/topology.yaml + lab/keys/ into:

  lab/gateway/wg0.conf        wg-quick config for the gateway
  lab/gateway/policy.yaml     the declarative policy wgdrift enforces
  lab/gateway/nftables.conf   initial ruleset == what wgdrift derives from the policy
  lab/peers/<name>/wg0.conf   one client config per peer (incl. unenrolled ones)
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

LAB = Path(__file__).resolve().parent
sys.path.insert(0, str(LAB.parent))
from wgdrift import nftgen, policy as policy_mod          # noqa: E402
from wgdrift.conf import InterfaceConf, PeerConf, render  # noqa: E402


def key(name: str, kind: str) -> str:
    p = LAB / "keys" / f"{name}.{kind}"
    if not p.exists():
        sys.exit(f"missing {p}; run `make keys` first")
    return p.read_text().strip()


def write(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)
    print(f"wrote {path.relative_to(LAB.parent)}")


def main() -> None:
    t = yaml.safe_load((LAB / "topology.yaml").read_text())
    gw, gw_pub = t["gateway"], key("gateway", "pub")
    prefix = t["tunnel_network"].split("/")[1]
    enrolled = {n: p for n, p in t["peers"].items() if p.get("enrolled", True)}

    gw_conf = InterfaceConf(private_key=key("gateway", "key"),
                            address=[f'{gw["tunnel_ip"]}/{prefix}'], listen_port=gw["listen_port"])
    for name, p in enrolled.items():
        gw_conf.peers.append(PeerConf(public_key=key(name, "pub"), allowed_ips=[f'{p["tunnel_ip"]}/32'], name=name))
    write(LAB / "gateway" / "wg0.conf", render(gw_conf), 0o600)

    policy = {
        "version": 1,
        "gateway": {
            "interface": gw["interface"], "public_key": gw_pub, "listen_port": gw["listen_port"],
            "tunnel_network": t["tunnel_network"], "protected_networks": [t["lan_network"]],
            "nft_table": "wgdrift",
        },
        "peers": [{"name": n, "public_key": key(n, "pub"), "tunnel_ip": p["tunnel_ip"], "role": p["role"]}
                  for n, p in enrolled.items()],
        "targets": [{"name": n, "address": s["lan_ip"], "services": [f'tcp/{s["port"]}', "icmp"]}
                    for n, s in t["servers"].items()],
        "roles": {role: {"allow": rules} for role, rules in t["roles"].items()},
        "safety": {"admin_peers": t["admin_peers"]},
    }
    write(LAB / "gateway" / "policy.yaml", yaml.safe_dump(policy, sort_keys=False))

    # The initial firewall is exactly what wgdrift would generate, so a fresh
    # gateway reports zero drift and every later difference is real.
    pol = policy_mod.from_dict(policy, "lab/gateway/policy.yaml")
    write(LAB / "gateway" / "nftables.conf",
          "#!/usr/sbin/nft -f\n# Rendered from policy.yaml via wgdrift.nftgen - do not edit by hand.\n"
          "flush ruleset\n\n" + nftgen.render_table(nftgen.build(pol)))

    for name, p in t["peers"].items():
        c = InterfaceConf(private_key=key(name, "key"), address=[f'{p["tunnel_ip"]}/{prefix}'],
                          peers=[PeerConf(public_key=gw_pub, allowed_ips=[t["tunnel_network"], t["lan_network"]],
                                          endpoint=f'{gw["wan_ip"]}:{gw["listen_port"]}',
                                          persistent_keepalive=25, name="gateway")])
        write(LAB / "peers" / name / "wg0.conf", render(c), 0o600)


if __name__ == "__main__":
    main()
