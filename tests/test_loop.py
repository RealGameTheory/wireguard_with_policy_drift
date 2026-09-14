"""Stages 2-5 on a snapshot assembled from real gateway captures, plus the
same snapshot with drift applied to the model (what the kernel would return
after the lab's inject.sh scenarios)."""
from dataclasses import replace
from ipaddress import ip_network
from pathlib import Path

import pytest

from wgdrift import drift, nftgen, policy as policy_mod, reconcile
from wgdrift.models import WGPeer
from wgdrift.nftables import parse_ruleset
from wgdrift.routing import RoutingState, parse_links, parse_routes, parse_rules
from wgdrift.snapshot import Snapshot
from wgdrift.wireguard import parse_dump

FIX = Path(__file__).parent / "fixtures" / "gateway"


@pytest.fixture
def pol():
    return policy_mod.load(FIX / "policy.yaml")


@pytest.fixture
def snap():
    wg = parse_dump((FIX / "wg_dump.txt").read_text(), interface="wg0")[0]
    rt = RoutingState(True, parse_routes((FIX / "routes.json").read_text()),
                      parse_links((FIX / "addrs.json").read_text()), parse_rules((FIX / "rules.json").read_text()))
    return Snapshot(0.0, wg, rt, parse_ruleset((FIX / "nft.json").read_text()))


def kinds(report):
    return {f.kind for f in report.findings}


def test_clean_gateway_has_no_drift(snap, pol):
    r = drift.analyse(snap, pol)
    assert r.clean, [f.message for f in r.findings]
    assert r.admins_ok()
    eff = {(x.name, x.target.name, str(x.service)): x.reachable for x in r.reaches}
    assert eff[("alice", "db", "tcp/5432")] and eff[("bob", "app", "tcp/8080")]
    assert not eff[("bob", "db", "tcp/5432")] and not eff[("bob", "app", "icmp")]
    assert reconcile.plan(r) == []


def peer(snap, name_key):
    return next(p for p in snap.wg.peers if p.public_key.startswith(name_key))


def with_peers(snap, peers):
    return replace(snap, wg=replace(snap.wg, peers=tuple(peers)))


def test_stolen_ip_is_critical_and_plan_restores_it(snap, pol):
    alice, bob = pol.peers
    lp_alice = snap.wg.peer(alice.public_key)
    lp_bob = replace(snap.wg.peer(bob.public_key), allowed_ips=(ip_network("10.10.0.3/32"), ip_network("10.10.0.2/32")))
    s = with_peers(snap, [replace(lp_alice, allowed_ips=()), lp_bob])
    r = drift.analyse(s, pol)
    assert {"wg_ip_stolen", "wg_allowed_ips", "unauthorized_access", "missing_access"} <= kinds(r)
    assert r.worst == "critical" and not r.admins_ok()
    # bob, sourcing alice's address, can reach the db
    assert any(x.name == "bob" and str(x.src) == "10.10.0.2" and x.target.name == "db" and x.reachable for x in r.reaches)
    ops = reconcile.plan(r)
    descs = [o.description for o in ops]
    assert descs == ["set peer alice allowed-ips 10.10.0.2/32", "set peer bob allowed-ips 10.10.0.3/32"]
    assert all(o.rollback for o in ops)


def test_rogue_peer_removed_after_policy_peers_fixed(snap, pol):
    rogue = WGPeer(public_key="6K+I5ESOy5HEMlmF0lwxQgGTPP4K7LFv+D+sNbz4I0Q=", allowed_ips=(ip_network("10.10.0.4/32"),))
    s = with_peers(snap, [*snap.wg.peers, rogue])
    r = drift.analyse(s, pol)
    assert "wg_rogue_peer" in kinds(r)
    # the rogue has a binding but no nft rule, so no unauthorized access yet
    assert "unauthorized_access" not in kinds(r)
    [op] = reconcile.plan(r)
    assert op.argv[-1] == "remove" and op.rollback[0][0][-2:] == ["allowed-ips", "10.10.0.4/32"]


def test_missing_admin_is_lockout(snap, pol):
    s = with_peers(snap, [p for p in snap.wg.peers if not p.public_key.startswith("eMwZ")])
    r = drift.analyse(s, pol)
    f = next(f for f in r.findings if f.kind == "wg_peer_missing")
    assert f.severity == "critical" and "ADMIN LOCKOUT" in f.message
    assert not r.admins_ok()


def test_ip_forward_off_blocks_everyone(snap, pol):
    s = replace(snap, routing=replace(snap.routing, ip_forward=False))
    r = drift.analyse(s, pol)
    assert "ip_forward_off" in kinds(r)
    assert all(not x.reachable and x.blocked_by() == "routing" for x in r.reaches)
    assert reconcile.plan(r)[0].argv[0] == "sysctl-write"


def test_missing_tunnel_route(snap, pol):
    routes = tuple(x for x in snap.routing.routes if x.dev != "wg0")
    r = drift.analyse(replace(snap, routing=replace(snap.routing, routes=routes)), pol)
    assert "tunnel_route_missing" in kinds(r)
    assert reconcile.plan(r)[0].argv == ["ip", "-4", "route", "add", "10.10.0.0/24", "dev", "wg0"]


def test_deleted_table_is_fail_open(snap, pol):
    r = drift.analyse(replace(snap, nft=parse_ruleset('{"nftables": []}')), pol)
    assert "nft_table_missing" in kinds(r)
    bad = [f for f in r.findings if f.kind == "unauthorized_access"]
    assert any("bob" in f.subject and "db" in f.message for f in bad)
    ops = reconcile.plan(r)
    assert ops[-1].mechanism == "nftables" and ops[-1].stdin.startswith("table inet wgdrift {}")


def test_extra_rule_detected_semantically(snap, pol):
    text = (FIX / "nft.json").read_text().replace(
        '"expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "wg0"}}, '
        '{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "10.10.0.3"}}',
        '"expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "wg0"}}, '
        '{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "10.10.0.3"}}', 1)
    rs = parse_ruleset(text)
    from wgdrift.nftables import Match, Rule, Verdict
    rs.chains[("inet", "wgdrift", "forward")].rules.append(Rule(
        (Match("iifname", values=("wg0",)), Match("saddr", values=(ip_network("10.10.0.3/32"),)),
         Match("daddr", values=(ip_network("10.100.0.20/32"),)), Match("dport", values=((5432, 5432),), proto="tcp")),
        Verdict("accept")))
    r = drift.analyse(replace(snap, nft=rs), pol)
    assert {"nft_rules_drift", "unauthorized_access"} <= kinds(r)


def test_policy_validation_errors():
    doc = {"gateway": {"interface": "wg0", "listen_port": 1, "tunnel_network": "10.10.0.0/24",
                       "protected_networks": ["10.100.0.0/24"]},
           "roles": {"admin": {"allow": [{"dst": "10.100.0.0/24"}]}},
           "targets": [{"name": "app", "address": "10.100.0.10"}],
           "peers": [{"name": "x", "public_key": "notakey", "tunnel_ip": "10.10.0.2", "role": "admin"}]}
    with pytest.raises(policy_mod.PolicyError, match="public_key"):
        policy_mod.from_dict(doc)
    doc["peers"][0]["public_key"] = "eMwZgix2WJWODeE/ElQNdb6F2LAOsjLLGU2Xmg0A2AA="
    doc["peers"][0]["tunnel_ip"] = "10.99.0.2"
    with pytest.raises(policy_mod.PolicyError, match="not in 10.10.0.0/24"):
        policy_mod.from_dict(doc)
    doc["peers"][0]["tunnel_ip"] = "10.10.0.2"
    doc["safety"] = {"admin_peers": ["nobody"]}
    with pytest.raises(policy_mod.PolicyError, match="unknown peer"):
        policy_mod.from_dict(doc)
