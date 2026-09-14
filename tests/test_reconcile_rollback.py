"""Rollback behaviour of reconcile.apply. The plan is built from a real
snapshot; only the command executor and the post-apply re-collection are
intercepted, so the ordering and inverse commands under test are the real
ones the product would run."""
from dataclasses import replace
from ipaddress import ip_network
from pathlib import Path

import pytest

from wgdrift import drift, policy as policy_mod, reconcile
from wgdrift.nftables import parse_ruleset
from wgdrift.routing import RoutingState, parse_links, parse_routes, parse_rules
from wgdrift.snapshot import Snapshot
from wgdrift.wireguard import parse_dump

FIX = Path(__file__).parent / "fixtures" / "gateway"


@pytest.fixture
def pol():
    return policy_mod.load(FIX / "policy.yaml")


@pytest.fixture
def drifted(pol):
    wg = parse_dump((FIX / "wg_dump.txt").read_text(), interface="wg0")[0]
    rt = RoutingState(False, parse_routes((FIX / "routes.json").read_text()),   # ip_forward off ...
                      parse_links((FIX / "addrs.json").read_text()), parse_rules((FIX / "rules.json").read_text()))
    alice, bob = pol.peers
    peers = [replace(wg.peer(alice.public_key), allowed_ips=()),                 # ... and alice's IP stolen
             replace(wg.peer(bob.public_key), allowed_ips=(ip_network("10.10.0.3/32"), ip_network("10.10.0.2/32")))]
    return Snapshot(0.0, replace(wg, peers=tuple(peers)), rt, parse_ruleset((FIX / "nft.json").read_text()))


def test_failed_op_rolls_back_previous_ops_in_reverse(pol, drifted, monkeypatch):
    report = drift.analyse(drifted, pol)
    ops = reconcile.plan(report)
    assert [o.mechanism for o in ops] == ["routing", "wireguard", "wireguard"]
    ran = []

    def fake_exec(argv, stdin):
        ran.append(argv)
        if argv[:3] == ["wg", "set", "wg0"] and "lqch" in argv[4]:       # bob's op fails
            raise RuntimeError("Unable to modify interface: boom")
    monkeypatch.setattr(reconcile, "_exec", fake_exec)
    monkeypatch.setattr(reconcile, "take", lambda p: drifted)
    res = reconcile.apply(report, ops)
    assert not res.success and res.rolled_back and "boom" in res.error
    assert res.failed.description.startswith("set peer bob")
    # forward ops: sysctl, alice; failure on bob; then inverses of alice, sysctl in reverse order
    assert ran[0][0] == "sysctl-write" and ran[0][2] == "1\n"
    assert ran[-2][:5] == ["wg", "set", "wg0", "peer", pol.peers[0].public_key] and ran[-2][-1] == "0.0.0.0/32"
    assert ran[-1][0] == "sysctl-write" and ran[-1][2] == "0\n"


def test_admin_lockout_after_apply_is_reverted(pol, drifted, monkeypatch):
    """Admins were fine before, the 'fix' leaves them locked out -> revert."""
    clean_wg = parse_dump((FIX / "wg_dump.txt").read_text(), interface="wg0")[0]
    before = Snapshot(0.0, clean_wg, replace(drifted.routing, ip_forward=True),
                      parse_ruleset('{"nftables": []}'))             # only nftables drift, admins ok
    report = drift.analyse(before, pol)
    assert report.admins_ok() and "nft_table_missing" in {f.kind for f in report.findings}
    ops = reconcile.plan(report)
    ran = []
    monkeypatch.setattr(reconcile, "_exec", lambda argv, stdin: ran.append((argv, stdin)))
    # pretend the kernel came back with forwarding off after our change
    monkeypatch.setattr(reconcile, "take", lambda p: replace(before, routing=replace(before.routing, ip_forward=False)))
    res = reconcile.apply(report, ops)
    assert res.rolled_back and "admin lockout" in res.error
    assert ran[0][0] == ["nft", "-f", "-"] and ran[0][1].startswith("table inet wgdrift {}")
    # the inverse deletes the table we created (it did not exist before)
    assert ran[1][0] == ["nft", "-f", "-"] and ran[1][1].strip().endswith("delete table inet wgdrift")


def test_dry_run_executes_nothing(pol, drifted, monkeypatch):
    report = drift.analyse(drifted, pol)
    monkeypatch.setattr(reconcile, "_exec", lambda *a: pytest.fail("must not execute"))
    res = reconcile.apply(report, reconcile.plan(report), dry_run=True)
    assert res.executed == [] and res.after is None
