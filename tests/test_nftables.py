"""Parser and evaluator tests against `nft -j list ruleset` captured from the
lab gateway (tests/fixtures/gateway/nft.json)."""
from ipaddress import IPv4Address, ip_network
from pathlib import Path

from wgdrift import nftgen, policy as policy_mod
from wgdrift.nftables import Match, Packet, Rule, Verdict, evaluate, parse_ruleset

FIX = Path(__file__).parent / "fixtures" / "gateway"
A, B, APP, DB = (IPv4Address(x) for x in ("10.10.0.2", "10.10.0.3", "10.100.0.10", "10.100.0.20"))


def ruleset():
    return parse_ruleset((FIX / "nft.json").read_text())


def test_parse_structure():
    rs = ruleset()
    assert rs.has_table("inet", "wgdrift")
    fwd = rs.chains[("inet", "wgdrift", "forward")]
    assert fwd.hook == "forward" and fwd.policy == "drop" and fwd.type == "filter"
    assert [r.comment for r in fwd.rules] == ["wgdrift:return-traffic", "wgdrift:alice:admin", "wgdrift:bob:developer"]
    bob = fwd.rules[2]
    assert Match("dport", values=((8080, 8080),), proto="tcp") in bob.matches
    assert Match("saddr", values=(ip_network("10.10.0.3/32"),)) in bob.matches
    assert bob.verdict == Verdict("accept") and not bob.unsupported


def test_forward_verdicts_match_policy():
    rs = ruleset()
    new = lambda s, d, proto, port=None: Packet(s, d, proto, iif="wg0", oif="eth0", dport=port)
    assert evaluate(rs, "forward", new(A, DB, "tcp", 5432)).accepted          # admin -> db
    assert evaluate(rs, "forward", new(B, APP, "tcp", 8080)).accepted         # developer -> app
    assert not evaluate(rs, "forward", new(B, DB, "tcp", 5432)).accepted      # developer -> db
    assert not evaluate(rs, "forward", new(B, APP, "udp", 8080)).accepted     # wrong proto
    assert not evaluate(rs, "forward", new(B, APP, "icmp")).accepted
    d = evaluate(rs, "forward", new(A, DB, "tcp", 5432, ))
    assert d.chain == "inet wgdrift forward" and d.rule.comment == "wgdrift:alice:admin"
    # not from the tunnel interface -> only the policy applies
    d = evaluate(rs, "forward", Packet(A, DB, "tcp", iif="eth1", oif="eth0", dport=5432))
    assert d.verdict == "drop" and "(policy)" in d.chain


def test_established_traffic_and_input_hook():
    rs = ruleset()
    p = Packet(DB, B, "tcp", iif="eth0", oif="wg0", dport=40000, ct_state="established")
    assert evaluate(rs, "forward", p).accepted
    assert evaluate(rs, "input", Packet(IPv4Address("10.200.0.11"), IPv4Address("10.200.0.2"), "udp", iif="eth1", dport=51820)).accepted


def test_unsupported_expression_is_reported_not_guessed():
    doc = '''{"nftables":[{"table":{"family":"inet","name":"t"}},
      {"chain":{"family":"inet","table":"t","name":"f","type":"filter","hook":"forward","prio":0,"policy":"drop"}},
      {"rule":{"family":"inet","table":"t","chain":"f","handle":9,"expr":[
         {"match":{"op":"==","left":{"meta":{"key":"mark"}},"right":7}},{"accept":null}]}}]}'''
    rs = parse_ruleset(doc)
    d = evaluate(rs, "forward", Packet(A, DB, "tcp", iif="wg0", dport=1))
    assert not d.accepted and any("unsupported meta mark" in w for w in d.warnings)


def test_jump_and_multiple_base_chains():
    doc = '''{"nftables":[{"table":{"family":"inet","name":"t"}},
      {"chain":{"family":"inet","table":"t","name":"f","type":"filter","hook":"forward","prio":0,"policy":"accept"}},
      {"chain":{"family":"inet","table":"t","name":"sub"}},
      {"chain":{"family":"ip","table":"other","name":"f2","type":"filter","hook":"forward","prio":10,"policy":"accept"}},
      {"rule":{"family":"inet","table":"t","chain":"f","expr":[{"jump":{"target":"sub"}}]}},
      {"rule":{"family":"inet","table":"t","chain":"sub","expr":[
         {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"prefix":{"addr":"10.100.0.0","len":24}}}},{"accept":null}]}},
      {"rule":{"family":"ip","table":"other","chain":"f2","expr":[
         {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":{"set":[22,{"range":[5000,6000]}]}}},{"drop":null}]}}]}'''
    rs = parse_ruleset(doc)
    # accepted by the first table but dropped by the second: drop wins
    assert evaluate(rs, "forward", Packet(A, DB, "tcp", dport=5432)).verdict == "drop"
    assert evaluate(rs, "forward", Packet(A, DB, "tcp", dport=8080)).accepted


def test_generated_table_matches_live_ruleset():
    pol = policy_mod.load(FIX / "policy.yaml")
    diffs = nftgen.diff(nftgen.build(pol), ruleset())
    assert all(d.clean for d in diffs), [(d.chain, d.missing, d.extra) for d in diffs]


def test_rendered_text_is_valid_nft_syntax_shape():
    pol = policy_mod.load(FIX / "policy.yaml")
    text = nftgen.render_table(nftgen.build(pol))
    assert 'iifname "wg0" ip saddr 10.10.0.3 ip daddr 10.100.0.10 tcp dport 8080 accept comment "wgdrift:bob:developer"' in text
    assert "policy drop;" in text and "policy accept;" in text
    script = nftgen.render_replace_script(nftgen.build(pol))
    assert script.startswith("table inet wgdrift {}\ndelete table inet wgdrift\n")
