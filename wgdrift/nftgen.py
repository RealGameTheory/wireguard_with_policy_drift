"""Generate the nftables table wgdrift owns from a policy.

The table is built as structured `Rule` objects (the same type the
collector parses live rules into) so that intended and live rulesets can be
compared semantically, and rendered to nft syntax for `nft -f`.

Design choices that keep this safe on a production gateway:
  * Only ONE table (`inet <nft_table>`) is ever touched. Other tables,
    including the administrator's own input filtering, are left alone.
  * The `input` chain has policy accept and only adds an allow for the
    WireGuard port; it can never lock an admin out of SSH.
  * The `forward` chain has policy drop and one accept per (peer, rule).
  * The whole table is replaced in a single transaction.
"""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_network

from .nftables import Chain, Match, Rule, Ruleset, Verdict
from .policy import Policy

FAMILY = "inet"


@dataclass
class ManagedTable:
    name: str
    input: Chain
    forward: Chain

    @property
    def chains(self) -> list[Chain]:
        return [self.input, self.forward]


def build(policy: Policy) -> ManagedTable:
    g = policy.gateway
    inp = Chain(FAMILY, g.nft_table, "input", type="filter", hook="input", prio=0, policy="accept")
    inp.rules.append(Rule(
        (Match("dport", values=((g.listen_port, g.listen_port),), proto="udp"),),
        Verdict("accept"), comment="wgdrift:listen-port"))

    fwd = Chain(FAMILY, g.nft_table, "forward", type="filter", hook="forward", prio=0, policy="drop")
    fwd.rules.append(Rule(
        (Match("ct_state", values=("established", "related")),),
        Verdict("accept"), comment="wgdrift:return-traffic"))
    for peer in policy.peers:
        role = policy.roles[peer.role]
        for rule in role.allow:
            matches = [
                Match("iifname", values=(g.interface,)),
                Match("saddr", values=(ip_network(f"{peer.tunnel_ip}/32"),)),
                Match("daddr", values=(rule.dst,)),
            ]
            if rule.proto in ("tcp", "udp") and rule.ports:
                matches.append(Match("dport", values=tuple((p, p) for p in rule.ports), proto=rule.proto))
            elif rule.proto != "any":
                matches.append(Match("l4proto", values=(rule.proto,)))
            fwd.rules.append(Rule(tuple(matches), Verdict("accept"),
                                  comment=f"wgdrift:{peer.name}:{peer.role}"))
    return ManagedTable(g.nft_table, inp, fwd)


def render_chain(c: Chain) -> str:
    lines = [f"    chain {c.name} {{",
             f"        type {c.type} hook {c.hook} priority {c.prio}; policy {c.policy};"]
    lines += [f"        {r.text()}" for r in c.rules]
    lines.append("    }")
    return "\n".join(lines)


def render_table(mt: ManagedTable) -> str:
    body = "\n\n".join(render_chain(c) for c in mt.chains)
    return f"table {FAMILY} {mt.name} {{\n{body}\n}}\n"


def render_replace_script(mt: ManagedTable) -> str:
    """An nft script that atomically replaces the managed table. The first
    line creates the table if absent so the delete never fails; nft -f
    commits the whole file as one transaction."""
    return f"table {FAMILY} {mt.name} {{}}\ndelete table {FAMILY} {mt.name}\n{render_table(mt)}"


@dataclass
class ChainDiff:
    chain: str
    missing: list[Rule]          # intended but not live
    extra: list[Rule]            # live but not intended
    policy_live: str | None
    policy_want: str
    hook_ok: bool

    @property
    def clean(self) -> bool:
        return not self.missing and not self.extra and self.policy_live == self.policy_want and self.hook_ok


def diff(mt: ManagedTable, live: Ruleset) -> list[ChainDiff]:
    """Semantic comparison of the intended managed table with the live one."""
    out = []
    for want in mt.chains:
        have = live.chains.get((FAMILY, mt.name, want.name))
        if have is None:
            out.append(ChainDiff(want.name, list(want.rules), [], None, want.policy, False))
            continue
        want_c = {r.canonical(): r for r in want.rules}
        have_c = {r.canonical(): r for r in have.rules}
        out.append(ChainDiff(
            want.name,
            [r for k, r in want_c.items() if k not in have_c],
            [r for k, r in have_c.items() if k not in want_c],
            have.policy, want.policy,
            have.hook == want.hook and have.type == want.type,
        ))
    return out
