"""Stage 1 collector and packet-verdict evaluator for nftables.

The ruleset is read with `nft -j list ruleset` and turned into a structured
model of tables, chains and rules. The evaluator then answers "what verdict
would the kernel give this packet at hook X?" by walking base chains in
priority order and rules top to bottom, exactly as netfilter does.

Supported matches cover what access-control rulesets on a gateway use:
interface names, ip saddr/daddr (addresses, prefixes, ranges, sets),
l4proto, tcp/udp ports (single, ranges, sets), ct state, icmp type,
nfproto. Anything else is recorded as *unsupported* on that rule: the rule
is then treated as non-matching and a warning is attached to the decision,
so the drift stage can report the result as uncertain instead of guessing.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from typing import Any, Sequence

IPV4_FAMILIES = ("inet", "ip")
TERMINAL = ("accept", "drop", "reject")
_PROTO_NUM = {1: "icmp", 6: "tcp", 17: "udp", 58: "ipv6-icmp"}


class NftError(RuntimeError):
    pass


# --- model -----------------------------------------------------------------

@dataclass(frozen=True)
class Match:
    """One comparison in a rule, canonicalised so that rules produced by the
    generator and rules parsed back from the kernel compare equal."""
    key: str                       # iifname oifname saddr daddr l4proto dport sport ct_state icmp_type nfproto
    op: str = "=="                 # == != (sets/lists use ==; membership semantics)
    values: tuple = ()             # names / IPv4Network / (lo,hi) port ranges / state strings
    proto: str | None = None       # for dport/sport: tcp or udp

    def text(self) -> str:
        neg = "!= " if self.op == "!=" else ""
        if self.key in ("iifname", "oifname"):
            v = self.values[0] if len(self.values) == 1 else "{ " + ", ".join(self.values) + " }"
            return f'{self.key} {neg}"{v}"' if len(self.values) == 1 else f"{self.key} {neg}{v}"
        if self.key in ("saddr", "daddr"):
            nets = [str(n.network_address) if n.prefixlen == 32 else str(n) for n in self.values]
            v = nets[0] if len(nets) == 1 else "{ " + ", ".join(nets) + " }"
            return f"ip {self.key} {neg}{v}"
        if self.key == "l4proto":
            v = self.values[0] if len(self.values) == 1 else "{ " + ", ".join(self.values) + " }"
            return f"meta l4proto {neg}{v}"
        if self.key in ("dport", "sport"):
            parts = [str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in self.values]
            v = parts[0] if len(parts) == 1 else "{ " + ", ".join(parts) + " }"
            return f"{self.proto} {self.key} {neg}{v}"
        if self.key == "ct_state":
            return f"ct state {neg}{','.join(self.values)}"
        if self.key == "icmp_type":
            return f"icmp type {neg}{self.values[0]}"
        if self.key == "nfproto":
            return f"meta nfproto {neg}{self.values[0]}"
        raise ValueError(self.key)


@dataclass(frozen=True)
class Verdict:
    kind: str                      # accept drop reject jump goto return continue
    target: str | None = None

    def text(self) -> str:
        return f"{self.kind} {self.target}" if self.target else self.kind


@dataclass(frozen=True)
class Rule:
    matches: tuple[Match, ...]
    verdict: Verdict | None
    comment: str | None = None
    handle: int | None = None
    unsupported: tuple[str, ...] = ()
    rate_limited: bool = False

    def canonical(self) -> tuple:
        return (tuple(sorted((m.key, m.op, m.proto, tuple(sorted(map(str, m.values)))) for m in self.matches)),
                self.verdict.text() if self.verdict else None)

    def text(self) -> str:
        parts = [m.text() for m in self.matches]
        if self.verdict:
            parts.append(self.verdict.text())
        if self.comment:
            parts.append(f'comment "{self.comment}"')
        return " ".join(parts)


@dataclass
class Chain:
    family: str
    table: str
    name: str
    type: str | None = None        # filter/nat/route for base chains
    hook: str | None = None
    prio: int = 0
    policy: str = "accept"
    rules: list[Rule] = field(default_factory=list)

    @property
    def is_base(self) -> bool:
        return self.hook is not None


@dataclass
class Ruleset:
    tables: list[tuple[str, str]] = field(default_factory=list)       # (family, name)
    chains: dict[tuple[str, str, str], Chain] = field(default_factory=dict)

    def table_chains(self, family: str, table: str) -> list[Chain]:
        return [c for (f, t, _), c in self.chains.items() if f == family and t == table]

    def has_table(self, family: str, table: str) -> bool:
        return (family, table) in self.tables

    def base_chains(self, hook: str, families: Sequence[str] = IPV4_FAMILIES) -> list[Chain]:
        cs = [c for c in self.chains.values() if c.hook == hook and c.family in families]
        return sorted(cs, key=lambda c: c.prio)

    def to_dict(self) -> dict:
        return {
            "tables": [f"{f} {t}" for f, t in self.tables],
            "chains": [
                {"family": c.family, "table": c.table, "name": c.name, "hook": c.hook,
                 "prio": c.prio, "policy": c.policy, "rules": [r.text() for r in c.rules]}
                for c in self.chains.values()
            ],
        }


# --- parsing `nft -j list ruleset` -------------------------------------------

def _right_values(right: Any, kind: str) -> tuple:
    """Flatten the JSON right-hand side into canonical values."""
    if isinstance(right, dict) and "set" in right:
        items = right["set"]
    elif isinstance(right, list):
        items = right
    else:
        items = [right]
    out: list = []
    for it in items:
        if kind == "addr":
            if isinstance(it, dict) and "prefix" in it:
                out.append(ip_network(f'{it["prefix"]["addr"]}/{it["prefix"]["len"]}', strict=False))
            elif isinstance(it, dict) and "range" in it:
                a, b = (ip_address(x) for x in it["range"])
                out.extend(ip_network(n) for n in _summarize(a, b))
            elif isinstance(it, str):
                out.append(ip_network(it, strict=False))
            else:
                raise NftError(f"unsupported address operand {it!r}")
        elif kind == "port":
            if isinstance(it, dict) and "range" in it:
                out.append((int(it["range"][0]), int(it["range"][1])))
            elif isinstance(it, int):
                out.append((it, it))
            else:
                raise NftError(f"unsupported port operand {it!r}")
        elif kind == "proto":
            out.append(_PROTO_NUM.get(it, it) if isinstance(it, int) else str(it))
        else:
            out.append(str(it))
    return tuple(out)


def _summarize(a: IPv4Address, b: IPv4Address):
    from ipaddress import summarize_address_range
    return summarize_address_range(a, b)


def _parse_match(m: dict) -> Match:
    left, right, op = m["left"], m.get("right"), m.get("op", "==")
    if isinstance(right, str) and right.startswith("@"):
        raise NftError(f"named set {right}")
    if op not in ("==", "!=", "in"):
        raise NftError(f"operator {op}")
    op = "==" if op == "in" else op
    if "meta" in left:
        key = left["meta"]["key"]
        if key in ("iifname", "iif"):
            return Match("iifname", op, _right_values(right, "str"))
        if key in ("oifname", "oif"):
            return Match("oifname", op, _right_values(right, "str"))
        if key == "l4proto":
            return Match("l4proto", op, _right_values(right, "proto"))
        if key == "nfproto":
            return Match("nfproto", op, _right_values(right, "str"))
        raise NftError(f"meta {key}")
    if "payload" in left:
        proto, fld = left["payload"]["protocol"], left["payload"]["field"]
        if proto == "ip" and fld in ("saddr", "daddr"):
            return Match(fld, op, _right_values(right, "addr"))
        if proto == "ip" and fld == "protocol":
            return Match("l4proto", op, _right_values(right, "proto"))
        if proto in ("tcp", "udp") and fld in ("dport", "sport"):
            return Match(fld, op, _right_values(right, "port"), proto=proto)
        if proto == "icmp" and fld == "type":
            return Match("icmp_type", op, _right_values(right, "str"))
        if proto in ("ip6", "icmpv6"):
            return Match("nfproto", "==", ("ipv6",))   # never matches an IPv4 packet
        raise NftError(f"payload {proto} {fld}")
    if "ct" in left and left["ct"].get("key") == "state":
        return Match("ct_state", op, tuple(sorted(_right_values(right, "str"))))
    raise NftError(f"expression {json.dumps(left)}")


def _parse_rule(r: dict) -> Rule:
    matches: list[Match] = []
    verdict: Verdict | None = None
    unsupported: list[str] = []
    rate_limited = False
    for expr in r.get("expr", []):
        (kind, body), = expr.items()
        if kind == "match":
            try:
                matches.append(_parse_match(body))
            except NftError as e:
                unsupported.append(str(e))
        elif kind in ("accept", "drop", "reject", "return", "continue"):
            verdict = Verdict(kind)
        elif kind in ("jump", "goto"):
            verdict = Verdict(kind, body["target"])
        elif kind in ("counter", "log", "notrack", "meter"):
            continue
        elif kind == "limit":
            rate_limited = True
        else:
            unsupported.append(kind)
    return Rule(tuple(matches), verdict, r.get("comment"), r.get("handle"),
                tuple(unsupported), rate_limited)


def parse_ruleset(text: str) -> Ruleset:
    doc = json.loads(text or '{"nftables": []}')
    rs = Ruleset()
    for item in doc.get("nftables", []):
        if "table" in item:
            t = item["table"]
            rs.tables.append((t["family"], t["name"]))
        elif "chain" in item:
            c = item["chain"]
            rs.chains[(c["family"], c["table"], c["name"])] = Chain(
                family=c["family"], table=c["table"], name=c["name"], type=c.get("type"),
                hook=c.get("hook"), prio=int(c.get("prio", 0)), policy=c.get("policy", "accept"),
            )
        elif "rule" in item:
            r = item["rule"]
            key = (r["family"], r["table"], r["chain"])
            if key not in rs.chains:  # chain declared later? nft always emits chains first
                rs.chains[key] = Chain(r["family"], r["table"], r["chain"])
            rs.chains[key].rules.append(_parse_rule(r))
    return rs


# --- evaluation --------------------------------------------------------------

@dataclass(frozen=True)
class Packet:
    saddr: IPv4Address
    daddr: IPv4Address
    proto: str                      # tcp udp icmp
    iif: str | None = None
    oif: str | None = None
    dport: int | None = None
    ct_state: str = "new"
    icmp_type: str = "echo-request"


@dataclass
class Decision:
    verdict: str                    # accept drop reject
    chain: str | None = None        # "family table chain" that decided
    rule: Rule | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def accepted(self) -> bool:
        return self.verdict == "accept"

    def __str__(self) -> str:
        where = f" by {self.chain}" if self.chain else " (no base chain)"
        rule = f' rule "{self.rule.text()}"' if self.rule else ""
        return f"{self.verdict}{where}{rule}"


def _match(m: Match, p: Packet) -> bool:
    if m.key == "iifname":
        hit = p.iif in m.values
    elif m.key == "oifname":
        hit = p.oif in m.values
    elif m.key == "saddr":
        hit = any(p.saddr in n for n in m.values)
    elif m.key == "daddr":
        hit = any(p.daddr in n for n in m.values)
    elif m.key == "l4proto":
        hit = p.proto in m.values
    elif m.key in ("dport", "sport"):
        port = p.dport if m.key == "dport" else None
        hit = p.proto == m.proto and port is not None and any(lo <= port <= hi for lo, hi in m.values)
    elif m.key == "ct_state":
        hit = p.ct_state in m.values
    elif m.key == "icmp_type":
        hit = p.proto == "icmp" and p.icmp_type in m.values
    elif m.key == "nfproto":
        hit = "ipv4" in m.values
    else:
        return False
    return not hit if m.op == "!=" else hit


def _run_chain(rs: Ruleset, chain: Chain, p: Packet, d: Decision, depth: int = 0) -> Verdict | None:
    """Returns a terminal verdict, Verdict('return'), or None (fell off the end)."""
    if depth > 16:
        d.warnings.append(f"jump depth exceeded in {chain.name}")
        return None
    for rule in chain.rules:
        if rule.unsupported:
            d.warnings.append(
                f"{chain.family} {chain.table} {chain.name} handle {rule.handle}: "
                f"unsupported {', '.join(rule.unsupported)}; rule assumed not to match")
            continue
        if not all(_match(m, p) for m in rule.matches):
            continue
        if rule.rate_limited:
            d.warnings.append(f"{chain.name} handle {rule.handle}: rate limit assumed not exceeded")
        v = rule.verdict
        if v is None or v.kind == "continue":
            continue
        if v.kind in TERMINAL:
            d.chain, d.rule = f"{chain.family} {chain.table} {chain.name}", rule
            return v
        if v.kind == "return":
            return v
        if v.kind in ("jump", "goto"):
            target = rs.chains.get((chain.family, chain.table, v.target))
            if target is None:
                d.warnings.append(f"missing chain {v.target}")
                continue
            sub = _run_chain(rs, target, p, d, depth + 1)
            if sub is not None and sub.kind in TERMINAL:
                return sub
            if v.kind == "goto":
                return None
    return None


def evaluate(rs: Ruleset, hook: str, p: Packet) -> Decision:
    """Verdict for `p` at `hook` (e.g. "forward", "input") across every
    IPv4-capable base chain. A packet must be accepted by all base chains;
    a drop/reject in any one is final."""
    d = Decision("accept")
    for chain in rs.base_chains(hook):
        if chain.type != "filter":
            continue
        v = _run_chain(rs, chain, p, d)
        if v is None or v.kind == "return":
            if chain.policy in ("drop", "reject"):
                d.verdict, d.chain, d.rule = chain.policy, f"{chain.family} {chain.table} {chain.name} (policy)", None
                return d
            continue
        if v.kind in ("drop", "reject"):
            d.verdict = v.kind
            return d
        # accept: this chain is done, continue with the next base chain
    return d


# --- collection and write path ----------------------------------------------

def _nft(args: Sequence[str], stdin: str | None = None) -> str:
    if shutil.which("nft") is None:
        raise NftError("`nft` binary not found; install nftables")
    proc = subprocess.run(["nft", *args], capture_output=True, text=True, input=stdin)
    if proc.returncode != 0:
        raise NftError(f"nft {' '.join(args)}: {proc.stderr.strip()}")
    return proc.stdout


def collect() -> Ruleset:
    return parse_ruleset(_nft(["-j", "list", "ruleset"]))


def list_table_text(family: str, name: str) -> str | None:
    """Current textual definition of one table, or None if it does not exist."""
    try:
        return _nft(["list", "table", family, name])
    except NftError:
        return None


class NftController:
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.executed: list[tuple[list[str], str | None]] = []

    def apply(self, script: str) -> None:
        """Apply an nft script as ONE atomic transaction (`nft -f -`)."""
        self.executed.append((["nft", "-f", "-"], script))
        if not self.dry_run:
            _nft(["-f", "-"], stdin=script)

    def check(self, script: str) -> None:
        """Syntax/semantic check without committing."""
        _nft(["-c", "-f", "-"], stdin=script)
