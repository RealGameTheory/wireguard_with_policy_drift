"""Human-readable rendering of reports and plans."""
from __future__ import annotations

import time

from .drift import Report
from .reconcile import Op

SEV_MARK = {"critical": "!!", "high": "! ", "medium": "~ ", "info": "i "}


def findings_text(report: Report) -> str:
    if report.clean:
        return "no drift: kernel state matches policy\n"
    lines = [f"{len(report.findings)} finding(s), worst: {report.worst}", ""]
    for mech in ("wireguard", "routing", "nftables", "access", "collector"):
        fs = report.by_mechanism(mech)
        if not fs:
            continue
        lines.append(f"[{mech}]")
        for f in fs:
            tag = "" if f.fixable else " (manual)"
            lines.append(f"  {SEV_MARK[f.severity]} {f.kind}{tag}: {f.message}")
        lines.append("")
    lines.append("admins ok: " + ("yes" if report.admins_ok() else "NO"))
    return "\n".join(lines) + "\n"


def matrix_text(report: Report) -> str:
    """Effective vs intended access, one row per (peer, src, target, service)."""
    pol = report.policy
    rows = []
    for r in report.reaches:
        pp = pol.peer_by_key(r.key)
        own = pp is not None and r.src == pp.tunnel_ip
        intended = pol.allowed(pp, r.target, r.service) if (pp and own) else False
        eff = "YES" if r.reachable else "no"
        want = "YES" if intended else "no"
        flag = "" if r.reachable == intended else ("  <-- UNAUTHORIZED" if r.reachable else "  <-- MISSING")
        via = "" if r.reachable else f" [{r.blocked_by()}]"
        who = r.name or (r.key[:12] + "…")
        if pp and not own:
            who += f" as {r.src}"
        rows.append((who, f"{r.target.name} {r.service}", want, eff + via, flag))
    w0 = max((len(x[0]) for x in rows), default=4)
    w1 = max((len(x[1]) for x in rows), default=6)
    out = [f"{'peer':<{w0}}  {'target':<{w1}}  intended  effective", "-" * (w0 + w1 + 24)]
    out += [f"{a:<{w0}}  {b:<{w1}}  {c:<8}  {d}{e}" for a, b, c, d, e in rows]
    return "\n".join(out) + "\n"


def plan_text(ops: list[Op]) -> str:
    if not ops:
        return "nothing to do\n"
    lines = [f"plan: {len(ops)} operation(s)"]
    for i, op in enumerate(ops, 1):
        lines.append(f"  {i}. [{op.mechanism}] {op.description}")
        lines.append(f"       {' '.join(op.argv)}" + (" <<script" if op.stdin else ""))
    return "\n".join(lines) + "\n"


def header(report: Report) -> str:
    t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(report.snapshot.taken_at))
    return f"wgdrift  {t}  policy={report.policy.source}  interface={report.policy.gateway.interface}\n"
