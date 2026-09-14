"""Command line entry point.

  wgdrift collect   [--json]                stage 1: snapshot of wg, routing, nftables
  wgdrift status    [--json]                stage 2: effective vs intended access matrix
  wgdrift check     [--json]                stages 1-4: drift report, exit 1 if drift
  wgdrift reconcile [--dry-run] [--json]    stage 5: plan + apply + verify (+rollback)
  wgdrift run       [--interval N] [--reconcile] [--status-file F]   continuous loop
  wgdrift policy validate | render-nft
  wgdrift wg show | diff                    low-level WireGuard helpers

The policy path comes from --policy, $WGDRIFT_POLICY, or /etc/wgdrift/policy.yaml.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from pathlib import Path

from . import drift, nftgen, policy as policy_mod, reconcile, report as rpt, wireguard
from .conf import parse as parse_conf
from .snapshot import take

DEFAULT_POLICY = "/etc/wgdrift/policy.yaml"


def _log(msg: str) -> None:
    print(time.strftime("%H:%M:%S ") + msg, file=sys.stderr, flush=True)


def _policy(args) -> policy_mod.Policy:
    path = args.policy or os.environ.get("WGDRIFT_POLICY") or DEFAULT_POLICY
    try:
        return policy_mod.load(path)
    except policy_mod.PolicyError as e:
        sys.exit(f"policy error: {e}")


def _report(args) -> drift.Report:
    pol = _policy(args)
    return drift.analyse(take(pol), pol)


# --- commands -------------------------------------------------------------------

def cmd_collect(args) -> int:
    snap = take(_policy(args))
    if args.json:
        print(json.dumps(snap.to_dict(), indent=2))
        return 0
    d = snap.to_dict()
    print("wireguard:", json.dumps(d["wireguard"], indent=2) if d["wireguard"] else "(interface missing)")
    print("routing:  ip_forward =", d["routing"]["ip_forward"])
    for r in d["routing"]["routes"]:
        print("   ", r)
    for l in d["routing"]["links"]:
        print("   link", l["name"], "UP" if l["up"] else "DOWN", ", ".join(l["addresses"]))
    print("nftables:")
    for c in d["nftables"]["chains"]:
        hook = f" hook {c['hook']} prio {c['prio']} policy {c['policy']}" if c["hook"] else ""
        print(f"    {c['family']} {c['table']} {c['name']}{hook}")
        for r in c["rules"]:
            print("       ", r)
    return 0


def cmd_status(args) -> int:
    r = _report(args)
    if args.json:
        print(json.dumps({"reachability": [x.to_dict() for x in r.reaches], "admins_ok": r.admins_ok()}, indent=2))
        return 0
    print(rpt.header(r) + rpt.matrix_text(r))
    return 0


def cmd_check(args) -> int:
    r = _report(args)
    if args.json:
        print(json.dumps(r.to_dict(), indent=2))
    else:
        print(rpt.header(r) + rpt.findings_text(r))
        if args.matrix:
            print(rpt.matrix_text(r))
    return 0 if r.clean else 1


def cmd_reconcile(args) -> int:
    r = _report(args)
    ops = reconcile.plan(r)
    if not args.json:
        print(rpt.header(r) + rpt.findings_text(r) + rpt.plan_text(ops))
    if not ops:
        if args.json:
            print(json.dumps({"success": True, "executed": [], "note": "nothing to do"}))
        return 0
    if args.dry_run:
        if args.json:
            print(json.dumps({"dry_run": True, "plan": [o.to_dict() for o in ops]}, indent=2))
        return 0
    res = reconcile.apply(r, ops, log=_log)
    if args.json:
        print(json.dumps(res.to_dict(), indent=2))
    else:
        print()
        if res.success:
            print(f"applied {len(res.executed)} operation(s); verification: "
                  f"{len(res.after.findings)} finding(s) remain, admins ok: {res.after.admins_ok()}")
            if res.after.findings:
                print(rpt.findings_text(res.after))
        else:
            print(f"FAILED: {res.error}" + (" (rolled back)" if res.rolled_back else ""))
    return 0 if res.success else 1


def cmd_run(args) -> int:
    pol = _policy(args)
    stop = {"now": False}

    def _sig(*_):
        stop["now"] = True
    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)

    _log(f"wgdrift loop: policy={pol.source} interface={pol.gateway.interface} "
         f"interval={args.interval}s reconcile={'on' if args.reconcile else 'off'}"
         + (" (dry-run)" if args.dry_run else ""))
    policy_mtime = Path(pol.source).stat().st_mtime if Path(pol.source).exists() else 0
    cycle = 0
    while not stop["now"]:
        cycle += 1
        try:
            p = Path(pol.source)
            if p.exists() and p.stat().st_mtime != policy_mtime:
                pol = policy_mod.load(pol.source)
                policy_mtime = p.stat().st_mtime
                _log("policy reloaded")
            r = drift.analyse(take(pol), pol)
            record = {"cycle": cycle, "time": r.snapshot.taken_at, "clean": r.clean, "worst": r.worst,
                      "admins_ok": r.admins_ok(),
                      "findings": [{"kind": f.kind, "severity": f.severity, "subject": f.subject,
                                    "message": f.message} for f in r.findings]}
            if r.clean:
                _log("ok: no drift")
            else:
                _log(f"DRIFT: {len(r.findings)} finding(s), worst {r.worst}")
                for f in r.findings:
                    _log(f"  [{f.severity}] {f.kind} {f.subject}: {f.message}")
            if args.reconcile and not r.clean:
                ops = reconcile.plan(r)
                if ops:
                    res = reconcile.apply(r, ops, dry_run=args.dry_run, log=_log)
                    record["reconcile"] = res.to_dict()
                    if not args.dry_run:
                        _log("reconciled" if res.success else f"reconcile failed: {res.error}")
                else:
                    _log("no automatic fix available; manual action required")
            if args.status_file:
                tmp = Path(args.status_file + ".tmp")
                tmp.write_text(json.dumps(record, indent=2))
                tmp.replace(args.status_file)
            if args.json:
                print(json.dumps(record), flush=True)
        except (wireguard.WireGuardError, policy_mod.PolicyError, OSError, RuntimeError) as e:
            _log(f"cycle error: {e}")
        for _ in range(int(args.interval * 10)):
            if stop["now"]:
                break
            time.sleep(0.1)
    _log("stopped")
    return 0


def cmd_policy_validate(args) -> int:
    pol = _policy(args)
    print(f"{pol.source}: ok - {len(pol.peers)} peer(s), {len(pol.targets)} target(s), "
          f"{len(pol.roles)} role(s), admins: {', '.join(pol.admin_peers) or 'none'}")
    return 0


def cmd_policy_render_nft(args) -> int:
    print(nftgen.render_table(nftgen.build(_policy(args))), end="")
    return 0


def cmd_wg_show(args) -> int:
    interfaces = wireguard.collect(args.interface)
    if args.json:
        print(json.dumps([i.to_dict() for i in interfaces], indent=2))
        return 0
    now = time.time()
    for iface in interfaces:
        print(f"interface {iface.name}  port {iface.listen_port}  pubkey {iface.public_key}")
        for p in iface.peers or ():
            age = p.handshake_age(now)
            age_s = "never" if age is None else f"{int(age)}s ago"
            print(f"  peer {p.public_key}\n    allowed-ips {', '.join(map(str, p.allowed_ips)) or '(none)'}"
                  f"\n    endpoint    {p.endpoint or '(none)'}   handshake {age_s} "
                  f"[{'connected' if p.is_connected(now) else 'idle'}]\n    transfer    rx {p.rx_bytes} B  tx {p.tx_bytes} B")
    return 0


def cmd_wg_diff(args) -> int:
    conf = parse_conf(Path(args.conf).read_text())
    live = wireguard.collect(args.interface)[0]
    want = {p.public_key: sorted(p.allowed_ips) for p in conf.peers}
    have = {k: sorted(str(n) for n in v) for k, v in live.bindings().items()}
    n = 0
    for key in sorted(set(want) | set(have)):
        name = (conf.peer(key).name if conf.peer(key) else None) or key[:12] + "…"
        if key not in have:
            print(f"MISSING  {name}: in config, not in kernel"); n += 1
        elif key not in want:
            print(f"ROGUE    {name}: in kernel, not in config  allowed-ips={have[key]}"); n += 1
        elif want[key] != have[key]:
            print(f"CHANGED  {name}: allowed-ips config={want[key]} kernel={have[key]}"); n += 1
    print("no drift" if n == 0 else f"{n} difference(s)")
    return 1 if n else 0


# --- parser ----------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="wgdrift", description="policy-drift control loop for WireGuard gateways")
    parser.add_argument("--policy", "-p", help=f"policy file (default: $WGDRIFT_POLICY or {DEFAULT_POLICY})")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("collect", help="snapshot live state of all three mechanisms")
    p.add_argument("--json", action="store_true"); p.set_defaults(func=cmd_collect)

    p = sub.add_parser("status", help="effective vs intended access matrix")
    p.add_argument("--json", action="store_true"); p.set_defaults(func=cmd_status)

    p = sub.add_parser("check", help="detect drift; exit 1 if any")
    p.add_argument("--json", action="store_true"); p.add_argument("--matrix", action="store_true")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("reconcile", help="fix drift safely (verifies, rolls back on admin lockout)")
    p.add_argument("--dry-run", action="store_true", help="show the plan, change nothing")
    p.add_argument("--json", action="store_true"); p.set_defaults(func=cmd_reconcile)

    p = sub.add_parser("run", help="continuous control loop")
    p.add_argument("--interval", type=float, default=10.0, help="seconds between cycles (default 10)")
    p.add_argument("--reconcile", action="store_true", help="fix drift automatically")
    p.add_argument("--dry-run", action="store_true", help="with --reconcile: log the plan only")
    p.add_argument("--status-file", help="write the latest cycle as JSON to this path")
    p.add_argument("--json", action="store_true", help="print one JSON line per cycle to stdout")
    p.set_defaults(func=cmd_run)

    pp = sub.add_parser("policy", help="policy tools").add_subparsers(dest="pcmd", required=True)
    pp.add_parser("validate").set_defaults(func=cmd_policy_validate)
    pp.add_parser("render-nft", help="print the nftables table the policy implies").set_defaults(func=cmd_policy_render_nft)

    wg = sub.add_parser("wg", help="WireGuard helpers").add_subparsers(dest="wgcmd", required=True)
    s = wg.add_parser("show"); s.add_argument("interface", nargs="?"); s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_wg_show)
    d = wg.add_parser("diff"); d.add_argument("interface"); d.add_argument("--conf", required=True)
    d.set_defaults(func=cmd_wg_diff)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (wireguard.WireGuardError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
