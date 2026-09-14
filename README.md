# wgdrift — runtime policy-drift control for WireGuard gateways

A WireGuard gateway enforces access with three independent Linux
mechanisms: **WireGuard** binds each peer's key to the IPs it may use,
**kernel routing** decides where packets are forwarded, and **nftables**
filters them. They are configured separately, so after updates, restarts
and quick manual fixes the live kernel state drifts away from what the
administrator intended. wgdrift is a continuous five-stage control loop
that reads the live state of all three, computes the *effective*
reachability, diffs it against a declarative YAML policy, and reconciles
the gateway safely, rolling back if administrators would be locked out.

```
   ┌──────────┐   ┌──────────────┐   ┌────────┐   ┌───────┐   ┌───────────┐
   │ 1 collect│ → │2 reachability│ → │3 policy│ → │4 drift│ → │5 reconcile│ ─┐
   └──────────┘   └──────────────┘   └────────┘   └───────┘   └───────────┘  │
        ▲            wg / ip / nft, no simulation                 verify + rollback
        └────────────────────────────────────────────────────────────────────┘
```

Nothing is mocked: every number comes from `wg show dump`, `ip -j`,
`nft -j list ruleset` and `/proc/sys`, and every fix is a real `wg set`,
`ip route` or atomic `nft -f` transaction.

## Install on a gateway

```bash
sudo packaging/install.sh                 # Debian/Ubuntu; see docs/install.md
sudo vi /etc/wgdrift/policy.yaml          # see docs/policy.md
sudo wgdrift policy validate
sudo wgdrift check --matrix               # detect
sudo wgdrift reconcile --dry-run          # show the fix
sudo systemctl enable --now wgdrift       # continuous loop with auto-heal
```

## Commands

| command | stage | what it does |
|---|---|---|
| `wgdrift collect` | 1 | snapshot of WireGuard peers, routes/links/ip_forward, nftables ruleset |
| `wgdrift status` | 2 | effective vs intended access, one row per peer × target × service |
| `wgdrift check` | 1–4 | findings by mechanism and by access effect; exit 1 on drift |
| `wgdrift reconcile` | 5 | plan → apply → re-collect → verify admins → rollback on lockout |
| `wgdrift run` | loop | all of the above every N seconds; `--reconcile` to auto-heal, `--status-file` for JSON |
| `wgdrift policy validate / render-nft` | 3 | check the policy; print the nftables table it implies |

Example output after someone moved alice's IP onto bob's key with a single `wg set`:

```
3 finding(s), worst: critical

[wireguard]
  !! wg_ip_stolen: alice's address 10.10.0.2 is bound to bob
  !! wg_allowed_ips: peer bob allowed-ips are ['10.10.0.2/32', '10.10.0.3/32'], policy says ['10.10.0.3/32']; the extra prefixes let this key impersonate other addresses
[access]
  !! unauthorized_access: bob can reach db tcp/5432 using address 10.10.0.2 (which belongs to alice)
  !! missing_access: alice (admin) cannot reach db tcp/5432: blocked by wireguard (10.10.0.2 is bound to bob, not this key) (ADMIN LOCKOUT)

admins ok: NO

plan: 2 operation(s)
  1. [wireguard] set peer alice allowed-ips 10.10.0.2/32
  2. [wireguard] set peer bob allowed-ips 10.10.0.3/32
```

Neither the config file nor any nftables rule changed in that scenario;
only a cross-mechanism view catches it.

## What gets detected and fixed

| mechanism | detected | auto-fixed |
|---|---|---|
| WireGuard | rogue peer, missing peer, widened/wrong AllowedIPs, stolen IP, listen port, interface missing, key swap | all but interface/key (reported as manual) |
| routing | `ip_forward` off, tunnel return route missing, protected network route missing or looping into the tunnel, interface down, policy-routing rules | forwarding, tunnel route, connected routes, link up |
| nftables | managed table/chain missing, policy changed, rules added/removed (semantic comparison, not text), unfiltered forward path, blocked listen port, rules the evaluator cannot interpret | managed table replaced atomically |
| access | any peer × target × service that is reachable but forbidden, or granted but blocked, with the stage that blocks it | via the mechanism fixes above |

Safety rails: only the policy's own nftables table is ever written; routing
changes only add paths; policy peers are corrected before rogue peers are
removed; every operation has a recorded inverse; after applying, the
kernel is re-read and if any `admin_peers` lost intended access the run is
reverted.

## Lab (Docker, runs on macOS or Linux)

Docker Desktop's Linux kernel has native WireGuard and nftables, so the
lab is real kernel state, not a userspace emulation.

```bash
make venv keys up      # gateway + alice(admin) + bob(developer) + mallory(unenrolled) + app + db
make lab-test          # 11 live-traffic checks of the intended access matrix
make check             # wgdrift check --matrix on the gateway
make drift-test        # 11 drift scenarios: inject → detect → reconcile → verify with live traffic
make watch             # run the loop with auto-heal; in another shell: make inject S=steal-ip
```

To demo with your own laptop or a friend's phone as real WireGuard clients, see [docs/demo-devices.md](docs/demo-devices.md).

Scenarios in `lab/inject.sh`: rogue-peer, steal-ip, widen, drop-peer,
port, forward-off, del-route, open-fw, lockout, extra-rule, chain-policy.

## Layout

```
wgdrift/
  wireguard.py   stage 1: `wg show dump` parser, collect(), wg set controller
  routing.py     stage 1: routes, links, ip rules, ip_forward; longest-prefix lookup
  nftables.py    stage 1: `nft -j` parser + packet verdict evaluator (base chains, jumps, sets, ranges)
  snapshot.py    stage 1: one consistent read of all three
  reachability.py stage 2: per-flow verdict through WireGuard → routing → nftables
  policy.py      stage 3: YAML policy model + validation + intended access
  nftgen.py      stage 3: the nftables table a policy implies; semantic diff vs live
  drift.py       stage 4: mechanism findings (cause) + access findings (effect)
  reconcile.py   stage 5: ordered plan with inverses, apply, verify, rollback
  cli.py         collect/status/check/reconcile/run/policy/wg
  conf.py, models.py   wg-quick config parser, WireGuard state model
tests/           28 unit tests on real captures from the lab gateway (tests/fixtures/gateway)
lab/             Docker Compose lab, renderer, drift injection, end-to-end suites
packaging/       systemd unit + installer     examples/policy.yaml     docs/
```

## Limitations

- IPv4 only.
- Reachability is computed on the main routing table; policy-routing rules are reported, not modelled.
- The nftables evaluator covers interface, address, protocol, port, ct state, icmp type and jumps. Rules using other expressions (marks, named sets, maps) are reported as *uncertain* rather than guessed.
- A missing interface or a swapped private key needs `wg-quick`; wgdrift reports it and does not touch keys.
# wireguard_with_policy_drift
