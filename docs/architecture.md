# Architecture

## The three mechanisms and where drift hides

| Mechanism | Answers | Read via | Typical drift |
|---|---|---|---|
| WireGuard | which **key** may send/receive which **IPs** (AllowedIPs, longest-prefix, unique per interface) | `wg show all dump` | rogue peer added with `wg set`; AllowedIPs widened; IP moved between keys (silently unbinding the old one) |
| Routing | where a destination is **forwarded** (main table, policy rules, `ip_forward`) | `ip -j route`, `ip -j rule`, sysctl | forwarding disabled after a restart; a new default/overlay route bypasses the tunnel |
| nftables | which flows are **accepted** in `forward` | `nft -j list ruleset` | table deleted (fail-open); chain flushed (fail-closed lockout); hand-added accept rule |

A packet from a peer reaches a protected host only if all three agree:

```
reach(peer, dst, proto, port) =
      dst_src_ip ∈ AllowedIPs(peer.key)          # WireGuard
  and route(dst) leaves via the LAN interface     # routing, ip_forward=1
  and nft forward accepts (src_ip, dst, proto, port)   # nftables
```

nftables keys on the *IP*, WireGuard keys on the *key*. The `steal-ip`
lab scenario shows why looking at either alone is not enough: a single
`wg set` moves 10.10.0.2 to bob's key, every nft rule still looks correct,
the config file still looks correct, yet bob is now an admin and alice is
locked out.

## The five-stage loop

1. **Collect** — snapshot live state from the three mechanisms. Read-only,
   idempotent, no secrets retained (`wgdrift.wireguard` done; routing and
   nftables collectors next).
2. **Reachability** — evaluate the formula above for every (peer, protected
   host, service) pair to get the *effective* access matrix.
3. **Policy** — load `policy.yaml` (peers, roles, allowed destinations,
   safety rails) and expand it to the *intended* access matrix.
4. **Drift** — diff intended vs effective. Classify each finding by the
   mechanism that caused it and by risk (fail-open exposure vs fail-closed
   lockout) so that the reconciler can order fixes.
5. **Reconcile** — generate the minimal set of `wg set` / `ip route` / `nft`
   operations, apply them in an order that never removes an admin's path
   before its replacement exists, verify with a fresh collect, and roll back
   if admin reachability was lost.

## WireGuard state model (stage 1, implemented)

`WGInterface(name, public_key, listen_port, fwmark, peers)` and
`WGPeer(public_key, allowed_ips, endpoint, latest_handshake, rx, tx,
persistent_keepalive, has_preshared_key)`.

- `bindings()` gives the key→networks map the kernel enforces.
- `owner_of(ip)` answers "which key does the kernel trust for this source
  IP?" using WireGuard's longest-prefix match, which is what the
  reachability stage needs.
- `is_connected()` uses the 180 s reject-after-time, so an "idle" peer is a
  binding that exists but is not in use.
- Private and preshared keys are dropped at parse time; the model can be
  logged or serialised safely.

`WireGuardController` wraps `wg set` with a dry-run mode so the reconciler
can print its plan before touching the kernel.
