# Policy reference

The policy is a YAML file, by default `/etc/wgdrift/policy.yaml`
(`--policy` or `$WGDRIFT_POLICY` override it). The daemon reloads it when
the file changes. Validate with `wgdrift policy validate`.

## `gateway`

| field | required | meaning |
|---|---|---|
| `interface` | yes | WireGuard interface name, e.g. `wg0` |
| `listen_port` | yes | UDP port peers connect to |
| `tunnel_network` | yes | CIDR from which peer `tunnel_ip`s are allocated |
| `protected_networks` | yes | list of CIDRs reachable through the gateway; every target must be inside one |
| `nft_table` | no | name of the `inet` nftables table wgdrift owns (default `wgdrift`) |
| `public_key` | no | expected gateway public key; a mismatch is reported (cannot be auto-fixed) |

## `peers`

One entry per enrolled key: `name`, `public_key` (44-char base64), `tunnel_ip`
(inside `tunnel_network`, unique), `role` (must exist under `roles`).
The kernel binding wgdrift enforces is exactly `AllowedIPs = tunnel_ip/32`.
Any key on the interface that is not listed here is a rogue peer and is removed.

## `targets`

Hosts whose reachability is computed and verified. `services` is a list of
`tcp/PORT`, `udp/PORT` or `icmp` (default `[icmp]`). Add every service you
care about: the access matrix (`wgdrift status`) has one row per
peer × target × service.

## `roles`

```yaml
roles:
  <role>:
    allow:
      - dst: <CIDR>            # required
        proto: any|tcp|udp|icmp   # default any
        ports: [..]            # only with tcp/udp; empty = all ports
```

Each allow rule becomes one nftables rule per peer of that role:
`iifname <interface> ip saddr <tunnel_ip> ip daddr <dst> [<proto> dport {..}] accept`.
The forward chain policy is `drop`, so anything not listed is blocked.

## `safety`

`admin_peers`: names of peers that must never lose access. After every
reconciliation wgdrift re-reads the kernel; if any admin's intended access
is not effective, or the listen port became unreachable, all changes of that
run are undone in reverse order.

## What wgdrift will and will not touch

Managed (created, corrected, removed):

- peers and AllowedIPs on `gateway.interface`, its listen port
- `net.ipv4.ip_forward`, the route for `tunnel_network` via the interface,
  routes to protected networks that are directly connected
- the whole `inet <nft_table>` table (replaced atomically)

Never touched, only reported as findings marked *(manual)*:

- the gateway's private key / a missing interface (needs `wg-quick up`)
- other nftables tables, including your own input/SSH rules
- policy routing rules (`ip rule`) and routes into the tunnel for protected networks
