# Demo with real devices

The lab gateway publishes UDP 51820 on the Mac that runs Docker, so any
real WireGuard client can join the tunnel: your own laptop, a friend's
laptop on the same Wi-Fi, or a phone. Two device peers are pre-generated:

| peer | address | enrolled | use |
|---|---|---|---|
| `laptop` | 10.10.0.5 | yes, role developer | your machine: may reach app:8080 only |
| `guest` | 10.10.0.6 | **no** | a friend's device: locked out until someone enrols it behind the policy's back |

## 1. Start the lab

```bash
make up
make lab-test
```

## 2. Connect your own Mac (the one running Docker)

Install the WireGuard app from the Mac App Store (free, official). Then:

```bash
lab/client-conf.sh laptop > ~/Desktop/laptop.conf
```

WireGuard app → Import tunnel(s) from file → pick `laptop.conf` → Activate.
The endpoint is `127.0.0.1:51820`, i.e. Docker's published port on this Mac.

Check it: in a terminal, `curl http://10.100.0.10:8080/` prints
"hello from app:8080"; `curl -m 3 http://10.100.0.20:5432/` times out
because a developer may not reach the database.

## 3. Connect a friend's laptop or phone (same Wi-Fi)

The endpoint is this Mac's LAN address, auto-detected:

```bash
lab/client-conf.sh guest            # prints the config; send the file to the laptop
lab/client-conf.sh guest --qr       # QR code for the WireGuard phone app: Add tunnel → scan
```

If macOS asks whether to allow incoming connections for Docker, allow it.
If auto-detection picks the wrong interface, pass the endpoint explicitly:
`lab/client-conf.sh guest 192.168.1.20:51820`.

The guest is **not** enrolled, so activating the tunnel does nothing:
no handshake, no traffic. That is the starting point of the demo below.

## 4. The demo, step by step

Open a terminal on the Mac with the control loop watching (it heals every 3 s):

```bash
make watch
```

Keep a second terminal for injecting drift. Suggested sequence:

**A. A backdoor peer.** The friend's device is off the policy. An "admin"
adds it by hand:

```bash
make inject S=rogue-guest
```

Within seconds the friend's WireGuard app shows a handshake and
`curl http://10.100.0.10:8080/` works on their device. The watch terminal
reports `wg_rogue_peer` and removes the key. The friend's tunnel goes dead
again. Stop the loop first (Ctrl-C) if you want the backdoor to stay open
long enough to show it on the friend's screen, then run
`make check` and `make reconcile` by hand.

**B. Fail-open firewall.** Your laptop is a developer.

```bash
make inject S=open-fw
```

On your Mac, `curl http://10.100.0.20:5432/` now prints "hello from db".
The watch terminal reports `nft_table_missing` and `unauthorized_access
laptop`, then restores the table; the curl times out again.

**C. Stolen admin identity.**

```bash
make inject S=promote-laptop
```

Your laptop's key now also owns alice's address 10.10.0.2. The report
shows `wg_ip_stolen alice` and `missing_access alice (ADMIN LOCKOUT)`,
and the fix restores alice before narrowing your laptop.

**D. Everyone locked out.**

```bash
make inject S=forward-off
```

All curls from all devices hang; `ip_forward_off` is reported and fixed.

Use `make inject S=reset` to return the gateway to its rendered state at any time,
and `make check` for a one-shot report with the access matrix.

## Troubleshooting

- **No handshake from a friend's device**: both machines must be on the same
  Wi-Fi with client isolation off; check `docker port wgdrift-gateway-1`
  shows `0.0.0.0:51820`, and that the endpoint IP matches `ipconfig getifaddr en0`.
- **Handshake but no traffic after a fix**: a peer that was removed and re-added
  keeps a stale session for up to 25 s until the client re-handshakes. Toggle the tunnel.
- **Your Mac's own tunnel breaks Docker**: the client only routes 10.10.0.0/24
  and 10.100.0.0/24; nothing else changes. If in doubt deactivate the tunnel.

## 5. Full scenario list for a developer laptop

With the `laptop` tunnel active (address 10.10.0.5, developer: app:8080 only),
run each block in order: inject, observe on your Mac, detect, fix, observe again.
`APP` and `DB` below are `curl -m 3 http://10.100.0.10:8080/` and
`curl -m 3 http://10.100.0.20:5432/`.

| scenario | inject | what you see on your Mac while drifted | finding | after reconcile |
|---|---|---|---|---|
| firewall deleted (fail-open) | `make inject S=open-fw` | DB answers | `nft_table_missing`, `unauthorized_access laptop` | DB times out |
| chain policy flipped to accept | `make inject S=chain-policy` | DB answers | `nft_rules_drift` (policy accept) | DB times out |
| hand-added rule for you | `make inject S="extra-rule laptop"` | DB answers | `nft_rules_drift` (1 unexpected rule), `unauthorized_access laptop` | DB times out |
| forward chain flushed (fail-closed) | `make inject S=lockout` | APP times out too | `nft_rules_drift`, `missing_access` for everyone, ADMIN LOCKOUT | APP answers |
| forwarding disabled | `make inject S=forward-off` | APP times out, `ping 10.10.0.1` still works | `ip_forward_off` | APP answers |
| return route deleted | `make inject S=del-route` | APP times out | `tunnel_route_missing` | APP answers |
| your key steals alice's IP | `make inject S="steal-ip laptop"` | nothing changes for you; alice is locked out: `docker compose -f lab/docker-compose.yml exec alice curl -m 3 http://10.100.0.20:5432/` times out | `wg_ip_stolen alice`, `missing_access alice (ADMIN LOCKOUT)`, `unauthorized_access laptop ... using address 10.10.0.2` | alice reachable again |
| you are removed | `make inject S="drop-peer laptop"` | APP times out, app shows no new handshake | `wg_peer_missing laptop`, `missing_access laptop` | APP answers after the client re-handshakes (toggle the tunnel or wait ≤25 s) |
| backdoor device | `make inject S=rogue-guest` | nothing for you; a friend's `guest` tunnel comes alive | `wg_rogue_peer` | guest tunnel dead again |
| listen port changed | `make inject S=port` | tunnel keeps working ~2 min, then dies (client still sends to 51820) | `wg_listen_port` | fixed before you notice, if the loop is running |

Then repeat any of them with `make watch` running in another terminal to show
the loop healing on its own within three seconds.
