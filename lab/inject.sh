#!/bin/sh
# Drift injection scenarios. Each changes the LIVE kernel state of the
# gateway without touching wg0.conf / policy.yaml - the way real drift
# happens (an admin's quick fix, a script, a restart with stale config).
#
#   wireguard  rogue-peer   enrol mallory in the kernel only
#              steal-ip     move alice's IP to bob's key (alice unbound, bob can act as admin)
#              widen        bob's allowed-ips becomes the whole tunnel /24
#              drop-peer    remove alice (admin lockout)
#              port         change the listen port
#   routing    forward-off  net.ipv4.ip_forward = 0 (everyone locked out)
#              del-route    delete the return route to the tunnel network
#   nftables   open-fw      delete the managed table (everything forwarded)
#              lockout      flush the forward chain (policy drop blocks admins too)
#              extra-rule   hand-added accept: bob -> db
#              chain-policy forward policy drop -> accept
#   reset      restart the gateway to the rendered state
set -eu
cd "$(dirname "$0")"
gw() { docker compose exec -T gateway "$@"; }

case "${1:-}" in
  rogue-peer)   gw wg set wg0 peer "$(cat keys/mallory.pub)" allowed-ips 10.10.0.4/32 ;;
  steal-ip)     gw wg set wg0 peer "$(cat keys/bob.pub)" allowed-ips 10.10.0.3/32,10.10.0.2/32 ;;
  widen)        gw wg set wg0 peer "$(cat keys/bob.pub)" allowed-ips 10.10.0.0/24 ;;
  drop-peer)    gw wg set wg0 peer "$(cat keys/alice.pub)" remove ;;
  port)         gw wg set wg0 listen-port 51821 ;;
  forward-off)  gw sh -c 'echo 0 > /proc/sys/net/ipv4/ip_forward' ;;
  del-route)    gw ip route del 10.10.0.0/24 dev wg0 ;;
  open-fw)      gw nft delete table inet wgdrift ;;
  lockout)      gw nft flush chain inet wgdrift forward ;;
  extra-rule)   gw nft add rule inet wgdrift forward iifname wg0 ip saddr 10.10.0.3 ip daddr 10.100.0.20 tcp dport 5432 accept ;;
  chain-policy) gw nft chain inet wgdrift forward '{ policy accept; }' ;;
  reset)        docker compose restart gateway >/dev/null 2>&1; sleep 4 ;;
  *) sed -n '2,17p' "$0"; exit 1 ;;
esac
echo "injected: $1"
