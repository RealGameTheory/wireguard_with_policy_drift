#!/bin/sh
# Drift injection scenarios. Each changes the LIVE kernel state of the
# gateway without touching wg0.conf / policy.yaml - the way real drift
# happens (an admin's quick fix, a script, a restart with stale config).
# Peer-based scenarios take an optional peer name:  ./inject.sh steal-ip laptop
#
#   wireguard  rogue-peer          enrol mallory in the kernel only
#              rogue-guest         enrol the un-enrolled guest device
#              steal-ip [PEER]     PEER (default bob) also gets alice's IP: alice unbound, PEER can act as admin
#              widen [PEER]        PEER's allowed-ips becomes the whole tunnel /24
#              drop-peer [PEER]    remove PEER (default alice = admin lockout)
#              port                change the listen port
#   routing    forward-off         net.ipv4.ip_forward = 0 (everyone locked out)
#              del-route           delete the return route to the tunnel network
#   nftables   open-fw             delete the managed table (everything forwarded)
#              lockout             flush the forward chain (policy drop blocks admins too)
#              extra-rule [PEER]   hand-added accept: PEER (default bob) -> db:5432
#              chain-policy        forward policy drop -> accept
#   reset                          restart the gateway to the rendered state
set -eu
cd "$(dirname "$0")"
gw() { docker compose exec -T gateway "$@"; }
tip() { grep -E "^  $1:" topology.yaml | sed -E 's/.*tunnel_ip: ([0-9.]+).*/\1/'; }
pub() { cat "keys/$1.pub"; }

s=${1:-}; p=${2:-}
case "$s" in
  rogue-peer)   gw wg set wg0 peer "$(pub mallory)" allowed-ips 10.10.0.4/32 ;;
  rogue-guest)  gw wg set wg0 peer "$(pub guest)" allowed-ips 10.10.0.6/32 ;;
  steal-ip)     p=${p:-bob};   gw wg set wg0 peer "$(pub $p)" allowed-ips "$(tip $p)/32,10.10.0.2/32" ;;
  promote-laptop) p=laptop;    gw wg set wg0 peer "$(pub $p)" allowed-ips "$(tip $p)/32,10.10.0.2/32" ;;
  widen)        p=${p:-bob};   gw wg set wg0 peer "$(pub $p)" allowed-ips 10.10.0.0/24 ;;
  drop-peer)    p=${p:-alice}; gw wg set wg0 peer "$(pub $p)" remove ;;
  port)         gw wg set wg0 listen-port 51821 ;;
  forward-off)  gw sh -c 'echo 0 > /proc/sys/net/ipv4/ip_forward' ;;
  del-route)    gw ip route del 10.10.0.0/24 dev wg0 ;;
  open-fw)      gw nft delete table inet wgdrift ;;
  lockout)      gw nft flush chain inet wgdrift forward ;;
  extra-rule)   p=${p:-bob};   gw nft add rule inet wgdrift forward iifname wg0 ip saddr "$(tip $p)" ip daddr 10.100.0.20 tcp dport 5432 accept ;;
  chain-policy) gw nft chain inet wgdrift forward '{ policy accept; }' ;;
  reset)        docker compose restart gateway >/dev/null 2>&1; sleep 4 ;;
  *) sed -n '2,21p' "$0"; exit 1 ;;
esac
echo "injected: $s${p:+ $p}"
