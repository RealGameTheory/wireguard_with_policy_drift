#!/bin/sh
# Gateway boot: bring up wg0 from the rendered config, load the nftables
# policy, then idle. All three enforcement mechanisms are now live:
#   WireGuard (wg0 peers)  -  routing (ip_forward + connected routes)  -  nftables
set -eu
wg-quick up /etc/wgdrift/wg0.conf
nft -f /etc/wgdrift/nftables.conf
echo "gateway up:"; wg show; ip -br addr; nft list ruleset
exec sleep infinity
