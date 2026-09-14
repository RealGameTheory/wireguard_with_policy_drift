#!/bin/sh
# Print (or QR-encode) a WireGuard client config for a real device.
#   lab/client-conf.sh laptop                # endpoint 127.0.0.1:51820 (this Mac)
#   lab/client-conf.sh guest                 # endpoint <this Mac's LAN IP>:51820
#   lab/client-conf.sh guest 192.0.2.7:51820 # explicit endpoint
#   lab/client-conf.sh guest --qr            # QR code for the WireGuard phone app
set -eu
cd "$(dirname "$0")"
name=${1:?usage: client-conf.sh NAME [ENDPOINT] [--qr]}; shift
endpoint=""; qr=0
for a in "$@"; do case "$a" in --qr) qr=1 ;; *) endpoint=$a ;; esac; done
[ -f "peers/$name/wg0.conf" ] || { echo "no config for $name; run make render"; exit 1; }
if [ -z "$endpoint" ]; then
  if [ "$name" = laptop ]; then endpoint=127.0.0.1:51820
  else
    ip=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')
    [ -n "$ip" ] || { echo "cannot detect LAN IP; pass ENDPOINT explicitly"; exit 1; }
    endpoint="$ip:51820"
  fi
fi
conf=$(sed "s|^Endpoint = .*|Endpoint = $endpoint|" "peers/$name/wg0.conf")
if [ $qr -eq 1 ]; then
  printf '%s\n' "$conf" | docker run --rm -i alpine:3.20 sh -c 'apk add -q libqrencode-tools >/dev/null 2>&1; qrencode -t ansiutf8'
else
  printf '%s\n' "$conf"
fi
