#!/bin/sh
# Protected LAN host. Routes tunnel traffic back via the gateway and serves
# a tiny HTTP page on $PORT so peers can prove reachability with curl.
set -eu
ip route add "$TUNNEL" via "$GATEWAY"
mkdir -p /www && echo "hello from $(hostname):$PORT" > /www/index.html
exec python3 -m http.server "$PORT" --bind 0.0.0.0 --directory /www
