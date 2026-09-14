#!/bin/sh
set -eu
wg-quick up /etc/wgdrift/wg0.conf
exec sleep infinity
