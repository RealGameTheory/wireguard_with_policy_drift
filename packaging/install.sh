#!/bin/sh
# Install wgdrift on a Debian/Ubuntu WireGuard gateway. Run as root from a
# checkout of this repository:  sudo packaging/install.sh
set -eu
PREFIX=/opt/wgdrift
SRC=$(cd "$(dirname "$0")/.." && pwd)

[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
command -v apt-get >/dev/null && apt-get install -y --no-install-recommends wireguard-tools nftables iproute2 python3-venv >/dev/null

mkdir -p "$PREFIX" /etc/wgdrift
python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install -q --upgrade pip
"$PREFIX/venv/bin/pip" install -q "$SRC"
cp -r "$SRC/docs" "$PREFIX/"
install -m 644 "$SRC/packaging/wgdrift.service" /etc/systemd/system/wgdrift.service
[ -f /etc/wgdrift/policy.yaml ] || install -m 600 "$SRC/examples/policy.yaml" /etc/wgdrift/policy.yaml
systemctl daemon-reload

cat <<MSG
installed.

  1. edit /etc/wgdrift/policy.yaml  (see $PREFIX/docs/policy.md)
  2. $PREFIX/venv/bin/wgdrift policy validate
  3. $PREFIX/venv/bin/wgdrift check --matrix      # detect only
  4. $PREFIX/venv/bin/wgdrift reconcile --dry-run # see what would change
  5. systemctl enable --now wgdrift               # continuous loop
     journalctl -fu wgdrift
MSG
