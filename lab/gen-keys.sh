#!/bin/sh
# Generate a WireGuard key pair for every node in the lab, using the `wg`
# binary inside the lab image (the macOS host has no wireguard-tools).
# Existing keys are kept so re-running never rotates anything by accident.
set -eu
cd "$(dirname "$0")"
mkdir -p keys
docker image inspect wgdrift-lab >/dev/null 2>&1 || docker build -q -t wgdrift-lab . >/dev/null

need=""
for n in gateway alice bob mallory; do
  [ -f "keys/$n.key" ] || need="$need $n"
done
[ -z "$need" ] && { echo "all keys present in lab/keys/"; exit 0; }

docker run --rm wgdrift-lab sh -c "for n in $need; do k=\$(wg genkey); echo \"\$n \$k \$(echo \$k | wg pubkey)\"; done" \
| while read -r name priv pub; do
    umask 077
    printf '%s\n' "$priv" > "keys/$name.key"
    printf '%s\n' "$pub"  > "keys/$name.pub"
    echo "generated $name  pub=$pub"
  done
