#!/bin/sh
# End-to-end proof of the control loop: inject real drift into the running
# gateway, detect it with `wgdrift check`, heal it with `wgdrift reconcile`,
# then prove the access matrix is back to policy with test-lab.sh.
set -u
cd "$(dirname "$0")"
WG="docker compose exec -T gateway python3 -m wgdrift -p /etc/wgdrift/policy.yaml"
pass=0; fail=0
ok()  { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }

scenario() {  # name  expected-finding-kind
  echo "== $1"
  ./inject.sh "$1" >/dev/null || { bad "inject $1"; return; }
  out=$($WG check 2>&1); rc=$?
  if [ $rc -eq 1 ] && echo "$out" | grep -q "$2"; then ok "detected: $2"; else bad "expected finding '$2' (rc=$rc)"; echo "$out" | sed 's/^/      /'; fi
  out=$($WG reconcile 2>&1); rc=$?
  if [ $rc -eq 0 ]; then ok "reconciled"; else bad "reconcile rc=$rc"; echo "$out" | sed 's/^/      /'; fi
  if $WG check >/dev/null 2>&1; then ok "clean after reconcile"; else bad "still drifted"; $WG check | sed 's/^/      /'; fi
  # A peer removed and re-added keeps a stale session on the client until it
  # re-handshakes (<= 25s with keepalive), so allow a few attempts.
  n=0; while [ $n -lt 4 ]; do ./test-lab.sh >/dev/null 2>&1 && break; n=$((n+1)); sleep 8; done
  if [ $n -lt 4 ]; then ok "access matrix verified by live traffic"; else bad "live traffic checks failed"; ./test-lab.sh | grep FAIL | sed 's/^/      /'; fi
}

echo "== baseline"
if $WG check >/dev/null 2>&1; then ok "clean gateway reports no drift"; else bad "baseline not clean"; $WG check; fi

scenario rogue-peer   wg_rogue_peer
scenario steal-ip     wg_ip_stolen
scenario widen        wg_allowed_ips
scenario drop-peer    "wg_peer_missing"
scenario port         wg_listen_port
scenario forward-off  ip_forward_off
scenario del-route    tunnel_route_missing
scenario open-fw      nft_table_missing
scenario lockout      nft_rules_drift
scenario extra-rule   unauthorized_access
scenario chain-policy nft_rules_drift

echo; echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
