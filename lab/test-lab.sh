#!/bin/sh
# End-to-end proof that the gateway enforces the intended policy.
# Runs from the host against the compose lab.
set -u
cd "$(dirname "$0")"
DC="docker compose"
pass=0; fail=0

x() { $DC exec -T "$@" 2>/dev/null; }
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
expect_reach()   { if x "$1" curl -s --connect-timeout 3 -m 4 "http://$2:$3/" | grep -q "hello from"; then ok "$1 -> $2:$3 reachable"; else bad "$1 -> $2:$3 should be reachable"; fi; }
expect_blocked() { if x "$1" curl -s --connect-timeout 3 -m 4 "http://$2:$3/" | grep -q "hello from"; then bad "$1 -> $2:$3 should be BLOCKED"; else ok "$1 -> $2:$3 blocked"; fi; }
expect_ping()    { if x "$1" ping -c1 -W2 "$2" >/dev/null; then ok "$1 ping $2"; else bad "$1 ping $2 should succeed"; fi; }
expect_noping()  { if x "$1" ping -c1 -W2 "$2" >/dev/null; then bad "$1 ping $2 should FAIL"; else ok "$1 ping $2 blocked"; fi; }

echo "== WireGuard handshakes"
expect_ping alice 10.10.0.1
expect_ping bob   10.10.0.1
expect_noping mallory 10.10.0.1     # valid key, not enrolled -> no handshake

echo "== alice (admin): full LAN access"
expect_reach alice 10.100.0.10 8080
expect_reach alice 10.100.0.20 5432
expect_ping  alice 10.100.0.20

echo "== bob (developer): app:8080 only"
expect_reach   bob 10.100.0.10 8080
expect_blocked bob 10.100.0.20 5432
expect_noping  bob 10.100.0.20

echo "== gateway: live state via wgdrift"
if x gateway python3 -m wgdrift wg show --json | grep -q '"listen_port": 51820'; then ok "wgdrift wg show reads kernel state"; else bad "wgdrift wg show"; fi
if x gateway python3 -m wgdrift wg diff wg0 --conf /etc/wgdrift/wg0.conf | grep -q "no drift"; then ok "wgdrift wg diff: kernel matches wg0.conf"; else bad "wgdrift wg diff reports drift on a clean gateway"; fi

echo; echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
