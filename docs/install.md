# Installing on a gateway

Requirements: Linux with kernel WireGuard, `wireguard-tools`, `nftables`,
`iproute2`, Python 3.11+. Tested on Debian/Ubuntu-style hosts and the Docker
lab in this repository.

```bash
git clone <this repo> /usr/local/src/wgdrift
cd /usr/local/src/wgdrift
sudo packaging/install.sh
```

The installer creates a virtualenv in `/opt/wgdrift/venv`, installs the
`wgdrift` command, a systemd unit, and an example policy at
`/etc/wgdrift/policy.yaml` if none exists.

## First run: detect only

```bash
sudo wgdrift policy validate
sudo wgdrift collect                # what the kernel says right now
sudo wgdrift status                 # effective vs intended access, per flow
sudo wgdrift check --matrix         # drift findings; exit code 1 if any
sudo wgdrift reconcile --dry-run    # the exact commands a fix would run
```

(`wgdrift` here is `/opt/wgdrift/venv/bin/wgdrift`; add it to PATH or symlink it.)

If the gateway was set up by hand, the first `check` will usually report
nftables drift because your existing forward rules are not the ones the
policy implies. Compare `wgdrift policy render-nft` with `nft list ruleset`,
then either adjust the policy until `check` is clean, or let `reconcile`
install the managed table. Rules in other tables are left alone.

## Continuous mode

```bash
sudo systemctl enable --now wgdrift
journalctl -fu wgdrift
cat /run/wgdrift/status.json        # last cycle, machine-readable
```

The unit runs `wgdrift run --interval 10 --reconcile`. Drop `--reconcile`
from `ExecStart` for a detect-only deployment; every cycle still logs its
findings and updates the status file.

## Exit codes

| command | 0 | 1 | 2 |
|---|---|---|---|
| `check` | no drift | drift found | collector error |
| `reconcile` | converged (or nothing to do) | apply failed / rolled back | collector error |
