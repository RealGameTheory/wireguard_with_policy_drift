PY := .venv/bin/python
DC := docker compose -f lab/docker-compose.yml

.PHONY: venv test keys render build up down lab-test logs shell inject clean

venv:            ## create virtualenv and install package + dev deps
	python3 -m venv .venv && .venv/bin/pip install -q -e '.[dev]'

test:            ## unit tests (no Docker needed)
	$(PY) -m pytest -q

build:           ## build the lab image
	docker build -q -t wgdrift-lab lab/

keys: build      ## generate WireGuard key pairs into lab/keys/ (idempotent)
	lab/gen-keys.sh

render:          ## render wg configs, nftables ruleset and policy.yaml
	$(PY) lab/render.py

up: render       ## start the lab
	$(DC) up -d --build

down:
	$(DC) down -v

lab-test:        ## end-to-end connectivity + policy checks
	lab/test-lab.sh

logs:
	$(DC) logs --tail=50 gateway

shell:           ## shell on the gateway (wg, nft, ip, python3 -m wgdrift ...)
	$(DC) exec gateway sh

inject:          ## make inject S=rogue-peer|steal-ip|open-fw|lockout|reset
	lab/inject.sh $(S)

clean: down
	rm -rf lab/keys lab/gateway/wg0.conf lab/peers

drift-test:      ## inject every drift scenario, detect, reconcile, verify with live traffic
	lab/test-drift.sh

watch:           ## run the control loop with auto-reconcile on the lab gateway (Ctrl-C to stop)
	$(DC) exec gateway python3 -m wgdrift -p /etc/wgdrift/policy.yaml run --interval 3 --reconcile

check:           ## one-shot drift check on the lab gateway
	$(DC) exec gateway python3 -m wgdrift -p /etc/wgdrift/policy.yaml check --matrix
