# ============================================================
#  Nexus Network Lab — Makefile
#  Author: Adrian S. Obungu
# ============================================================

.PHONY: help lab-01 lab-02 destroy status clean verify-01 capture security automate setup

SHELL := /bin/bash

help:
	@echo ""
	@echo "  Nexus Network Lab"
	@echo "  ─────────────────────────────────────────"
	@echo "  make setup       Install all Python dependencies"
	@echo "  make lab-01      Deploy Lab 01: OSPF Fundamentals"
	@echo "  make lab-02      Deploy Lab 02: Static Routing"
	@echo "  make verify-01   Run automated OSPF verification"
	@echo "  make capture     Capture 10 OSPF Hello packets (Scapy)"
	@echo "  make security    OSPF rogue LSA simulation (dry-run)"
	@echo "  make automate    Collect state from all routers"
	@echo "  make destroy     Tear down all running labs"
	@echo "  make status      Show running containers"
	@echo "  make clean       Remove lab artefacts"
	@echo ""

setup:
	pip3 install scapy rich netmiko napalm nornir nornir-netmiko pyyaml tabulate
	@echo "Dependencies installed."

lab-01:
	sudo containerlab deploy --topo labs/01-ospf-fundamentals/ospf.clab.yml --reconfigure

lab-02:
	sudo containerlab deploy --topo labs/02-static-routing/static.clab.yml --reconfigure

verify-01:
	python3 scripts/verify_ospf.py

capture:
	sudo -E python3 scripts/capture_ospf.py --count 10

security:
	sudo -E python3 scripts/ospf_security_sim.py --dry-run

security-live:
	sudo -E python3 scripts/ospf_security_sim.py

automate:
	python3 scripts/automate_config.py --action collect

automate-push:
	python3 scripts/automate_config.py --action full-cycle

destroy:
	sudo containerlab destroy --all --cleanup

status:
	@docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}"

clean:
	@find . -name "clab-*" -type d -exec rm -rf {} + 2>/dev/null || true
	@find . -name "*.log" -delete 2>/dev/null || true
	@echo "Clean."
