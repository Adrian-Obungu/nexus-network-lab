# ============================================================
#  Nexus Network Lab — Makefile
#  Author: Adrian S. Obungu
# ============================================================

.PHONY: help lab-01 lab-02 destroy status clean verify-01

SHELL := /bin/bash

help:
	@echo ""
	@echo "  Nexus Network Lab"
	@echo "  ─────────────────────────────────────────"
	@echo "  make lab-01      Deploy Lab 01: OSPF Fundamentals"
	@echo "  make lab-02      Deploy Lab 02: Static Routing"
	@echo "  make verify-01   Run automated OSPF verification"
	@echo "  make destroy     Tear down all running labs"
	@echo "  make status      Show running containers"
	@echo "  make clean       Remove lab artefacts"
	@echo ""

lab-01:
	sudo containerlab deploy --topo labs/01-ospf-fundamentals/ospf.clab.yml --reconfigure

lab-02:
	sudo containerlab deploy --topo labs/02-static-routing/static.clab.yml --reconfigure

verify-01:
	python3 scripts/verify_ospf.py

destroy:
	sudo containerlab destroy --all --cleanup

status:
	@docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}"

clean:
	@find . -name "clab-*" -type d -exec rm -rf {} + 2>/dev/null || true
	@find . -name "*.log" -delete 2>/dev/null || true
	@echo "Clean."
