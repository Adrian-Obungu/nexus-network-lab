#!/bin/bash
set -e

echo "============================================"
echo "  Nexus Network Lab — Environment Bootstrap"
echo "============================================"

echo "[1/4] System dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq curl wget jq net-tools iputils-ping iproute2 tcpdump

echo "[2/4] Containerlab..."
bash -c "$(curl -sL https://get.containerlab.dev)"

echo "[3/4] Python toolchain..."
pip3 install --quiet netmiko napalm nornir nornir-netmiko scapy rich pyyaml tabulate
# Explicit installs for Codespaces that were created before Phase 3
pip3 install --quiet scapy rich 2>/dev/null || true

echo "[4/4] Verifying..."
containerlab version 2>/dev/null && echo "  ✅ Containerlab" || echo "  ⚠️  Containerlab — restart terminal"
python3 -c "import netmiko; print('  ✅ Netmiko')" 2>/dev/null || true
python3 -c "import scapy; print('  ✅ Scapy')" 2>/dev/null || true

echo ""
echo "  Run 'make help' to get started."
echo "============================================"
