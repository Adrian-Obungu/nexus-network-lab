<div align="center">
  <img src="https://files.manuscdn.com/user_upload_by_module/session_file/95436842/ODBaHLhKJhAtnvxx.png" width="100%" alt="Nexus Network Lab Banner">
  <br>
  <h1>🌐 Nexus Network Lab</h1>
  <p><i>Infrastructure-as-Code Networking Environment for Mobile & Minimal Workstations</i></p>

  [![Environment: Codespaces](https://img.shields.io/badge/Environment-Codespaces_Ready-success?style=for-the-badge&logo=github)](https://github.com/Adrian-Obungu/nexus-network-lab)
  [![Orchestration: Containerlab](https://img.shields.io/badge/Orchestration-Containerlab-blueviolet?style=for-the-badge&logo=docker)](https://containerlab.dev/)
  [![Routing: FRR](https://img.shields.io/badge/Routing-FRRouting-005571?style=for-the-badge&logo=linux)](https://frrouting.org/)
</div>

---

## 🔬 Overview
**Nexus Network Lab** is a self-contained, containerized network engineering environment designed to bypass the heavy hardware requirements of traditional hypervisors like GNS3 or EVE-NG. Developed with a "Build Slow, Build Sure" philosophy, it allows complex network topologies to be spun up entirely within a GitHub Codespace.

By leveraging **Containerlab** and **FRRouting (FRR)**, this project bridges the gap between legacy CLI configuration and modern DevSecOps practices. It provides an industry-standard routing environment that can be operated seamlessly from an iPad browser or any minimal workstation.

---

## 🚀 Core Architecture

<table align="center">
  <tr>
    <th>Component</th>
    <th>Implementation</th>
    <th>Engineering Value</th>
  </tr>
  <tr>
    <td><b>Topology Orchestration</b></td>
    <td>Containerlab (YAML)</td>
    <td>Declarative infrastructure-as-code; reproducible network states without VM overhead.</td>
  </tr>
  <tr>
    <td><b>Routing Engine</b></td>
    <td>FRRouting (FRR)</td>
    <td>Open-source implementation of OSPF, BGP, and IS-IS with a Cisco/Huawei-like VTY shell.</td>
  </tr>
  <tr>
    <td><b>State Verification</b></td>
    <td>Python Subprocess</td>
    <td>Automated assertion of LSDB synchronization, routing tables, and end-to-end reachability.</td>
  </tr>
  <tr>
    <td><b>Environment Isolation</b></td>
    <td>Docker-in-Docker</td>
    <td>Zero local dependencies; guarantees a consistent runtime across any hardware.</td>
  </tr>
</table>

---

## 📊 Available Topologies

The repository currently supports the following modular lab environments:

- **Lab 01: OSPF Fundamentals**: A dual-router Area 0 backbone demonstrating Hello/Dead timer tuning, Router ID election, and Link-State Database (LSDB) synchronization.
- **Lab 02: Static Routing**: A three-router chain focusing on next-hop resolution, administrative distance, and exit-interface routing mechanics.

---

## 🛠️ Deployment & Execution

### Minimal Environment Setup
Designed to run flawlessly on GitHub Codespaces free tier.

1. Launch a new Codespace from the `main` branch.
2. The `.devcontainer` configuration will automatically install Docker, Containerlab, and the Python networking toolchain.

### Lab Orchestration
```bash
# View available deployment targets
make help

# Spin up the OSPF Area 0 topology
make lab-01

# Verify running FRR containers
make status
```

### Manual Verification (Optional)
If you want to inspect the live FRR shell directly, use the correct container names as shown in `make status`:

```bash
# Connect to R1's VTY shell
docker exec -it clab-ospf-lab-R1 vtysh

# Inside vtysh — run these commands:
show ip ospf neighbor
show ip ospf database
show ip route
exit
```

> **Note:** Container names follow the pattern `clab-{topology-name}-{node-name}`. The topology name is defined by the `name:` field in the `.clab.yml` file — in this case `ospf-lab`, not `ospf-fundamentals`.

### Automated Verification
The recommended approach — runs 6 deterministic checks and prints a pass/fail matrix:

```bash
make verify-01
```

---

## 🗺️ Enhancement Roadmap
- [x] **Containerlab Integration**: Base orchestration and FRR image pulling.
- [x] **OSPF Baseline**: Area 0 adjacency and automated verification script.
- [x] **Documentation Sync**: Zettelkasten-formatted lab notes for Obsidian integration.
- [ ] **Netmiko Abstraction**: Migrate verification scripts from `subprocess` to remote SSH automation.
- [ ] **BGP Topologies**: Multi-AS eBGP/iBGP labs with route reflection.
- [ ] **Security Simulation**: Scapy-driven OSPF rogue LSA injection scenarios.

---

## ⚖️ License & Ethics
Distributed under the **MIT License**. This environment is built for network engineering research, automation testing, and portfolio demonstration. 

**Architected by 🧠 and 💻 [Adrian S. Obungu](https://github.com/Adrian-Obungu)**
