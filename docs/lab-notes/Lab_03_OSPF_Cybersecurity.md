# Lab 03: OSPF Cybersecurity & Packet Analysis

**Author:** Adrian S. Obungu
**Environment:** GitHub Codespaces · Containerlab · Scapy

---

## Multidisciplinary Integration: Networking meets Forensics

Routing protocols are inherently trusting. By default, OSPF assumes that any device speaking protocol 89 on the local subnet is a legitimate router. This lab bridges network engineering and cybersecurity by demonstrating how this trust model can be exploited and how such exploits are detected.

### Module 1: Packet Capture & Baseline Analysis

Before detecting an anomaly, you must understand the baseline. The `capture_ospf.py` script uses Scapy to sniff live traffic on the transit link between R1 and R2.

```bash
# Capture 10 OSPF Hello packets and display forensic breakdown
sudo python3 scripts/capture_ospf.py --count 10
```

**What to look for:**
- **Source IP:** Should only be the interface IPs of R1 and R2.
- **Router ID:** Should only be 1.1.1.1 and 2.2.2.2.
- **Hello/Dead Intervals:** Must match exactly (10s/40s).

### Module 2: Rogue LSA Injection Simulation

The `ospf_security_sim.py` script crafts a malicious OSPF Link State Update (LSU) packet. It advertises a rogue network (10.10.10.0/24) originating from a fake Router ID (6.6.6.6).

```bash
# Execute the attack simulation
sudo python3 scripts/ospf_security_sim.py
```

**The Attack Vector:**
1. The script crafts an OSPF Type-1 Router LSA.
2. It sets a high sequence number (`0x80000002`) to ensure the receiving router treats it as a newer, more preferred route.
3. It injects the packet onto the `224.0.0.5` multicast group.
4. R2 receives the packet, processes the LSA, and inserts the rogue network into its routing table.

**Defensive Countermeasures:**
To prevent this attack in production, network engineers must implement **OSPF MD5/SHA Authentication**. When enabled, the router computes a cryptographic hash of the OSPF packet using a pre-shared key. The rogue LSA injected by our script lacks this hash and would be silently dropped by an authenticated interface.

---
**Linked Notes:**
- [[OSPF_Dynamic_Routing]]
- [[Data_Encapsulation_Process]]
- [[Lab_01_OSPF_Procedure]]
