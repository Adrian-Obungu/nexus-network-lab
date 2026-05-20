# Lab 01: OSPF Area 0 — Procedure and Observations

**Author:** Adrian S. Obungu
**Environment:** GitHub Codespaces · Containerlab · FRRouting

---

## Topology Summary

| Device | Interface | Address | OSPF Role |
| :--- | :--- | :--- | :--- |
| R1 | eth1 (Transit) | 10.0.1.1/30 | Area 0 Active |
| R1 | eth2 (LAN) | 192.168.1.1/24 | Area 0 Passive |
| R2 | eth1 (Transit) | 10.0.1.2/30 | Area 0 Active |
| R2 | eth2 (LAN) | 192.168.2.1/24 | Area 0 Passive |
| PC1 | eth1 | 192.168.1.10/24 | End Host |
| PC2 | eth1 | 192.168.2.10/24 | End Host |

---

## Deployment

```bash
make lab-01
```

---

## Verification Sequence

```bash
# Step 1 — Confirm adjacency (note: container name = clab-{topology-name}-{node-name})
docker exec -it clab-ospf-lab-R1 vtysh -c 'show ip ospf neighbor'

# Step 2 — Inspect LSDB
docker exec -it clab-ospf-lab-R1 vtysh -c 'show ip ospf database'

# Step 3 — Confirm routing table
docker exec -it clab-ospf-lab-R1 vtysh -c 'show ip route'

# Step 4 — End-to-end ping
docker exec -it clab-ospf-lab-PC1 ping -c 4 192.168.2.10

# Step 5 — Automated matrix
python3 scripts/verify_ospf.py
```

---

## Key Observations

The transit link uses a /30 subnet (10.0.1.0/30), providing exactly two usable host addresses — one per router. This is standard practice for point-to-point links as it eliminates wasted address space and removes the possibility of a Designated Router (DR) election on the segment.

Both LAN-facing interfaces are configured as OSPF passive. A passive interface participates in OSPF (its network is advertised) but does not send or receive Hello packets. This prevents end hosts from attempting to form adjacencies and reduces unnecessary OSPF traffic on access segments.

The LSDB on both routers should be identical after convergence. If `show ip ospf database` on R2 does not contain R1's Router LSA (1.1.1.1), the adjacency has not reached Full state and the SPF calculation will be incomplete.

---
**Linked Notes:**
- [[OSPF_Dynamic_Routing]]
- [[IP_Addressing_and_Subnetting]]
- [[VRP_Command_Line_Interface]]
