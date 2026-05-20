# Lab 04: Infrastructure as Code — Network Automation

**Author:** Adrian S. Obungu
**Environment:** GitHub Codespaces · Python

---

## The Shift from CLI to Code

In modern infrastructure, logging into individual routers via SSH or console to type commands is considered an anti-pattern. It is slow, prone to human error, and difficult to audit. This lab introduces **programmatic configuration management** using Python.

### The Automation Script: `automate_config.py`

This script abstracts the underlying CLI syntax. It defines the desired state (a loopback interface) and pushes it to all nodes in the inventory simultaneously.

```bash
# Step 1: Collect current state (routing tables, neighbors)
python3 scripts/automate_config.py --action collect

# Step 2: Push new configuration (creates loopbacks)
python3 scripts/automate_config.py --action configure

# Step 3: Rollback changes
python3 scripts/automate_config.py --action rollback
```

### Engineering Value

1. **Idempotency & Dry Runs:** The script supports `--dry-run`, allowing engineers to see exactly what configuration will be applied before touching the live network.
2. **State Verification:** After pushing the configuration, the script automatically runs verification commands (`show ip ospf interface lo`) to assert that the desired state was achieved.
3. **Automated Rollback:** If a change causes an outage, the `rollback` action immediately reverts the configuration, minimizing Mean Time To Recovery (MTTR).

In a production environment, this script would run in a CI/CD pipeline (like GitHub Actions). When a network engineer merges a pull request containing a configuration change, the pipeline executes the script to push the change to the routers.

---
**Linked Notes:**
- [[VRP_Command_Line_Interface]]
- [[Lab_01_OSPF_Procedure]]
