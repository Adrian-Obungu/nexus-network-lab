#!/usr/bin/env python3
"""
verify_ospf.py
Lab 01 — Automated Verification Script
Author: Adrian S. Obungu

Executes commands against running Containerlab nodes via docker exec
and asserts expected network state across five checks:

  1. OSPF neighbour adjacency — Full state on R1
  2. OSPF routing table — R2 LAN learned via OSPF on R1
  3. LSDB — Router LSAs from both 1.1.1.1 and 2.2.2.2
  4. Reverse routing table — R1 LAN learned on R2
  5. End-to-end reachability — PC1 pings PC2

Usage:
    python3 scripts/verify_ospf.py
"""

import subprocess
import sys

try:
    from rich.console import Console
    from rich.table import Table
    RICH = True
except ImportError:
    RICH = False

RESULTS = []


def run(container: str, cmd: str) -> str:
    try:
        out = subprocess.run(
            ["docker", "exec", container, "sh", "-c", cmd],
            capture_output=True, text=True, timeout=10
        )
        return out.stdout.strip()
    except subprocess.TimeoutExpired:
        return "__TIMEOUT__"


def record(name: str, passed: bool, detail: str = "") -> None:
    RESULTS.append({"name": name, "passed": passed, "detail": detail})


def check_adjacency() -> None:
    out = run("clab-ospf-lab-R1", "vtysh -c 'show ip ospf neighbor'")
    ok = "Full" in out
    record("R1 ↔ R2 adjacency in Full state", ok,
           "Full" if ok else f"Not Full — {out[:80]}")


def check_routing_r1() -> None:
    out = run("clab-ospf-lab-R1", "vtysh -c 'show ip route ospf'")
    ok = "192.168.2.0/24" in out
    record("R1 routing table: 192.168.2.0/24 via OSPF", ok,
           "Present" if ok else "Missing")


def check_lsdb() -> None:
    out = run("clab-ospf-lab-R1", "vtysh -c 'show ip ospf database'")
    r1 = "1.1.1.1" in out
    r2 = "2.2.2.2" in out
    record("LSDB: Router LSA 1.1.1.1 (R1)", r1, "Present" if r1 else "Missing")
    record("LSDB: Router LSA 2.2.2.2 (R2)", r2, "Present" if r2 else "Missing")


def check_routing_r2() -> None:
    out = run("clab-ospf-lab-R2", "vtysh -c 'show ip route ospf'")
    ok = "192.168.1.0/24" in out
    record("R2 routing table: 192.168.1.0/24 via OSPF", ok,
           "Present" if ok else "Missing")


def check_e2e() -> None:
    out = run("clab-ospf-lab-PC1", "ping -c 3 -W 2 192.168.2.10")
    ok = "0% packet loss" in out or "3 received" in out
    record("End-to-end: PC1 (192.168.1.10) → PC2 (192.168.2.10)", ok,
           "Reachable" if ok else f"Unreachable — {out[:100]}")


def print_results() -> None:
    passed = sum(1 for r in RESULTS if r["passed"])
    total = len(RESULTS)

    if RICH:
        console = Console()
        table = Table(title="\nLab 01 — OSPF Verification", show_lines=True)
        table.add_column("Check", style="bold white", min_width=50)
        table.add_column("Result", justify="center", min_width=12)
        table.add_column("Detail", min_width=25)
        for r in RESULTS:
            status = "[green]✅ PASS[/green]" if r["passed"] else "[red]❌ FAIL[/red]"
            table.add_row(r["name"], status, r["detail"])
        console.print(table)
        summary = f"\n[bold]{passed}/{total} checks passed.[/bold]"
        if passed == total:
            console.print(summary + " [green]Lab complete.[/green]\n")
        else:
            console.print(summary + " [yellow]Review failed checks.[/yellow]\n")
    else:
        print(f"\nLab 01 — OSPF Verification ({passed}/{total} passed)")
        for r in RESULTS:
            mark = "PASS" if r["passed"] else "FAIL"
            print(f"  [{mark}] {r['name']} — {r['detail']}")
        print()


if __name__ == "__main__":
    try:
        check_adjacency()
        check_routing_r1()
        check_lsdb()
        check_routing_r2()
        check_e2e()
    except Exception as e:
        print(f"Error during verification: {e}")
        sys.exit(1)
    print_results()
