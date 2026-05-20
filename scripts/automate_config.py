#!/usr/bin/env python3
"""
automate_config.py
Software Engineering Module — Programmatic Network Configuration & State Collection
Author: Adrian S. Obungu

Demonstrates infrastructure-as-code principles applied to network devices.
Instead of manually typing CLI commands into each router, this script
programmatically pushes configuration changes and collects operational
state across all nodes in the topology.

This mirrors real-world network automation workflows used by:
    - Network Reliability Engineers (NREs) at hyperscalers
    - DevOps teams managing cloud-native network fabrics
    - Managed Service Providers (MSPs) operating multi-tenant environments

The script uses docker exec + vtysh as the transport mechanism (since FRR
containers in Containerlab do not expose SSH by default). In production,
this same logic would use Netmiko, NAPALM, or Nornir over SSH/NETCONF.

Usage:
    # Collect state from all routers
    python3 scripts/automate_config.py --action collect

    # Push a configuration change (add a loopback interface)
    python3 scripts/automate_config.py --action configure

    # Full cycle: configure, verify, rollback
    python3 scripts/automate_config.py --action full-cycle

Requirements:
    pip3 install rich pyyaml
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.syntax import Syntax
    RICH = True
except ImportError:
    RICH = False

# Inventory — defines all managed nodes and their roles
INVENTORY = {
    "R1": {
        "container": "clab-ospf-lab-R1",
        "router_id": "1.1.1.1",
        "role": "Area 0 ABR",
        "interfaces": ["eth1", "eth2"]
    },
    "R2": {
        "container": "clab-ospf-lab-R2",
        "router_id": "2.2.2.2",
        "role": "Area 0 ABR",
        "interfaces": ["eth1", "eth2"]
    }
}

# Configuration template — what we want to push
CONFIG_TEMPLATE = """
configure terminal
interface lo
 ip address {loopback_ip}/32
 ip ospf area 0
exit
router ospf
 network {loopback_ip}/32 area 0
exit
end
write memory
"""

ROLLBACK_TEMPLATE = """
configure terminal
no interface lo
router ospf
 no network {loopback_ip}/32 area 0
exit
end
write memory
"""


def vtysh_exec(container: str, commands: str) -> str:
    """Execute vtysh commands inside a Containerlab container."""
    try:
        result = subprocess.run(
            ["docker", "exec", container, "vtysh", "-c", commands],
            capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return "__TIMEOUT__"
    except FileNotFoundError:
        return "__DOCKER_NOT_FOUND__"


def vtysh_config(container: str, config_block: str) -> str:
    """Push a multi-line configuration block via vtysh."""
    try:
        result = subprocess.run(
            ["docker", "exec", "-i", container, "vtysh"],
            input=config_block, capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return "__TIMEOUT__"


def collect_state() -> dict:
    """Collect operational state from all routers in the inventory."""
    state = {}
    for name, node in INVENTORY.items():
        container = node["container"]
        state[name] = {
            "ospf_neighbors": vtysh_exec(container, "show ip ospf neighbor"),
            "routing_table": vtysh_exec(container, "show ip route"),
            "ospf_database": vtysh_exec(container, "show ip ospf database"),
            "interfaces": vtysh_exec(container, "show interface brief"),
            "running_config": vtysh_exec(container, "show running-config"),
            "collected_at": datetime.now().isoformat()
        }
    return state


def push_config(dry_run: bool = False) -> dict:
    """Push loopback configuration to all routers."""
    results = {}
    loopbacks = {"R1": "1.1.1.1", "R2": "2.2.2.2"}

    for name, node in INVENTORY.items():
        config = CONFIG_TEMPLATE.format(loopback_ip=loopbacks[name])
        if dry_run:
            results[name] = {"status": "DRY_RUN", "config": config.strip()}
        else:
            output = vtysh_config(node["container"], config)
            # Verify the loopback was created
            verify = vtysh_exec(node["container"], "show ip ospf interface lo")
            success = "lo" in verify or "Internet Address" in verify
            results[name] = {
                "status": "SUCCESS" if success else "VERIFY_FAILED",
                "output": output,
                "verification": verify
            }
    return results


def rollback_config() -> dict:
    """Remove the loopback configuration from all routers."""
    results = {}
    loopbacks = {"R1": "1.1.1.1", "R2": "2.2.2.2"}

    for name, node in INVENTORY.items():
        config = ROLLBACK_TEMPLATE.format(loopback_ip=loopbacks[name])
        output = vtysh_config(node["container"], config)
        results[name] = {"status": "ROLLED_BACK", "output": output}
    return results


def display_state(state: dict) -> None:
    """Display collected state in a structured format."""
    if not RICH:
        print(json.dumps(state, indent=2))
        return

    console = Console()
    console.print(Panel(
        f"[bold]Network State Collection[/bold]\n"
        f"Nodes: {', '.join(state.keys())}\n"
        f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        title="Automated State Collection",
        border_style="green"
    ))

    for name, data in state.items():
        console.print(f"\n[bold cyan]━━━ {name} ({INVENTORY[name]['role']}) ━━━[/bold cyan]")

        # OSPF Neighbors
        console.print("[bold]OSPF Neighbors:[/bold]")
        if data["ospf_neighbors"]:
            console.print(Syntax(data["ospf_neighbors"], "text", theme="monokai"))
        else:
            console.print("  [dim]No neighbors[/dim]")

        # Routing table summary
        routes = data["routing_table"].split("\n")
        ospf_routes = [r for r in routes if "O " in r or "O>*" in r]
        console.print(f"[bold]OSPF Routes Learned: {len(ospf_routes)}[/bold]")
        for r in ospf_routes:
            console.print(f"  {r.strip()}")


def display_config_results(results: dict, action: str) -> None:
    """Display configuration push or rollback results."""
    if not RICH:
        print(json.dumps(results, indent=2))
        return

    console = Console()
    table = Table(title=f"Configuration {action.title()} Results", show_lines=True)
    table.add_column("Node", style="bold", min_width=8)
    table.add_column("Status", justify="center", min_width=15)
    table.add_column("Detail", min_width=40)

    for name, data in results.items():
        status = data["status"]
        if status == "SUCCESS":
            style = "[green]SUCCESS[/green]"
        elif status == "DRY_RUN":
            style = "[yellow]DRY RUN[/yellow]"
        elif status == "ROLLED_BACK":
            style = "[cyan]ROLLED BACK[/cyan]"
        else:
            style = f"[red]{status}[/red]"

        detail = data.get("verification", data.get("output", data.get("config", "")))[:80]
        table.add_row(name, style, detail)

    console.print(table)


def main():
    parser = argparse.ArgumentParser(
        description="Programmatic network configuration and state collection"
    )
    parser.add_argument("--action", choices=["collect", "configure", "rollback", "full-cycle"],
                        default="collect",
                        help="Action to perform (default: collect)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be configured without applying")
    args = parser.parse_args()

    if RICH:
        console = Console()

    if args.action == "collect":
        state = collect_state()
        display_state(state)

    elif args.action == "configure":
        if RICH:
            console.print("\n[bold]Pushing loopback configuration to all routers...[/bold]")
        results = push_config(dry_run=args.dry_run)
        display_config_results(results, "push")

    elif args.action == "rollback":
        if RICH:
            console.print("\n[bold]Rolling back loopback configuration...[/bold]")
        results = rollback_config()
        display_config_results(results, "rollback")

    elif args.action == "full-cycle":
        if RICH:
            console.print(Panel(
                "[bold]Full Automation Cycle[/bold]\n"
                "1. Collect pre-change state\n"
                "2. Push configuration\n"
                "3. Verify post-change state\n"
                "4. Rollback\n"
                "5. Verify rollback",
                title="Full Cycle", border_style="magenta"
            ))

        # Step 1: Pre-change
        if RICH:
            console.print("\n[bold]Step 1: Pre-change state collection[/bold]")
        pre_state = collect_state()
        display_state(pre_state)

        # Step 2: Configure
        if RICH:
            console.print("\n[bold]Step 2: Pushing configuration[/bold]")
        config_results = push_config()
        display_config_results(config_results, "push")

        # Step 3: Post-change verification
        if RICH:
            console.print("\n[bold]Step 3: Post-change verification[/bold]")
        import time
        time.sleep(2)
        post_state = collect_state()
        display_state(post_state)

        # Step 4: Rollback
        if RICH:
            console.print("\n[bold]Step 4: Rolling back[/bold]")
        rollback_results = rollback_config()
        display_config_results(rollback_results, "rollback")

        # Step 5: Final verification
        if RICH:
            console.print("\n[bold]Step 5: Final state (should match pre-change)[/bold]")
        time.sleep(2)
        final_state = collect_state()
        display_state(final_state)

        if RICH:
            console.print("\n[green bold]Full cycle complete.[/green bold]\n")


if __name__ == "__main__":
    main()
