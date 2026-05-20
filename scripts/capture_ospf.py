#!/usr/bin/env python3
"""
capture_ospf.py
Cybersecurity Module — OSPF Packet Capture & Analysis
Author: Adrian S. Obungu

Captures live OSPF Hello packets on the transit link between R1 and R2,
parses their fields, and presents a forensic breakdown of the OSPF
Hello exchange. This demonstrates the intersection of network engineering
and security analysis — understanding what legitimate OSPF traffic looks
like is a prerequisite for detecting anomalies.

Usage (from within the Codespace):
    # Capture 10 OSPF Hello packets on the R1-R2 transit link
    sudo python3 scripts/capture_ospf.py --count 10

    # Capture with a timeout instead of a packet count
    sudo python3 scripts/capture_ospf.py --timeout 30

    # Save raw pcap for later analysis in Wireshark
    sudo python3 scripts/capture_ospf.py --count 5 --pcap captures/ospf_hello.pcap

Requirements:
    pip3 install scapy rich
"""

import argparse
import os
import sys
import time
from datetime import datetime

try:
    from scapy.all import (
        sniff, wrpcap, IP, OSPF_Hdr, OSPF_Hello,
        conf, get_if_list
    )
except ImportError:
    print("Error: scapy not installed. Run: pip3 install scapy")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    RICH = True
except ImportError:
    RICH = False

# OSPF uses protocol number 89 and multicast 224.0.0.5 (AllSPFRouters)
OSPF_FILTER = "proto ospf"
OSPF_MULTICAST = "224.0.0.5"

# OSPF packet type codes
OSPF_TYPES = {
    1: "Hello",
    2: "Database Description (DBD)",
    3: "Link State Request (LSR)",
    4: "Link State Update (LSU)",
    5: "Link State Acknowledgement (LSAck)"
}


def find_transit_interface() -> str:
    """
    Identify the veth interface connecting to the Containerlab bridge.
    In a Codespace with Docker-in-Docker, the transit link between R1 and R2
    is bridged via a veth pair. We look for interfaces that carry OSPF traffic.
    """
    interfaces = get_if_list()
    # Filter out loopback and docker0
    candidates = [i for i in interfaces if i not in ("lo", "docker0") and not i.startswith("br-")]
    if candidates:
        return candidates[0]
    return "eth0"


def parse_ospf_packet(pkt) -> dict:
    """Extract forensic fields from a captured OSPF packet."""
    result = {
        "timestamp": datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S.%f")[:-3],
        "src_ip": pkt[IP].src if pkt.haslayer(IP) else "N/A",
        "dst_ip": pkt[IP].dst if pkt.haslayer(IP) else "N/A",
        "ospf_type": "Unknown",
        "router_id": "N/A",
        "area_id": "N/A",
        "hello_interval": "N/A",
        "dead_interval": "N/A",
        "neighbors": "N/A",
        "dr": "N/A",
        "bdr": "N/A",
        "network_mask": "N/A"
    }

    if pkt.haslayer(OSPF_Hdr):
        hdr = pkt[OSPF_Hdr]
        result["ospf_type"] = OSPF_TYPES.get(hdr.type, f"Unknown ({hdr.type})")
        result["router_id"] = hdr.src
        result["area_id"] = hdr.area

    if pkt.haslayer(OSPF_Hello):
        hello = pkt[OSPF_Hello]
        result["hello_interval"] = str(hello.hellointerval)
        result["dead_interval"] = str(hello.deadinterval)
        result["dr"] = hello.router if hasattr(hello, "router") else str(hello.dr)
        result["bdr"] = str(hello.bdr)
        result["network_mask"] = str(hello.mask)
        # Extract neighbor list
        if hasattr(hello, "neighbors") and hello.neighbors:
            result["neighbors"] = str(hello.neighbors)
        elif hasattr(hello, "payload") and hello.payload:
            result["neighbors"] = "Present (raw)"
        else:
            result["neighbors"] = "None (waiting)"

    return result


def display_results(packets: list, parsed: list) -> None:
    """Print a forensic analysis table of captured OSPF packets."""
    if RICH:
        console = Console()
        console.print(Panel(
            f"[bold]Captured {len(parsed)} OSPF packets[/bold]\n"
            f"Filter: {OSPF_FILTER}\n"
            f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            title="OSPF Packet Capture — Forensic Analysis",
            border_style="cyan"
        ))

        table = Table(show_lines=True)
        table.add_column("Time", style="dim", min_width=12)
        table.add_column("Source IP", min_width=14)
        table.add_column("Type", style="bold cyan", min_width=10)
        table.add_column("Router ID", min_width=12)
        table.add_column("Area", min_width=8)
        table.add_column("Hello Int.", justify="center", min_width=10)
        table.add_column("Dead Int.", justify="center", min_width=10)
        table.add_column("Neighbors", min_width=15)

        for p in parsed:
            table.add_row(
                p["timestamp"],
                p["src_ip"],
                p["ospf_type"],
                p["router_id"],
                p["area_id"],
                p["hello_interval"],
                p["dead_interval"],
                p["neighbors"]
            )

        console.print(table)

        # Security analysis summary
        router_ids = set(p["router_id"] for p in parsed if p["router_id"] != "N/A")
        hello_intervals = set(p["hello_interval"] for p in parsed if p["hello_interval"] != "N/A")

        console.print("\n[bold]Security Baseline Analysis:[/bold]")
        console.print(f"  Unique Router IDs observed: {router_ids}")
        console.print(f"  Hello intervals in use: {hello_intervals}")

        if len(router_ids) > 2:
            console.print("  [red]⚠️  WARNING: More than 2 Router IDs detected on a point-to-point link.[/red]")
            console.print("  [red]     This may indicate a rogue OSPF speaker.[/red]")
        else:
            console.print("  [green]✅ Expected Router IDs only. No anomalies detected.[/green]")

    else:
        print(f"\nCaptured {len(parsed)} OSPF packets")
        for p in parsed:
            print(f"  [{p['timestamp']}] {p['src_ip']} -> {p['dst_ip']} "
                  f"| Type: {p['ospf_type']} | RID: {p['router_id']} "
                  f"| Hello: {p['hello_interval']}s | Dead: {p['dead_interval']}s")


def main():
    parser = argparse.ArgumentParser(
        description="Capture and analyse OSPF packets on the Containerlab transit link"
    )
    parser.add_argument("--count", type=int, default=5,
                        help="Number of OSPF packets to capture (default: 5)")
    parser.add_argument("--timeout", type=int, default=None,
                        help="Capture timeout in seconds (overrides --count)")
    parser.add_argument("--interface", type=str, default=None,
                        help="Network interface to capture on (auto-detected if omitted)")
    parser.add_argument("--pcap", type=str, default=None,
                        help="Save captured packets to a pcap file")
    args = parser.parse_args()

    iface = args.interface or find_transit_interface()

    if RICH:
        console = Console()
        console.print(f"\n[bold cyan]Starting OSPF capture on interface: {iface}[/bold cyan]")
        console.print(f"  Filter: {OSPF_FILTER}")
        if args.timeout:
            console.print(f"  Mode: timeout ({args.timeout}s)")
        else:
            console.print(f"  Mode: count ({args.count} packets)")
        console.print("  Waiting for OSPF Hello packets...\n")
    else:
        print(f"\nCapturing on {iface} | Filter: {OSPF_FILTER}")

    # Capture
    conf.verb = 0
    if args.timeout:
        packets = sniff(iface=iface, filter=OSPF_FILTER, timeout=args.timeout)
    else:
        packets = sniff(iface=iface, filter=OSPF_FILTER, count=args.count)

    if not packets:
        print("No OSPF packets captured. Ensure the lab is running (make lab-01).")
        sys.exit(1)

    # Parse
    parsed = [parse_ospf_packet(pkt) for pkt in packets]

    # Display
    display_results(packets, parsed)

    # Save pcap if requested
    if args.pcap:
        os.makedirs(os.path.dirname(args.pcap) if os.path.dirname(args.pcap) else ".", exist_ok=True)
        wrpcap(args.pcap, packets)
        print(f"\nPackets saved to: {args.pcap}")
        print("Open in Wireshark for deeper inspection.")


if __name__ == "__main__":
    main()
