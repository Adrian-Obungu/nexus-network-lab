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

Architecture:
    Stage 1 — tcpdump captures raw packets to a temporary pcap file.
               tcpdump runs under sudo (it is pre-installed and permitted).
    Stage 2 — Scapy parses the pcap file in userspace (no raw socket needed).

This two-stage design works within GitHub Codespaces container security
restrictions that prevent setting file capabilities on the Python binary.

Usage (from within the Codespace):
    # Capture 10 OSPF packets and display forensic breakdown
    python3 scripts/capture_ospf.py --count 10

    # Capture for 30 seconds instead of a fixed count
    python3 scripts/capture_ospf.py --timeout 30

    # Save the pcap for later Wireshark analysis
    python3 scripts/capture_ospf.py --count 5 --pcap captures/ospf_hello.pcap

Requirements:
    pip3 install scapy rich
    tcpdump must be installed (pre-installed via devcontainer)
"""

import argparse
import os
import subprocess
import sys
import tempfile
from datetime import datetime

try:
    from scapy.all import rdpcap, IP, OSPF_Hdr, OSPF_Hello
    SCAPY = True
except ImportError:
    SCAPY = False
    print("Warning: scapy not available — raw packet field parsing disabled.")

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    RICH = True
except ImportError:
    RICH = False

# OSPF packet type codes
OSPF_TYPES = {
    1: "Hello",
    2: "DBD",
    3: "LSR",
    4: "LSU",
    5: "LSAck"
}


def find_ospf_interface() -> str:
    """
    Find the network interface carrying OSPF traffic.

    In GitHub Codespaces, Containerlab runs inside Docker. The OSPF transit
    link between R1 and R2 is bridged through a Docker bridge interface
    (br-XXXXXXXX), not through eth0. This function detects the active Docker
    bridge by looking for a 'br-' prefixed interface that is UP and has veth
    pairs attached to it.

    Falls back to 'any' if no bridge is found.
    """
    try:
        result = subprocess.run(
            ["ip", "-o", "link", "show"],
            capture_output=True, text=True, timeout=5
        )
        lines = result.stdout.strip().split("\n")
        # First preference: Docker bridge used by Containerlab (br-XXXXXXXX, state UP)
        for line in lines:
            if "br-" in line and "UP" in line:
                parts = line.split()
                if len(parts) >= 2:
                    iface = parts[1].rstrip(":")
                    if iface.startswith("br-"):
                        return iface
        # Second preference: any bridge interface
        for line in lines:
            parts = line.split()
            if len(parts) >= 2:
                iface = parts[1].rstrip(":")
                if iface.startswith("br-"):
                    return iface
        # Last resort: capture on all interfaces
    except Exception:
        pass
    return "any"


def capture_with_tcpdump(iface: str, count: int, timeout: int, pcap_path: str) -> bool:
    """
    Run tcpdump under sudo to capture OSPF packets to a pcap file.
    Returns True if capture succeeded and produced output.
    """
    cmd = ["sudo", "tcpdump", "-i", iface, "-w", pcap_path, "proto ospf", "-q"]

    if timeout:
        cmd += ["-G", str(timeout), "-W", "1"]
    else:
        cmd += ["-c", str(count)]

    if RICH:
        console = Console()
        console.print(f"\n[bold cyan]Capturing OSPF packets on interface: {iface}[/bold cyan]")
        console.print(f"  Filter: proto ospf | Count: {count} | Output: {pcap_path}")
        console.print("  Waiting for OSPF Hello packets...\n")
    else:
        print(f"\nCapturing on {iface} | proto ospf | count={count}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=(timeout or 60) + 5)
        return os.path.exists(pcap_path) and os.path.getsize(pcap_path) > 24
    except subprocess.TimeoutExpired:
        return os.path.exists(pcap_path) and os.path.getsize(pcap_path) > 24
    except FileNotFoundError:
        print("Error: tcpdump not found. Run: sudo apt-get install -y tcpdump")
        return False


def parse_pcap(pcap_path: str) -> list:
    """Parse the captured pcap file and extract OSPF fields."""
    if not SCAPY:
        print(f"Pcap saved to {pcap_path}. Install scapy to parse fields.")
        return []

    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"Error reading pcap: {e}")
        return []

    parsed = []
    for pkt in packets:
        record = {
            "timestamp": datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S.%f")[:-3],
            "src_ip": pkt[IP].src if pkt.haslayer(IP) else "N/A",
            "dst_ip": pkt[IP].dst if pkt.haslayer(IP) else "N/A",
            "ospf_type": "Unknown",
            "router_id": "N/A",
            "area_id": "N/A",
            "hello_interval": "N/A",
            "dead_interval": "N/A",
            "neighbors": "N/A"
        }

        if pkt.haslayer(OSPF_Hdr):
            hdr = pkt[OSPF_Hdr]
            record["ospf_type"] = OSPF_TYPES.get(hdr.type, f"Type-{hdr.type}")
            record["router_id"] = str(hdr.src)
            record["area_id"] = str(hdr.area)

        if pkt.haslayer(OSPF_Hello):
            hello = pkt[OSPF_Hello]
            record["hello_interval"] = str(hello.hellointerval)
            record["dead_interval"] = str(hello.deadinterval)
            if hasattr(hello, "neighbors") and hello.neighbors:
                record["neighbors"] = str(hello.neighbors)
            else:
                record["neighbors"] = "None (waiting)"

        parsed.append(record)

    return parsed


def display_results(parsed: list) -> None:
    """Display forensic analysis of captured packets."""
    if not parsed:
        print("No OSPF packets parsed.")
        return

    if RICH:
        console = Console()
        console.print(Panel(
            f"[bold]Parsed {len(parsed)} OSPF packets[/bold]\n"
            f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            title="OSPF Packet Capture — Forensic Analysis",
            border_style="cyan"
        ))

        table = Table(show_lines=True)
        table.add_column("Time", style="dim", min_width=12)
        table.add_column("Source IP", min_width=14)
        table.add_column("Type", style="bold cyan", min_width=8)
        table.add_column("Router ID", min_width=12)
        table.add_column("Area", min_width=8)
        table.add_column("Hello", justify="center", min_width=7)
        table.add_column("Dead", justify="center", min_width=7)
        table.add_column("Neighbors", min_width=15)

        for p in parsed:
            table.add_row(
                p["timestamp"], p["src_ip"], p["ospf_type"],
                p["router_id"], p["area_id"],
                p["hello_interval"], p["dead_interval"], p["neighbors"]
            )

        console.print(table)

        # Security baseline check
        router_ids = set(p["router_id"] for p in parsed if p["router_id"] != "N/A")
        hello_intervals = set(p["hello_interval"] for p in parsed if p["hello_interval"] != "N/A")

        console.print("\n[bold]Security Baseline Analysis:[/bold]")
        console.print(f"  Unique Router IDs: {router_ids}")
        console.print(f"  Hello intervals:   {hello_intervals}")

        if len(router_ids) > 2:
            console.print("  [red]⚠  WARNING: More than 2 Router IDs on a point-to-point link.[/red]")
            console.print("  [red]   Possible rogue OSPF speaker detected.[/red]")
        else:
            console.print("  [green]✅ Expected Router IDs only. No anomalies detected.[/green]")
    else:
        print(f"\nCaptured {len(parsed)} OSPF packets")
        for p in parsed:
            print(f"  [{p['timestamp']}] {p['src_ip']} | {p['ospf_type']} | "
                  f"RID: {p['router_id']} | Hello: {p['hello_interval']}s")


def main():
    parser = argparse.ArgumentParser(
        description="Capture and analyse OSPF packets (tcpdump capture + Scapy parse)"
    )
    parser.add_argument("--count", type=int, default=10,
                        help="Number of OSPF packets to capture (default: 10)")
    parser.add_argument("--timeout", type=int, default=None,
                        help="Capture timeout in seconds (overrides --count)")
    parser.add_argument("--interface", type=str, default=None,
                        help="Network interface (auto-detected if omitted)")
    parser.add_argument("--pcap", type=str, default=None,
                        help="Save pcap to this path (optional)")
    args = parser.parse_args()

    iface = args.interface or find_ospf_interface()

    # Use a temp file unless the user specified a path
    if args.pcap:
        os.makedirs(os.path.dirname(args.pcap) if os.path.dirname(args.pcap) else ".", exist_ok=True)
        pcap_path = args.pcap
        keep_pcap = True
    else:
        tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        pcap_path = tmp.name
        tmp.close()
        keep_pcap = False

    success = capture_with_tcpdump(iface, args.count, args.timeout, pcap_path)

    if not success:
        print("Capture failed or no OSPF packets found.")
        print("Ensure the lab is running: make lab-01")
        if not keep_pcap:
            os.unlink(pcap_path)
        sys.exit(1)

    parsed = parse_pcap(pcap_path)
    display_results(parsed)

    if keep_pcap:
        print(f"\nPcap saved: {pcap_path}")
    else:
        os.unlink(pcap_path)


if __name__ == "__main__":
    main()
