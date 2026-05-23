#!/usr/bin/env python3
"""
capture_ospf.py
Cybersecurity Module — OSPF Packet Capture & Analysis
Author: Adrian S. Obungu

Captures live OSPF Hello packets on the transit link between R1 and R2,
parses their fields, and presents a forensic breakdown of the OSPF
Hello exchange.

Architecture:
    1. Get the container PID via 'docker inspect'
    2. Use 'sudo nsenter -t <PID> -n tcpdump ...' to capture inside
       the container's network namespace (proven working approach)
    3. Parse the resulting pcap with Scapy in userspace

Usage:
    python3 scripts/capture_ospf.py --count 5
    python3 scripts/capture_ospf.py --count 10 --pcap captures/ospf.pcap
"""

import argparse
import os
import subprocess
import sys
import tempfile
from datetime import datetime

try:
    from scapy.all import rdpcap, IP
    from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello
    SCAPY = True
except ImportError:
    SCAPY = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    RICH = True
except ImportError:
    RICH = False

OSPF_TYPES = {1: "Hello", 2: "DBD", 3: "LSR", 4: "LSU", 5: "LSAck"}
CONTAINER = "clab-ospf-lab-R1"
IFACE = "eth1"


def get_container_pid(container: str) -> str:
    """Get the PID of a running container."""
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{.State.Pid}}", container],
        capture_output=True, text=True
    )
    pid = result.stdout.strip()
    if result.returncode != 0 or not pid or pid == "0":
        return ""
    return pid


def capture(pid: str, iface: str, count: int, pcap_path: str) -> bool:
    """
    Capture OSPF packets using nsenter into the container network namespace.
    This is the exact approach proven to work manually:
        sudo nsenter -t <PID> -n tcpdump -i eth1 -c <N> proto ospf -w <path>
    """
    cmd = [
        "sudo", "nsenter", "-t", pid, "-n",
        "tcpdump", "-i", iface, "-c", str(count), "-w", pcap_path,
        "proto", "ospf"
    ]

    if RICH:
        console = Console()
        console.print(f"\n[bold cyan]OSPF Packet Capture[/bold cyan]")
        console.print(f"  Container PID : {pid}")
        console.print(f"  Interface     : {iface}")
        console.print(f"  Packet count  : {count}")
        console.print(f"  Output        : {pcap_path}")
        console.print(f"  Waiting for OSPF Hello packets (10s interval)...\n")
    else:
        print(f"\nCapturing {count} OSPF packets on {iface} (PID {pid})")
        print(f"Waiting for Hello packets (10s interval)...")

    try:
        # Timeout: count * 12s (Hello every 10s + buffer)
        timeout_s = max(count * 12, 30)
        result = subprocess.run(cmd, timeout=timeout_s, capture_output=True, text=True)
        if result.returncode != 0 and result.stderr:
            print(f"tcpdump stderr: {result.stderr.strip()}")
    except subprocess.TimeoutExpired:
        # tcpdump may still have written partial data
        pass

    return os.path.exists(pcap_path) and os.path.getsize(pcap_path) > 24


def parse_pcap(pcap_path: str) -> list:
    """Parse captured pcap and extract OSPF fields."""
    if not SCAPY:
        print(f"\nScapy not available. Raw pcap saved to: {pcap_path}")
        print("Install scapy: pip3 install scapy")
        print("Then analyse manually: python3 -c \"from scapy.all import *; pkts=rdpcap('{}')\".format(pcap_path)")
        return []

    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"Error reading pcap: {e}")
        return []

    parsed = []
    for pkt in packets:
        record = {
            "timestamp":      datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S.%f")[:-3],
            "src_ip":         pkt[IP].src if pkt.haslayer(IP) else "N/A",
            "dst_ip":         pkt[IP].dst if pkt.haslayer(IP) else "N/A",
            "ospf_type":      "Unknown",
            "router_id":      "N/A",
            "area_id":        "N/A",
            "hello_interval": "N/A",
            "dead_interval":  "N/A",
            "neighbors":      "N/A",
        }
        if pkt.haslayer(OSPF_Hdr):
            hdr = pkt[OSPF_Hdr]
            record["ospf_type"]  = OSPF_TYPES.get(hdr.type, f"Type-{hdr.type}")
            record["router_id"]  = str(hdr.src)
            record["area_id"]    = str(hdr.area)
        if pkt.haslayer(OSPF_Hello):
            hello = pkt[OSPF_Hello]
            record["hello_interval"] = str(hello.hellointerval)
            record["dead_interval"]  = str(hello.deadinterval)
            if hasattr(hello, "neighbors") and hello.neighbors:
                record["neighbors"] = str(hello.neighbors)
            else:
                record["neighbors"] = "None (waiting)"
        parsed.append(record)
    return parsed


def display(parsed: list) -> None:
    """Display forensic analysis."""
    if not parsed:
        return

    if RICH:
        console = Console()
        console.print(Panel(
            f"[bold]Captured {len(parsed)} OSPF packets[/bold]\n"
            f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            title="OSPF Forensic Analysis",
            border_style="cyan"
        ))

        table = Table(show_lines=True)
        table.add_column("Time", style="dim", min_width=12)
        table.add_column("Source IP", min_width=14)
        table.add_column("Type", style="bold cyan", min_width=8)
        table.add_column("Router ID", min_width=12)
        table.add_column("Area", min_width=8)
        table.add_column("Hello(s)", justify="center", min_width=7)
        table.add_column("Dead(s)", justify="center", min_width=7)
        table.add_column("Neighbors", min_width=15)

        for p in parsed:
            table.add_row(
                p["timestamp"], p["src_ip"], p["ospf_type"],
                p["router_id"], p["area_id"],
                p["hello_interval"], p["dead_interval"], p["neighbors"]
            )
        console.print(table)

        # Security baseline
        router_ids = {p["router_id"] for p in parsed if p["router_id"] != "N/A"}
        hello_intervals = {p["hello_interval"] for p in parsed if p["hello_interval"] != "N/A"}
        console.print("\n[bold]Security Baseline:[/bold]")
        console.print(f"  Unique Router IDs observed : {router_ids}")
        console.print(f"  Hello intervals observed   : {hello_intervals}")
        if len(router_ids) > 2:
            console.print("  [red]WARNING: Unexpected Router IDs detected — possible rogue OSPF speaker.[/red]")
        else:
            console.print("  [green]No anomalies detected. Baseline established.[/green]")
    else:
        print(f"\n{'='*60}")
        print(f"  OSPF Forensic Analysis — {len(parsed)} packets captured")
        print(f"{'='*60}")
        for p in parsed:
            print(f"  [{p['timestamp']}] {p['src_ip']:>15} -> {p['dst_ip']:>15} "
                  f"| {p['ospf_type']:<6} | RID: {p['router_id']:<12} "
                  f"| Hello: {p['hello_interval']}s | Dead: {p['dead_interval']}s")
        print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(description="Capture and analyse OSPF packets")
    parser.add_argument("--count", type=int, default=5, help="Number of packets to capture")
    parser.add_argument("--container", type=str, default=CONTAINER, help="Container name")
    parser.add_argument("--interface", type=str, default=IFACE, help="Interface inside container")
    parser.add_argument("--pcap", type=str, default=None, help="Save pcap to this path")
    args = parser.parse_args()

    # Step 1: Get container PID
    pid = get_container_pid(args.container)
    if not pid:
        print(f"Error: Container '{args.container}' is not running.")
        print("Start the lab first: make lab-01")
        sys.exit(1)

    # Step 2: Determine pcap output path
    if args.pcap:
        os.makedirs(os.path.dirname(args.pcap) if os.path.dirname(args.pcap) else ".", exist_ok=True)
        pcap_path = args.pcap
        keep = True
    else:
        tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        pcap_path = tmp.name
        tmp.close()
        keep = False

    # Step 3: Capture
    success = capture(pid, args.interface, args.count, pcap_path)
    if not success:
        print("\nCapture failed. Troubleshooting:")
        print(f"  1. Verify lab is running: docker inspect --format '{{{{.State.Running}}}}' {args.container}")
        print(f"  2. Verify interface exists: docker exec {args.container} ip link show")
        print(f"  3. Verify OSPF is active: docker exec {args.container} vtysh -c 'show ip ospf neighbor'")
        print(f"  4. Manual test: sudo nsenter -t {pid} -n tcpdump -i {args.interface} -c 2 proto ospf -w /tmp/manual.pcap")
        if not keep and os.path.exists(pcap_path):
            os.unlink(pcap_path)
        sys.exit(1)

    # Step 4: Parse and display
    parsed = parse_pcap(pcap_path)
    display(parsed)

    if keep:
        print(f"\nPcap saved: {pcap_path}")
    elif os.path.exists(pcap_path):
        os.unlink(pcap_path)


if __name__ == "__main__":
    main()
