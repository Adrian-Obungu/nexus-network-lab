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
    Stage 1 — tcpdump runs inside the R1 container via 'docker exec'.
               The container has its own network namespace where OSPF
               traffic is visible on eth1 (the transit link to R2).
               Output is written to a temporary pcap file on the host.
    Stage 2 — Scapy parses the pcap file in userspace.

This design works within GitHub Codespaces constraints: no raw socket
capability on the host Python binary is required, and no filesystem
restriction applies because we capture inside the container namespace.

Usage:
    python3 scripts/capture_ospf.py --count 10
    python3 scripts/capture_ospf.py --count 5 --pcap captures/ospf_hello.pcap

Requirements:
    pip3 install scapy rich
    Lab must be running: make lab-01
"""

import argparse
import os
import subprocess
import sys
import tempfile
from datetime import datetime

# OSPF_Hdr and OSPF_Hello live in scapy.contrib.ospf, not scapy.all
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

# Containerlab container name for R1 (matches ospf.clab.yml topology name)
R1_CONTAINER = "clab-ospf-lab-R1"
# Interface inside R1 that connects to R2.
# Confirmed from live topology: 'Created link: R1:eth1 ▪┄┄▪ R2:eth1'
# eth0 is the Containerlab management interface, eth1 is the transit link.
TRANSIT_IFACE = "eth1"


def container_running(name: str) -> bool:
    """Check whether the named container is running."""
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{.State.Running}}", name],
        capture_output=True, text=True
    )
    return result.stdout.strip() == "true"


def capture_inside_container(container: str, iface: str, count: int,
                              timeout: int, pcap_path: str) -> bool:
    """
    Run tcpdump inside the container's network namespace via docker exec,
    writing the pcap to a path inside the container, then copy it out.

    We write to /tmp/capture.pcap inside the container, then use
    'docker cp' to bring it to the host.
    """
    container_pcap = "/tmp/ospf_capture.pcap"

    # Build the tcpdump command to run inside the container
    tcpdump_cmd = [
        "docker", "exec", container,
        "tcpdump", "-i", iface, "-w", container_pcap,
        "-q", "proto", "ospf"
    ]
    if timeout:
        tcpdump_cmd += ["-G", str(timeout), "-W", "1"]
    else:
        tcpdump_cmd += ["-c", str(count)]

    if RICH:
        console = Console()
        console.print(f"\n[bold cyan]Capturing OSPF packets inside container: {container}[/bold cyan]")
        console.print(f"  Interface: {iface} | Filter: proto ospf | Count: {count}")
        console.print("  Waiting for OSPF Hello packets...\n")
    else:
        print(f"\nCapturing inside {container} on {iface} | count={count}")

    try:
        subprocess.run(
            tcpdump_cmd,
            timeout=(timeout or 30) + 5,
            capture_output=True
        )
    except subprocess.TimeoutExpired:
        pass
    except FileNotFoundError:
        print("Error: docker not found in PATH.")
        return False

    # Copy the pcap out of the container
    cp_result = subprocess.run(
        ["docker", "cp", f"{container}:{container_pcap}", pcap_path],
        capture_output=True, text=True
    )
    if cp_result.returncode != 0:
        # tcpdump may not be installed inside the FRR container
        # Fall back to nsenter approach
        return capture_via_nsenter(container, iface, count, timeout, pcap_path)

    return os.path.exists(pcap_path) and os.path.getsize(pcap_path) > 24


def capture_via_nsenter(container: str, iface: str, count: int,
                        timeout: int, pcap_path: str) -> bool:
    """
    Alternative: use nsenter to enter the container's network namespace
    from the host and run the host's tcpdump there.
    This works even if tcpdump is not installed inside the container.
    """
    # Get the container PID
    pid_result = subprocess.run(
        ["docker", "inspect", "--format", "{{.State.Pid}}", container],
        capture_output=True, text=True
    )
    if pid_result.returncode != 0 or not pid_result.stdout.strip():
        return False

    pid = pid_result.stdout.strip()

    nsenter_cmd = [
        "sudo", "nsenter", "-t", pid, "-n",
        "tcpdump", "-i", iface, "-w", pcap_path,
        "-q", "proto", "ospf"
    ]
    if timeout:
        nsenter_cmd += ["-G", str(timeout), "-W", "1"]
    else:
        nsenter_cmd += ["-c", str(count)]

    if RICH:
        console = Console()
        console.print(f"  [dim]Falling back to nsenter (PID {pid})[/dim]")

    try:
        subprocess.run(nsenter_cmd, timeout=(timeout or 30) + 5, capture_output=True)
    except subprocess.TimeoutExpired:
        pass

    return os.path.exists(pcap_path) and os.path.getsize(pcap_path) > 24


def parse_pcap(pcap_path: str) -> list:
    """Parse the captured pcap and extract OSPF fields."""
    if not SCAPY:
        print(f"Scapy not available. Pcap saved to {pcap_path}.")
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
            "src_ip":        pkt[IP].src if pkt.haslayer(IP) else "N/A",
            "dst_ip":        pkt[IP].dst if pkt.haslayer(IP) else "N/A",
            "ospf_type":     "Unknown",
            "router_id":     "N/A",
            "area_id":       "N/A",
            "hello_interval":"N/A",
            "dead_interval": "N/A",
            "neighbors":     "N/A",
        }
        if pkt.haslayer(OSPF_Hdr):
            hdr = pkt[OSPF_Hdr]
            record["ospf_type"] = OSPF_TYPES.get(hdr.type, f"Type-{hdr.type}")
            record["router_id"] = str(hdr.src)
            record["area_id"]   = str(hdr.area)
        if pkt.haslayer(OSPF_Hello):
            hello = pkt[OSPF_Hello]
            record["hello_interval"] = str(hello.hellointerval)
            record["dead_interval"]  = str(hello.deadinterval)
            record["neighbors"] = (
                str(hello.neighbors) if hasattr(hello, "neighbors") and hello.neighbors
                else "None (waiting)"
            )
        parsed.append(record)
    return parsed


def display_results(parsed: list) -> None:
    """Display forensic analysis table."""
    if not parsed:
        print("No OSPF packets parsed from pcap.")
        return

    if RICH:
        console = Console()
        console.print(Panel(
            f"[bold]Parsed {len(parsed)} OSPF packets[/bold]\n"
            f"Captured: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            title="OSPF Packet Capture — Forensic Analysis",
            border_style="cyan"
        ))
        table = Table(show_lines=True)
        for col, style, width in [
            ("Time",     "dim",       12), ("Source IP", "",         14),
            ("Type",     "bold cyan",  8), ("Router ID", "",         12),
            ("Area",     "",           8), ("Hello",     "center",    7),
            ("Dead",     "center",     7), ("Neighbors", "",         15),
        ]:
            table.add_column(col, style=style if style != "center" else "",
                             justify=style if style == "center" else "left",
                             min_width=width)
        for p in parsed:
            table.add_row(
                p["timestamp"], p["src_ip"], p["ospf_type"],
                p["router_id"], p["area_id"],
                p["hello_interval"], p["dead_interval"], p["neighbors"]
            )
        console.print(table)

        router_ids      = {p["router_id"] for p in parsed if p["router_id"] != "N/A"}
        hello_intervals = {p["hello_interval"] for p in parsed if p["hello_interval"] != "N/A"}
        console.print("\n[bold]Security Baseline:[/bold]")
        console.print(f"  Unique Router IDs : {router_ids}")
        console.print(f"  Hello intervals   : {hello_intervals}")
        if len(router_ids) > 2:
            console.print("  [red]⚠  WARNING: Unexpected Router IDs — possible rogue OSPF speaker.[/red]")
        else:
            console.print("  [green]✅ No anomalies detected.[/green]")
    else:
        print(f"\nCaptured {len(parsed)} OSPF packets")
        for p in parsed:
            print(f"  [{p['timestamp']}] {p['src_ip']} | {p['ospf_type']} | "
                  f"RID: {p['router_id']} | Hello: {p['hello_interval']}s")


def main():
    parser = argparse.ArgumentParser(
        description="Capture OSPF packets inside the R1 container and analyse forensically"
    )
    parser.add_argument("--count",     type=int, default=10)
    parser.add_argument("--timeout",   type=int, default=None)
    parser.add_argument("--container", type=str, default=R1_CONTAINER)
    parser.add_argument("--interface", type=str, default=TRANSIT_IFACE)
    parser.add_argument("--pcap",      type=str, default=None)
    args = parser.parse_args()

    if not container_running(args.container):
        print(f"Error: container '{args.container}' is not running.")
        print("Start the lab first: make lab-01")
        sys.exit(1)

    if args.pcap:
        os.makedirs(os.path.dirname(args.pcap) if os.path.dirname(args.pcap) else ".", exist_ok=True)
        pcap_path  = args.pcap
        keep_pcap  = True
    else:
        tmp        = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        pcap_path  = tmp.name
        tmp.close()
        keep_pcap  = False

    success = capture_inside_container(
        args.container, args.interface, args.count, args.timeout, pcap_path
    )

    if not success:
        print("Capture failed or no OSPF packets found on the transit link.")
        print(f"Container: {args.container}  |  Interface: {args.interface}")
        if not keep_pcap and os.path.exists(pcap_path):
            os.unlink(pcap_path)
        sys.exit(1)

    parsed = parse_pcap(pcap_path)
    display_results(parsed)

    if keep_pcap:
        print(f"\nPcap saved: {pcap_path}")
    elif os.path.exists(pcap_path):
        os.unlink(pcap_path)


if __name__ == "__main__":
    main()
