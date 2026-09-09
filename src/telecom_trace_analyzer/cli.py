"""Command-line entry point for the first development milestone."""

import argparse
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Telecom Trace Analyzer")
    parser.add_argument("--version", action="version", version="telecom-trace-analyzer 0.1.0")
    parser.add_argument("pcap", nargs="?", type=Path, help="PCAP/PCAPNG file (PCAP engine coming next)")
    args = parser.parse_args()

    if args.pcap:
        print(f"PCAP selected: {args.pcap}")
        print("PCAP decoding is the next implementation milestone.")
    else:
        parser.print_help()
