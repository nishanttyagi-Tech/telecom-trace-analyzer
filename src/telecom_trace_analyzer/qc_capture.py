"""QCSuper-inspired Qualcomm DIAG/PCAP workflow helpers.

This module does not implement Qualcomm DIAG transport. It provides safe,
deterministic tooling around PCAP files produced by authorized capture tools
such as QCSuper, QXDM exports, or network probes.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shutil
import subprocess
from typing import Iterable


@dataclass(frozen=True)
class PacketSummary:
    frame: str
    time: str
    source: str
    destination: str
    protocols: str


def find_tshark() -> str:
    """Return the tshark executable or raise a clear error."""
    exe = shutil.which("tshark")
    if not exe:
        raise RuntimeError(
            "tshark was not found. Install Wireshark with the TShark component "
            "and ensure tshark is available on PATH."
        )
    return exe


def pcap_to_json(pcap_path: str | Path) -> list[PacketSummary]:
    """Decode packet metadata from PCAP/PCAPNG using tshark."""
    pcap = Path(pcap_path)
    if not pcap.is_file():
        raise FileNotFoundError(pcap)

    completed = subprocess.run(
        [find_tshark(), "-r", str(pcap), "-T", "json", "-n"],
        check=True,
        capture_output=True,
        text=True,
    )

    import json

    packets = json.loads(completed.stdout or "[]")
    summaries: list[PacketSummary] = []

    for item in packets:
        layers = item.get("_source", {}).get("layers", {})
        frame = layers.get("frame", {})
        summaries.append(
            PacketSummary(
                frame=str(frame.get("frame.number", "")),
                time=str(frame.get("frame.time_relative", "")),
                source=str(frame.get("ip.src", layers.get("ipv6.src", ""))),
                destination=str(frame.get("ip.dst", layers.get("ipv6.dst", ""))),
                protocols=str(frame.get("frame.protocols", "")),
            )
        )

    return summaries


PROTOCOL_FILTERS = {
    "5G SA / NGAP": "ngap",
    "5G NAS": "nas-5gs",
    "5G NR RRC": "nr-rrc",
    "LTE S1AP": "s1ap",
    "LTE NAS": "nas-eps",
    "LTE RRC": "lte-rrc",
    "IMS / SIP": "sip",
    "GTP": "gtp",
    "PFCP": "pfcp",
}


def build_display_filter(selection: Iterable[str]) -> str:
    """Build a Wireshark display filter from known protocol names."""
    return " or ".join(
        PROTOCOL_FILTERS[name] for name in selection if name in PROTOCOL_FILTERS
    )


def launch_wireshark(pcap_path: str | Path, display_filter: str = "") -> None:
    """Open a local PCAP in Wireshark."""
    pcap = Path(pcap_path)
    if not pcap.is_file():
        raise FileNotFoundError(pcap)

    wireshark = shutil.which("wireshark")
    if not wireshark:
        raise RuntimeError(
            "wireshark was not found. Install Wireshark and ensure it is on PATH."
        )

    command = [wireshark, str(pcap)]
    if display_filter.strip():
        command += ["-Y", display_filter.strip()]

    subprocess.Popen(command)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Inspect an authorized telecom PCAP and optionally open it in Wireshark."
    )
    parser.add_argument("pcap", help="PCAP or PCAPNG path")
    parser.add_argument(
        "--protocols",
        nargs="*",
        choices=sorted(PROTOCOL_FILTERS),
        help="Protocol groups to filter when opening Wireshark",
    )
    parser.add_argument("--open", action="store_true", help="Open the PCAP in Wireshark")
    args = parser.parse_args()

    display_filter = build_display_filter(args.protocols or [])
    if args.open:
        launch_wireshark(args.pcap, display_filter)
    else:
        for row in pcap_to_json(args.pcap):
            print(row)
