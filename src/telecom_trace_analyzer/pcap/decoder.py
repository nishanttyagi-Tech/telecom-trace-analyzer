"""PCAP decoding adapter using the local tshark installation."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from telecom_trace_analyzer.sip.models import SipMessage
from telecom_trace_analyzer.sip.parser import parse_sip_message


class TsharkNotFoundError(RuntimeError):
    """Raised when tshark is not installed or is not available on PATH."""


def _first(value: Any) -> Any:
    """Return the first value when Wireshark represents a field as a list."""
    return value[0] if isinstance(value, list) and value else value


def _walk_fields(value: Any, names: set[str]) -> dict[str, Any]:
    """Find selected field names in Wireshark's nested JSON representation."""
    found: dict[str, Any] = {}
    if isinstance(value, dict):
        for key, child in value.items():
            if key in names and key not in found:
                found[key] = _first(child)
            found.update({k: v for k, v in _walk_fields(child, names).items() if k not in found})
    elif isinstance(value, list):
        for child in value:
            found.update({k: v for k, v in _walk_fields(child, names).items() if k not in found})
    return found


def decode_sip_messages(pcap_path: str | Path) -> list[SipMessage]:
    """Decode SIP packets from a PCAP/PCAPNG file using tshark's JSON output.

    This adapter deliberately keeps packet decoding separate from SIP analysis.
    It is therefore replaceable later if another decoder is needed.
    """
    tshark = shutil.which("tshark")
    if not tshark:
        raise TsharkNotFoundError(
            "tshark was not found. Install Wireshark/tshark and make sure it is on PATH."
        )

    path = Path(pcap_path)
    if not path.is_file():
        raise FileNotFoundError(path)

    result = subprocess.run(
        [tshark, "-r", str(path), "-Y", "sip", "-T", "json"],
        check=True,
        capture_output=True,
        text=True,
    )
    packets = json.loads(result.stdout or "[]")
    messages: list[SipMessage] = []

    for packet in packets:
        layers = packet.get("_source", {}).get("layers", {})
        fields = _walk_fields(layers, {
            "frame.number", "frame.time_epoch", "ip.src", "ipv6.src",
            "ip.dst", "ipv6.dst", "sip.Request-Line", "sip.Status-Line",
            "sip.msg_hdr", "sip.msg_body",
        })

        start_line = fields.get("sip.Request-Line") or fields.get("sip.Status-Line")
        if not start_line:
            continue

        try:
            message = parse_sip_message(str(start_line))
        except ValueError:
            # Wireshark already decoded the packet; keep this adapter tolerant of
            # unusual SIP dissector output until packet fixtures are expanded.
            continue

        message.frame = int(fields["frame.number"]) if fields.get("frame.number") else None
        message.timestamp = float(fields["frame.time_epoch"]) if fields.get("frame.time_epoch") else None
        message.source = fields.get("ip.src") or fields.get("ipv6.src")
        message.destination = fields.get("ip.dst") or fields.get("ipv6.dst")
        messages.append(message)

    return messages
