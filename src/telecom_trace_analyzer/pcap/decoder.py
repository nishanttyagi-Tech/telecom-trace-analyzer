"""PCAP decoding adapter using the local tshark installation."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from telecom_trace_analyzer.sip.models import SipMessage


class TsharkNotFoundError(RuntimeError):
    """Raised when tshark is not installed or is not available on PATH."""


def _first(value: Any) -> Any:
    """Return the first value when Wireshark represents a field as a list."""
    return value[0] if isinstance(value, list) and value else value


def _collect_fields(value: Any, result: dict[str, Any] | None = None) -> dict[str, Any]:
    """Flatten Wireshark JSON fields, keeping the first value for each name."""
    result = result or {}
    if isinstance(value, dict):
        for key, child in value.items():
            if key not in result:
                result[key] = _first(child)
            _collect_fields(child, result)
    elif isinstance(value, list):
        for child in value:
            _collect_fields(child, result)
    return result


def _header(fields: dict[str, Any], *names: str) -> str | None:
    for name in names:
        value = fields.get(name)
        if value not in (None, ""):
            return str(value)
    return None


def _build_message(fields: dict[str, Any]) -> SipMessage | None:
    request_line = _header(fields, "sip.Request-Line")
    status_line = _header(fields, "sip.Status-Line")

    if request_line:
        method = request_line.split(" ", 1)[0]
        start_line = request_line
        message_type = "request"
        status_code = None
        reason = None
    elif status_line:
        parts = status_line.split(" ", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            return None
        method = None
        start_line = status_line
        message_type = "response"
        status_code = int(parts[1])
        reason = parts[2] if len(parts) > 2 else ""
    else:
        return None

    headers = {
        "call-id": _header(fields, "sip.Call-ID", "sip.call_id"),
        "cseq": _header(fields, "sip.CSeq"),
        "from": _header(fields, "sip.From"),
        "to": _header(fields, "sip.To"),
        "via": _header(fields, "sip.Via"),
        "contact": _header(fields, "sip.Contact"),
        "content-type": _header(fields, "sip.Content-Type"),
        "require": _header(fields, "sip.Require"),
        "supported": _header(fields, "sip.Supported"),
        "www-authenticate": _header(fields, "sip.WWW-Authenticate"),
    }
    headers = {key: value for key, value in headers.items() if value is not None}

    return SipMessage(
        start_line=start_line,
        message_type=message_type,
        method=method,
        status_code=status_code,
        reason=reason,
        headers=headers,
    )


def decode_sip_messages(pcap_path: str | Path) -> list[SipMessage]:
    """Decode SIP packets from a PCAP/PCAPNG file using tshark JSON output."""
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
        fields = _collect_fields(layers)
        message = _build_message(fields)
        if message is None:
            continue

        message.frame = int(fields["frame.number"]) if fields.get("frame.number") else None
        message.timestamp = float(fields["frame.time_epoch"]) if fields.get("frame.time_epoch") else None
        message.source = fields.get("ip.src") or fields.get("ipv6.src")
        message.destination = fields.get("ip.dst") or fields.get("ipv6.dst")
        messages.append(message)

    return messages
