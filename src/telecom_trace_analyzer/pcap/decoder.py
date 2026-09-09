"""PCAP decoding adapter using TShark with a raw-SIP fallback."""

from __future__ import annotations

import json
import re
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
    """Flatten Wireshark JSON fields while preserving the accumulator."""
    if result is None:
        result = {}

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


def _packet_metadata(fields: dict[str, Any]) -> tuple[int | None, float | None, str | None, str | None]:
    frame = int(fields["frame.number"]) if fields.get("frame.number") else None
    timestamp = float(fields["frame.time_epoch"]) if fields.get("frame.time_epoch") else None
    source = fields.get("ip.src") or fields.get("ipv6.src")
    destination = fields.get("ip.dst") or fields.get("ipv6.dst")
    return frame, timestamp, source, destination


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


def _decode_payload(value: Any) -> str:
    """Decode a Wireshark byte field into best-effort text."""
    value = _first(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    if not isinstance(value, str):
        return ""

    compact = re.sub(r"[^0-9A-Fa-f]", "", value)
    if len(compact) >= 2 and len(compact) % 2 == 0:
        try:
            raw = bytes.fromhex(compact)
            text = raw.decode("utf-8", errors="ignore")
            if any(token in text for token in ("SIP/2.0", "REGISTER ", "INVITE ", "ACK ", "BYE ", "CANCEL ", "OPTIONS ", "SUBSCRIBE ", "NOTIFY ")):
                return text
        except ValueError:
            pass
    return value


def _raw_sip_from_fields(fields: dict[str, Any]) -> str:
    """Find plaintext SIP in raw_sip or transport payload fields."""
    candidates = [
        fields.get("raw_sip.line"),
        fields.get("udp.payload"),
        fields.get("tcp.payload"),
        fields.get("data.data"),
    ]
    for candidate in candidates:
        text = _decode_payload(candidate)
        if text and ("SIP/2.0" in text or re.search(r"\b(?:REGISTER|INVITE|ACK|BYE|CANCEL|PRACK|UPDATE|SUBSCRIBE|NOTIFY|OPTIONS|REFER)\s+sip:", text)):
            return text
    return ""


def _parse_raw_sip(text: str) -> SipMessage | None:
    """Parse one plaintext SIP message when TShark did not dissect it."""
    lines = text.replace("\r\n", "\n").split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    if not lines:
        return None

    start_line = lines[0].strip()
    request_match = re.match(r"^(REGISTER|INVITE|ACK|BYE|CANCEL|PRACK|UPDATE|SUBSCRIBE|NOTIFY|OPTIONS|REFER)\s+\S+\s+SIP/2\.0$", start_line)
    response_match = re.match(r"^SIP/2\.0\s+(\d{3})(?:\s+(.*))?$", start_line)
    if request_match:
        message_type = "request"
        method = request_match.group(1)
        status_code = None
        reason = None
    elif response_match:
        message_type = "response"
        method = None
        status_code = int(response_match.group(1))
        reason = response_match.group(2) or ""
    else:
        return None

    header_values: dict[str, str] = {}
    for line in lines[1:]:
        if not line.strip():
            break
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        key = name.strip().lower()
        value = value.strip()
        header_values[key] = value

    aliases = {
        "call-id": ("call-id", "i"),
        "cseq": ("cseq",),
        "from": ("from", "f"),
        "to": ("to", "t"),
        "via": ("via", "v"),
        "contact": ("contact", "m"),
        "content-type": ("content-type", "c"),
        "require": ("require",),
        "supported": ("supported", "k"),
        "www-authenticate": ("www-authenticate",),
    }
    headers: dict[str, str] = {}
    for normalized, names in aliases.items():
        for name in names:
            if name in header_values:
                headers[normalized] = header_values[name]
                break

    body = ""
    if "\n\n" in text:
        body = text.split("\n\n", 1)[1]

    return SipMessage(
        start_line=start_line,
        message_type=message_type,
        method=method,
        status_code=status_code,
        reason=reason,
        headers=headers,
        body=body,
    )


def _run_tshark(tshark: str, path: Path, display_filter: str | None) -> list[dict[str, Any]]:
    command = [tshark, "-n", "-r", str(path)]
    if display_filter:
        command += ["-Y", display_filter]
    command += ["-T", "json"]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return json.loads(result.stdout or "[]")


def decode_sip_messages(pcap_path: str | Path) -> list[SipMessage]:
    """Decode SIP packets using TShark, with a raw-payload fallback."""
    tshark = shutil.which("tshark")
    if not tshark:
        raise TsharkNotFoundError(
            "tshark was not found. Install Wireshark/tshark and make sure it is on PATH."
        )

    path = Path(pcap_path)
    if not path.is_file():
        raise FileNotFoundError(path)

    messages: list[SipMessage] = []
    seen_frames: set[int] = set()

    # Primary path: use TShark's SIP dissector. This is fast and gives rich SIP fields.
    sip_packets = _run_tshark(tshark, path, "sip")
    for packet in sip_packets:
        layers = packet.get("_source", {}).get("layers", {})
        fields = _collect_fields(layers)
        message = _build_message(fields)
        if message is None:
            continue
        message.frame, message.timestamp, message.source, message.destination = _packet_metadata(fields)
        messages.append(message)
        if message.frame is not None:
            seen_frames.add(message.frame)

    # Fallback: some cloud TShark builds/preferences may not dissect every SIP packet.
    # Read all packets and recover plaintext SIP from raw transport payloads.
    all_packets = _run_tshark(tshark, path, None)
    for packet in all_packets:
        layers = packet.get("_source", {}).get("layers", {})
        fields = _collect_fields(layers)
        frame, timestamp, source, destination = _packet_metadata(fields)
        if frame is not None and frame in seen_frames:
            continue

        raw_text = _raw_sip_from_fields(fields)
        if not raw_text:
            continue
        message = _parse_raw_sip(raw_text)
        if message is None:
            continue

        message.frame = frame
        message.timestamp = timestamp
        message.source = source
        message.destination = destination
        messages.append(message)
        if frame is not None:
            seen_frames.add(frame)

    messages.sort(key=lambda message: (message.frame is None, message.frame or 0))
    return messages
