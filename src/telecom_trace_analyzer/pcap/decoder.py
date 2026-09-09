"""PCAP decoding adapter using TShark with raw packet SIP recovery."""

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
    return value[0] if isinstance(value, list) and value else value


def _collect_fields(value: Any, result: dict[str, Any] | None = None) -> dict[str, Any]:
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
        start_line, message_type, status_code, reason = request_line, "request", None, None
    elif status_line:
        parts = status_line.split(" ", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            return None
        method, start_line, message_type = None, status_line, "response"
        status_code, reason = int(parts[1]), parts[2] if len(parts) > 2 else ""
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
    return SipMessage(
        start_line=start_line,
        message_type=message_type,
        method=method,
        status_code=status_code,
        reason=reason,
        headers={key: value for key, value in headers.items() if value is not None},
    )


def _decode_hex(value: str) -> str:
    compact = re.sub(r"[^0-9A-Fa-f]", "", value or "")
    if not compact or len(compact) % 2:
        return ""
    try:
        return bytes.fromhex(compact).decode("utf-8", errors="ignore")
    except ValueError:
        return ""


def _parse_raw_sip(text: str) -> SipMessage | None:
    text = text.replace("\x00", "")
    lines = text.replace("\r\n", "\n").split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    if not lines:
        return None

    start_line = lines[0].strip()
    request_match = re.match(
        r"^(REGISTER|INVITE|ACK|BYE|CANCEL|PRACK|UPDATE|SUBSCRIBE|NOTIFY|OPTIONS|REFER)\s+\S+\s+SIP/2\.0$",
        start_line,
        re.I,
    )
    response_match = re.match(r"^SIP/2\.0\s+(\d{3})(?:\s+(.*))?$", start_line, re.I)
    if request_match:
        message_type, method, status_code, reason = "request", request_match.group(1).upper(), None, None
    elif response_match:
        message_type, method, status_code, reason = "response", None, int(response_match.group(1)), response_match.group(2) or ""
    else:
        return None

    header_values: dict[str, str] = {}
    header_end = None
    for index, line in enumerate(lines[1:], start=1):
        if not line.strip():
            header_end = index
            break
        if ":" in line:
            name, value = line.split(":", 1)
            header_values[name.strip().lower()] = value.strip()

    aliases = {
        "call-id": ("call-id", "i"), "cseq": ("cseq",), "from": ("from", "f"),
        "to": ("to", "t"), "via": ("via", "v"), "contact": ("contact", "m"),
        "content-type": ("content-type", "c"), "require": ("require",),
        "supported": ("supported", "k"), "www-authenticate": ("www-authenticate",),
    }
    headers: dict[str, str] = {}
    for normalized, names in aliases.items():
        for name in names:
            if name in header_values:
                headers[normalized] = header_values[name]
                break

    body = ""
    if header_end is not None:
        body = "\n".join(lines[header_end + 1:])

    return SipMessage(
        start_line=start_line,
        message_type=message_type,
        method=method,
        status_code=status_code,
        reason=reason,
        headers=headers,
        body=body,
    )


def _extract_sip_messages(text: str) -> list[SipMessage]:
    """Extract every SIP message start found in a decoded payload/stream."""
    text = text.replace("\r\n", "\n")
    pattern = re.compile(
        r"^(?:REGISTER|INVITE|ACK|BYE|CANCEL|PRACK|UPDATE|SUBSCRIBE|NOTIFY|OPTIONS|REFER)\s+\S+\s+SIP/2\.0\s*$|^SIP/2\.0\s+\d{3}(?:\s+.*)?$",
        re.I | re.M,
    )
    starts = list(pattern.finditer(text))
    messages: list[SipMessage] = []
    for index, match in enumerate(starts):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(text)
        message = _parse_raw_sip(text[match.start():end])
        if message is not None:
            messages.append(message)
    return messages


def _run_tshark(tshark: str, path: Path, display_filter: str | None) -> list[dict[str, Any]]:
    command = [tshark, "-2", "-n", "-r", str(path)]
    if display_filter:
        command += ["-Y", display_filter]
    command += ["-T", "json"]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return json.loads(result.stdout or "[]")


def _run_raw_json(tshark: str, path: Path) -> list[dict[str, Any]]:
    """Read packet bytes from TShark JSON when transport payload fields are unavailable."""
    command = [tshark, "-2", "-n", "-r", str(path), "-T", "jsonraw", "-x"]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return json.loads(result.stdout or "[]")


def _strings_from_tree(value: Any) -> list[str]:
    found: list[str] = []
    if isinstance(value, str):
        found.append(value)
    elif isinstance(value, dict):
        for child in value.values():
            found.extend(_strings_from_tree(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(_strings_from_tree(child))
    return found


def _raw_packet_candidates(packet: dict[str, Any]) -> list[str]:
    """Return decoded text candidates from raw JSON packet-byte fields."""
    candidates: list[str] = []
    for value in _strings_from_tree(packet):
        # JSONRAW commonly contains hex strings. Decode only plausible byte strings.
        compact = re.sub(r"[^0-9A-Fa-f]", "", value)
        if len(compact) < 20 or len(compact) % 2:
            continue
        text = _decode_hex(compact)
        if "SIP/2.0" in text or re.search(r"\b(?:REGISTER|INVITE|ACK|BYE|CANCEL|PRACK|UPDATE|SUBSCRIBE|NOTIFY|OPTIONS|REFER)\s+sip:", text, re.I):
            candidates.append(text)
    return candidates


def _run_transport_fields(tshark: str, path: Path) -> list[dict[str, str]]:
    fields = [
        "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
        "udp.srcport", "udp.dstport", "@udp.payload",
        "tcp.srcport", "tcp.dstport", "tcp.stream", "tcp.seq", "@tcp.payload",
    ]
    command = [tshark, "-2", "-n", "-r", str(path), "-Y", "udp or tcp", "-T", "fields"]
    for field in fields:
        command += ["-e", field]
    command += ["-E", "separator=|", "-E", "quote=n", "-E", "escape=n", "-E", "occurrence=f"]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    rows: list[dict[str, str]] = []
    for line in result.stdout.splitlines():
        values = line.split("|")
        if len(values) < len(fields):
            values += [""] * (len(fields) - len(values))
        rows.append(dict(zip(fields, values)))
    return rows


def _row_metadata(row: dict[str, str]) -> tuple[int | None, float | None, str | None, str | None]:
    frame = int(row["frame.number"]) if row.get("frame.number") else None
    timestamp = float(row["frame.time_epoch"]) if row.get("frame.time_epoch") else None
    source = row.get("ip.src") or row.get("ipv6.src") or None
    destination = row.get("ip.dst") or row.get("ipv6.dst") or None
    return frame, timestamp, source, destination


def decode_sip_messages(pcap_path: str | Path) -> list[SipMessage]:
    """Decode SIP using TShark and multiple recovery paths."""
    tshark = shutil.which("tshark")
    if not tshark:
        raise TsharkNotFoundError("tshark was not found. Install Wireshark/tshark and make sure it is on PATH.")

    path = Path(pcap_path)
    if not path.is_file():
        raise FileNotFoundError(path)

    messages: list[SipMessage] = []
    seen_frames: set[int] = set()

    try:
        sip_packets = _run_tshark(tshark, path, "sip")
    except subprocess.CalledProcessError:
        sip_packets = []
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

    try:
        rows = _run_transport_fields(tshark, path)
    except subprocess.CalledProcessError:
        rows = []

    for row in rows:
        payload = _decode_hex(row.get("@udp.payload", ""))
        if not payload:
            payload = _decode_hex(row.get("@tcp.payload", ""))
        if not payload:
            continue
        frame, timestamp, source, destination = _row_metadata(row)
        for message in _extract_sip_messages(payload):
            if frame is not None and frame in seen_frames:
                continue
            message.frame, message.timestamp, message.source, message.destination = frame, timestamp, source, destination
            messages.append(message)
            if frame is not None:
                seen_frames.add(frame)

    # Last-resort recovery: scan the actual packet bytes. This handles captures where
    # TShark exposes neither udp.payload nor tcp.payload in the fields interface.
    try:
        raw_packets = _run_raw_json(tshark, path)
    except subprocess.CalledProcessError:
        raw_packets = []

    for packet in raw_packets:
        layers = packet.get("_source", {}).get("layers", {})
        fields = _collect_fields(layers)
        frame, timestamp, source, destination = _packet_metadata(fields)
        if frame is not None and frame in seen_frames:
            continue
        for candidate in _raw_packet_candidates(packet):
            for message in _extract_sip_messages(candidate):
                if frame is not None and frame in seen_frames:
                    break
                message.frame, message.timestamp, message.source, message.destination = frame, timestamp, source, destination
                messages.append(message)
                if frame is not None:
                    seen_frames.add(frame)

    unique: dict[tuple[int | None, str, str | None], SipMessage] = {}
    for message in messages:
        unique[(message.frame, message.start_line, message.call_id)] = message
    result = list(unique.values())
    result.sort(key=lambda message: (message.frame is None, message.frame or 0))
    return result
