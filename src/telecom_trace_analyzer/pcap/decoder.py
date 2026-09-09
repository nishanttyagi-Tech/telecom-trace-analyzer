"""PCAP decoding adapter using TShark with transport-payload SIP recovery."""

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
    """Parse one complete plaintext SIP message."""
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
    """Extract every SIP message start found in a payload/stream."""
    text = text.replace("\r\n", "\n")
    starts = list(re.finditer(
        r"(?m)^(?:REGISTER|INVITE|ACK|BYE|CANCEL|PRACK|UPDATE|SUBSCRIBE|NOTIFY|OPTIONS|REFER)\s+\S+\s+SIP/2\.0\s*$|(?m)^SIP/2\.0\s+\d{3}(?:\s+.*)?$",
        text,
        re.I,
    ))
    messages: list[SipMessage] = []
    for index, match in enumerate(starts):
        chunk = text[match.start(): starts[index + 1].start() if index + 1 < len(starts) else len(text)]
        message = _parse_raw_sip(chunk)
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


def _run_transport_fields(tshark: str, path: Path) -> list[dict[str, str]]:
    """Extract raw UDP/TCP payloads explicitly; JSON protocol trees are not reliable for this."""
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
    """Decode SIP using TShark and recover missed SIP directly from transport payloads."""
    tshark = shutil.which("tshark")
    if not tshark:
        raise TsharkNotFoundError("tshark was not found. Install Wireshark/tshark and make sure it is on PATH.")

    path = Path(pcap_path)
    if not path.is_file():
        raise FileNotFoundError(path)

    messages: list[SipMessage] = []
    seen_frames: set[int] = set()

    # Rich dissector path.
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

    # Explicit raw transport extraction. This is the important Cloud fallback:
    # -e @udp.payload/@tcp.payload asks TShark for the actual bytes even when
    # the SIP dissector did not classify the packet as SIP.
    try:
        rows = _run_transport_fields(tshark, path)
    except subprocess.CalledProcessError:
        rows = []

    # UDP is message-oriented, so each datagram can be parsed independently.
    for row in rows:
        payload = _decode_hex(row.get("@udp.payload", ""))
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

    # TCP is stream-oriented. Reassemble captured payload segments per direction.
    tcp_streams: dict[tuple[str, str, str, str], list[tuple[int, int, str]]] = {}
    for row in rows:
        payload_hex = row.get("@tcp.payload", "")
        if not payload_hex or not row.get("tcp.stream") or not row.get("tcp.seq"):
            continue
        frame, _, source, destination = _row_metadata(row)
        if frame is None or not source or not destination:
            continue
        key = (row["tcp.stream"], source, destination, row.get("tcp.srcport", ""))
        try:
            seq = int(row["tcp.seq"])
        except ValueError:
            continue
        tcp_streams.setdefault(key, []).append((seq, frame, payload_hex))

    for segments in tcp_streams.values():
        stream_bytes = bytearray()
        frame_for_offset: list[tuple[int, int]] = []
        last_end: int | None = None
        for seq, frame, payload_hex in sorted(segments, key=lambda item: (item[0], item[1])):
            try:
                data = bytes.fromhex(re.sub(r"[^0-9A-Fa-f]", "", payload_hex))
            except ValueError:
                continue
            if not data:
                continue
            if last_end is not None and seq < last_end:
                overlap = last_end - seq
                if overlap >= len(data):
                    continue
                data = data[overlap:]
                seq = last_end
            if last_end is not None and seq > last_end:
                # Gap: keep the new segment separate rather than inventing bytes.
                stream_bytes = bytearray()
                frame_for_offset = []
            offset = len(stream_bytes)
            stream_bytes.extend(data)
            frame_for_offset.append((offset, frame))
            last_end = seq + len(data)

        text = stream_bytes.decode("utf-8", errors="ignore")
        for message in _extract_sip_messages(text):
            start_frame = frame_for_offset[0][1] if frame_for_offset else None
            if start_frame is not None and start_frame in seen_frames:
                continue
            message.frame = start_frame
            messages.append(message)
            if start_frame is not None:
                seen_frames.add(start_frame)

    # Final de-duplication: the same SIP frame can be found by both dissector and raw paths.
    unique: dict[tuple[int | None, str, str | None], SipMessage] = {}
    for message in messages:
        key = (message.frame, message.start_line, message.call_id)
        unique[key] = message

    result = list(unique.values())
    result.sort(key=lambda message: (message.frame is None, message.frame or 0))
    return result
