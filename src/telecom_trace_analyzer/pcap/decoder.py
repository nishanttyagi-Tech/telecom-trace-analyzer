"""PCAP decoding adapter using TShark with payload-first SIP recovery."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from telecom_trace_analyzer.sip.models import SipMessage


class TsharkNotFoundError(RuntimeError):
    """Raised when TShark is unavailable."""


_METHODS = "REGISTER|INVITE|ACK|BYE|CANCEL|PRACK|UPDATE|SUBSCRIBE|NOTIFY|OPTIONS|REFER|MESSAGE|INFO|PUBLISH"
_START = re.compile(
    rf"(?:{_METHODS})\s+\S+\s+SIP/2\.0|SIP/2\.0\s+\d{{3}}(?:\s+[^\r\n]*)?",
    re.I,
)


def _first(value: Any) -> Any:
    return value[0] if isinstance(value, list) and value else value


def _collect(value: Any, result: dict[str, Any] | None = None) -> dict[str, Any]:
    if result is None:
        result = {}
    if isinstance(value, dict):
        for key, child in value.items():
            if key not in result:
                result[key] = _first(child)
            _collect(child, result)
    elif isinstance(value, list):
        for child in value:
            _collect(child, result)
    return result


def _metadata(fields: dict[str, Any]) -> tuple[int | None, float | None, str | None, str | None]:
    try:
        frame = int(fields.get("frame.number")) if fields.get("frame.number") else None
    except (TypeError, ValueError):
        frame = None
    try:
        timestamp = float(fields.get("frame.time_epoch")) if fields.get("frame.time_epoch") else None
    except (TypeError, ValueError):
        timestamp = None
    source = fields.get("ip.src") or fields.get("ipv6.src")
    destination = fields.get("ip.dst") or fields.get("ipv6.dst")
    return frame, timestamp, source, destination


def _header(fields: dict[str, Any], *names: str) -> str | None:
    for name in names:
        value = fields.get(name)
        if value not in (None, ""):
            return str(value)
    return None


def _from_tshark(fields: dict[str, Any]) -> SipMessage | None:
    request = _header(fields, "sip.Request-Line")
    status = _header(fields, "sip.Status-Line")
    if request:
        start, kind, method, code, reason = request, "request", request.split(" ", 1)[0], None, None
    elif status:
        parts = status.split(" ", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            return None
        start, kind, method, code, reason = status, "response", None, int(parts[1]), parts[2] if len(parts) > 2 else ""
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
    return SipMessage(start_line=start, message_type=kind, method=method, status_code=code, reason=reason,
                      headers={k: v for k, v in headers.items() if v is not None})


def _decode_hex(value: str) -> str:
    compact = re.sub(r"[^0-9A-Fa-f]", "", value or "")
    if not compact or len(compact) % 2:
        return ""
    try:
        return bytes.fromhex(compact).decode("utf-8", errors="ignore")
    except ValueError:
        return ""


def _parse_raw(text: str) -> SipMessage | None:
    text = text.replace("\x00", "").replace("\r\n", "\n")
    lines = text.split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    if not lines:
        return None
    start = lines[0].strip()
    req = re.match(rf"^({_METHODS})\s+\S+\s+SIP/2\.0$", start, re.I)
    resp = re.match(r"^SIP/2\.0\s+(\d{3})(?:\s+(.*))?$", start, re.I)
    if req:
        kind, method, code, reason = "request", req.group(1).upper(), None, None
    elif resp:
        kind, method, code, reason = "response", None, int(resp.group(1)), resp.group(2) or ""
    else:
        return None
    values: dict[str, str] = {}
    for line in lines[1:]:
        if not line.strip():
            break
        if ":" in line:
            name, value = line.split(":", 1)
            values[name.strip().lower()] = value.strip()
    aliases = {
        "call-id": ("call-id", "i"), "cseq": ("cseq",), "from": ("from", "f"),
        "to": ("to", "t"), "via": ("via", "v"), "contact": ("contact", "m"),
        "content-type": ("content-type", "c"), "require": ("require",),
        "supported": ("supported", "k"), "www-authenticate": ("www-authenticate",),
    }
    headers: dict[str, str] = {}
    for normalized, names in aliases.items():
        for name in names:
            if name in values:
                headers[normalized] = values[name]
                break
    body = ""
    if "\n\n" in text:
        body = text.split("\n\n", 1)[1]
    return SipMessage(start_line=start, message_type=kind, method=method, status_code=code,
                      reason=reason, headers=headers, body=body)


def _extract(text: str) -> list[SipMessage]:
    """Find SIP messages anywhere in a payload, including after binary headers."""
    text = text.replace("\r\n", "\n")
    matches = list(_START.finditer(text))
    result: list[SipMessage] = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        message = _parse_raw(text[match.start():end])
        if message:
            result.append(message)
    return result


def _run_fields(tshark: str, path: Path) -> list[dict[str, str]]:
    # @field requests the raw field bytes as hexadecimal. data.data is included
    # because it is the generic byte-sequence field used when no upper dissector
    # claims the payload.
    fields = [
        "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
        "udp.srcport", "udp.dstport", "@udp.payload", "tcp.srcport", "tcp.dstport",
        "tcp.stream", "tcp.seq", "@tcp.payload", "@data.data",
    ]
    cmd = [tshark, "-2", "-n", "-r", str(path), "-T", "fields"]
    for field in fields:
        cmd += ["-e", field]
    cmd += ["-E", "separator=|", "-E", "quote=n", "-E", "escape=n", "-E", "occurrence=a", "-E", "aggregator=,"]
    completed = subprocess.run(cmd, check=True, capture_output=True, text=True)
    rows: list[dict[str, str]] = []
    for line in completed.stdout.splitlines():
        values = line.split("|")
        values += [""] * (len(fields) - len(values))
        rows.append(dict(zip(fields, values[:len(fields)])))
    return rows


def _run_json(tshark: str, path: Path, raw: bool = False) -> list[dict[str, Any]]:
    cmd = [tshark, "-2", "-n", "-r", str(path), "-T", "jsonraw" if raw else "json"]
    if raw:
        cmd.append("-x")
    completed = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return json.loads(completed.stdout or "[]")


def _hex_values(value: Any) -> list[str]:
    found: list[str] = []
    if isinstance(value, str) and re.fullmatch(r"(?:[0-9A-Fa-f]{2})+", value):
        found.append(value)
    elif isinstance(value, dict):
        for child in value.values():
            found.extend(_hex_values(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(_hex_values(child))
    return found


def _packet_hex_candidates(packet: dict[str, Any]) -> list[str]:
    result: list[str] = []
    for value in _hex_values(packet):
        text = _decode_hex(value)
        if "SIP/2.0" in text or re.search(rf"(?:{_METHODS})\s+sip:", text, re.I):
            result.append(text)
    return result


def decode_sip_messages(pcap_path: str | Path) -> list[SipMessage]:
    """Decode SIP using the TShark dissector plus payload/raw recovery."""
    tshark = shutil.which("tshark")
    if not tshark:
        raise TsharkNotFoundError("tshark was not found. Install Wireshark/tshark and make sure it is on PATH.")
    path = Path(pcap_path)
    if not path.is_file():
        raise FileNotFoundError(path)

    messages: list[SipMessage] = []
    seen: set[tuple[int | None, str, str | None]] = set()

    def add(message: SipMessage, frame: int | None, timestamp: float | None, source: str | None, destination: str | None) -> None:
        message.frame, message.timestamp, message.source, message.destination = frame, timestamp, source, destination
        key = (frame, message.start_line, message.call_id)
        if key not in seen:
            seen.add(key)
            messages.append(message)

    # 1. Normal SIP dissection: best headers and transaction information.
    try:
        for packet in _run_json(tshark, path):
            fields = _collect(packet.get("_source", {}).get("layers", {}))
            message = _from_tshark(fields)
            if message:
                add(message, *_metadata(fields))
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        pass

    # 2. Explicit raw transport fields. This is the main cloud-safe recovery path.
    try:
        rows = _run_fields(tshark, path)
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        rows = []
    for row in rows:
        try:
            frame = int(row.get("frame.number")) if row.get("frame.number") else None
        except ValueError:
            frame = None
        try:
            timestamp = float(row.get("frame.time_epoch")) if row.get("frame.time_epoch") else None
        except ValueError:
            timestamp = None
        source = row.get("ip.src") or row.get("ipv6.src") or None
        destination = row.get("ip.dst") or row.get("ipv6.dst") or None
        for field in ("@udp.payload", "@tcp.payload", "@data.data"):
            for raw_value in filter(None, row.get(field, "").split(",")):
                text = _decode_hex(raw_value)
                if not text:
                    continue
                for message in _extract(text):
                    add(message, frame, timestamp, source, destination)

    # 3. Raw JSON fallback, paired with normal JSON by packet index for metadata.
    try:
        normal = _run_json(tshark, path)
        raw_packets = _run_json(tshark, path, raw=True)
        for index, packet in enumerate(raw_packets):
            frame = timestamp = source = destination = None
            if index < len(normal):
                fields = _collect(normal[index].get("_source", {}).get("layers", {}))
                frame, timestamp, source, destination = _metadata(fields)
            for candidate in _packet_hex_candidates(packet):
                for message in _extract(candidate):
                    add(message, frame, timestamp, source, destination)
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        pass

    messages.sort(key=lambda message: (message.frame is None, message.frame or 0, message.timestamp or 0))
    return messages
