"""Small, dependency-free SIP message parser.

PCAP decoding will feed normalized SIP text into this parser. Keeping the SIP
normalization independent from tshark makes the analysis engine easy to test.
"""

from __future__ import annotations

import re

from .models import SipMessage

_STATUS_RE = re.compile(r"^SIP/2\.0\s+(\d{3})(?:\s+(.*))?$")
_REQUEST_RE = re.compile(r"^([A-Z][A-Z0-9-]*)\s+\S+\s+SIP/2\.0$")


def parse_sip_message(text: str, *, frame: int | None = None) -> SipMessage:
    """Parse a SIP message from text and return a normalized :class:`SipMessage`.

    Header names are normalized to lowercase. Repeated headers are joined with
    a comma, preserving all values without silently discarding information.
    """
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    head, separator, body = normalized.partition("\n\n")
    lines = head.split("\n") if head else []
    if not lines:
        raise ValueError("SIP message is empty")

    start_line = lines[0].strip()
    headers: dict[str, str] = {}
    current_name: str | None = None

    for raw_line in lines[1:]:
        if raw_line[:1] in (" ", "\t") and current_name:
            headers[current_name] += " " + raw_line.strip()
            continue
        if ":" not in raw_line:
            continue
        name, value = raw_line.split(":", 1)
        current_name = name.strip().lower()
        value = value.strip()
        if current_name in headers:
            headers[current_name] += ", " + value
        else:
            headers[current_name] = value

    status_match = _STATUS_RE.match(start_line)
    if status_match:
        return SipMessage(
            frame=frame,
            start_line=start_line,
            message_type="response",
            status_code=int(status_match.group(1)),
            reason=status_match.group(2) or "",
            headers=headers,
            body=body if separator else "",
        )

    request_match = _REQUEST_RE.match(start_line)
    if request_match:
        return SipMessage(
            frame=frame,
            start_line=start_line,
            message_type="request",
            method=request_match.group(1),
            headers=headers,
            body=body if separator else "",
        )

    raise ValueError(f"Not a recognized SIP start line: {start_line!r}")
