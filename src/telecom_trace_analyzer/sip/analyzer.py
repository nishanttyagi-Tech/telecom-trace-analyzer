"""SIP flow grouping and first-pass diagnostics."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass

from .models import SipFlow, SipMessage


@dataclass(slots=True)
class SipDiagnostic:
    """A deterministic finding tied to a SIP message/frame."""

    severity: str
    frame: int | None
    title: str
    detail: str


_CSEQ_METHOD_RE = re.compile(r"^\s*\d+\s+([A-Za-z][A-Za-z0-9-]*)")
_AUTH_CHALLENGE_CODES = {401, 407}


def cseq_method(message: SipMessage) -> str | None:
    """Return the method encoded in a CSeq header."""
    match = _CSEQ_METHOD_RE.match(message.cseq or "")
    return match.group(1).upper() if match else None


def group_by_call_id(messages: list[SipMessage]) -> list[SipFlow]:
    """Group SIP messages by Call-ID, preserving message order."""
    groups: dict[str, SipFlow] = {}
    for message in messages:
        call_id = message.call_id
        if not call_id:
            continue
        groups.setdefault(call_id, SipFlow(call_id=call_id)).add(message)

    flows = list(groups.values())
    flows.sort(key=lambda flow: min((m.frame or 0) for m in flow.messages))
    return flows


def is_authentication_challenge(message: SipMessage) -> bool:
    """Return True for normal SIP authentication challenge responses."""
    return (
        message.is_response
        and message.status_code in _AUTH_CHALLENGE_CODES
    )


def find_sip_errors(messages: list[SipMessage]) -> list[SipMessage]:
    """Return actual SIP failures, excluding normal authentication challenges."""
    return [
        message
        for message in messages
        if message.is_response
        and message.status_code is not None
        and message.status_code >= 400
        and message.status_code not in _AUTH_CHALLENGE_CODES
    ]


def summarize_message(message: SipMessage) -> str:
    """Create a compact human-readable description without using an LLM."""
    if message.is_request:
        description = f"SIP {message.method} request"
    else:
        description = f"SIP {message.status_code} {message.reason or ''}".rstrip()

    details = []
    if message.call_id:
        details.append(f"Call-ID={message.call_id}")
    if message.cseq:
        details.append(f"CSeq={message.cseq}")
    if message.body:
        details.append("SDP/body present")
    return description + (" (" + ", ".join(details) + ")" if details else "")


def diagnose_flow(flow: SipFlow) -> list[SipDiagnostic]:
    """Run conservative, deterministic checks over one SIP Call-ID flow."""
    findings: list[SipDiagnostic] = []
    transactions: dict[tuple[str, str], list[SipMessage]] = defaultdict(list)

    for message in flow.messages:
        method = message.method if message.is_request else cseq_method(message)
        cseq_number = (message.cseq or "").split(maxsplit=1)[0] if message.cseq else ""
        if method and cseq_number:
            transactions[(cseq_number, method.upper())].append(message)

    for message in flow.messages:
        if not message.is_response or not message.cseq:
            continue
        method = cseq_method(message)
        cseq_number = message.cseq.split(maxsplit=1)[0]
        if method and not any(m.is_request for m in transactions.get((cseq_number, method), [])):
            findings.append(
                SipDiagnostic(
                    "warning",
                    message.frame,
                    "Response has no matching request in this flow",
                    f"Observed {message.status_code} for CSeq {message.cseq}, but no matching {method} request was captured for this Call-ID.",
                )
            )

    for key, messages in transactions.items():
        requests = [m for m in messages if m.is_request]
        responses = [m for m in messages if m.is_response]
        if not requests or responses:
            continue
        method = key[1]
        if method in {"ACK", "CANCEL"}:
            continue
        last = requests[-1]
        findings.append(
            SipDiagnostic(
                "warning",
                last.frame,
                f"No final response observed for {method}",
                f"CSeq {last.cseq} contains a {method} request, but this capture contains no final 2xx-6xx response for the transaction.",
            )
        )

    failures = [
        m
        for m in flow.messages
        if m.is_response
        and m.status_code is not None
        and m.status_code >= 400
        and m.status_code not in _AUTH_CHALLENGE_CODES
    ]
    if failures:
        first = min(failures, key=lambda m: m.frame if m.frame is not None else 10**18)
        findings.insert(
            0,
            SipDiagnostic(
                "error",
                first.frame,
                f"First SIP failure: {first.status_code} {first.reason or ''}".strip(),
                f"This is the first non-authentication 4xx/5xx/6xx response observed in the Call-ID flow. Start root-cause analysis at frame {first.frame or 'N/A'} and correlate the request, CSeq, headers and preceding messages.",
            ),
        )

    return findings


def diagnose_flows(flows: list[SipFlow]) -> list[SipDiagnostic]:
    """Diagnose all Call-ID flows and return findings in frame order."""
    findings = [finding for flow in flows for finding in diagnose_flow(flow)]
    return sorted(findings, key=lambda f: f.frame if f.frame is not None else 10**18)
