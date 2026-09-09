"""SIP flow grouping and first-pass diagnostics."""

from collections import defaultdict

from .models import SipFlow, SipMessage


def group_by_call_id(messages: list[SipMessage]) -> list[SipFlow]:
    """Group SIP messages by Call-ID, preserving message order."""
    groups: dict[str, SipFlow] = {}
    without_call_id: list[SipMessage] = []

    for message in messages:
        call_id = message.call_id
        if not call_id:
            without_call_id.append(message)
            continue
        groups.setdefault(call_id, SipFlow(call_id=call_id)).add(message)

    flows = list(groups.values())
    flows.sort(key=lambda flow: min((m.frame or 0) for m in flow.messages))
    return flows


def find_sip_errors(messages: list[SipMessage]) -> list[SipMessage]:
    """Return SIP responses in the 4xx, 5xx and 6xx ranges."""
    return [
        message
        for message in messages
        if message.is_response and message.status_code is not None and message.status_code >= 400
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
