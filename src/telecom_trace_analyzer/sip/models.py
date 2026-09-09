"""Data models used by the SIP analysis engine."""

from dataclasses import dataclass, field


@dataclass(slots=True)
class SipMessage:
    """A normalized SIP message extracted from a packet or text capture."""

    frame: int | None = None
    timestamp: float | None = None
    source: str | None = None
    destination: str | None = None
    start_line: str = ""
    message_type: str = ""
    method: str | None = None
    status_code: int | None = None
    reason: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""

    @property
    def call_id(self) -> str | None:
        return self.headers.get("call-id") or self.headers.get("i")

    @property
    def cseq(self) -> str | None:
        return self.headers.get("cseq")

    @property
    def is_request(self) -> bool:
        return self.message_type == "request"

    @property
    def is_response(self) -> bool:
        return self.message_type == "response"


@dataclass(slots=True)
class SipFlow:
    """Messages belonging to the same SIP Call-ID/dialog candidate."""

    call_id: str
    messages: list[SipMessage] = field(default_factory=list)

    def add(self, message: SipMessage) -> None:
        self.messages.append(message)
