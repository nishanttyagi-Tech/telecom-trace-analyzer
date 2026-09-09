from telecom_trace_analyzer.sip.parser import parse_sip_message


REGISTER = """SIP/2.0 401 Unauthorized\r\nVia: SIP/2.0/UDP 192.0.2.10:5060\r\nCall-ID: test-call-123\r\nCSeq: 1 REGISTER\r\nWWW-Authenticate: Digest realm=\"ims.example\"\r\nContent-Length: 0\r\n\r\n"""


def test_parse_sip_response():
    message = parse_sip_message(REGISTER, frame=42)

    assert message.frame == 42
    assert message.is_response
    assert message.status_code == 401
    assert message.reason == "Unauthorized"
    assert message.call_id == "test-call-123"
    assert message.cseq == "1 REGISTER"
    assert message.headers["www-authenticate"].startswith("Digest")


def test_parse_sip_request_and_body():
    text = """INVITE sip:user@example.com SIP/2.0\r\nCall-ID: abc\r\nCSeq: 10 INVITE\r\nContent-Type: application/sdp\r\n\r\nv=0\r\no=- 1 1 IN IP4 192.0.2.10\r\n"""

    message = parse_sip_message(text)

    assert message.is_request
    assert message.method == "INVITE"
    assert message.call_id == "abc"
    assert message.body.startswith("v=0")
