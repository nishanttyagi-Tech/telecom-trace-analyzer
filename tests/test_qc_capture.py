from telecom_trace_analyzer.qc_capture import build_display_filter


def test_build_display_filter():
    result = build_display_filter(["5G SA / NGAP", "IMS / SIP"])
    assert result == "ngap or sip"


def test_unknown_entries_are_ignored():
    assert build_display_filter(["5G NAS"]) == "nas-5gs"
