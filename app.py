"""Local Streamlit UI for the first PCAP/SIP analysis milestone."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from telecom_trace_analyzer.pcap.decoder import TsharkNotFoundError, decode_sip_messages
from telecom_trace_analyzer.sip.analyzer import find_sip_errors, group_by_call_id, summarize_message


st.set_page_config(page_title="Telecom Trace Analyzer", page_icon="📡", layout="wide")
st.title("📡 Telecom Trace Analyzer")
st.caption("V1 — PCAP → SIP extraction → call-flow inspection")

uploaded = st.file_uploader("Upload a PCAP / PCAPNG file", type=["pcap", "pcapng"])

if not uploaded:
    st.info("Upload a sanitized or synthetic capture to start. Do not upload confidential work/customer traces to public services.")
    st.stop()

with tempfile.TemporaryDirectory(prefix="telecom_trace_") as tmp:
    pcap_path = Path(tmp) / uploaded.name
    pcap_path.write_bytes(uploaded.getvalue())

    try:
        messages = decode_sip_messages(pcap_path)
    except TsharkNotFoundError as exc:
        st.error(str(exc))
        st.stop()
    except Exception as exc:  # noqa: BLE001
        st.error(f"PCAP analysis failed: {exc}")
        st.stop()

st.success(f"Analysis complete: {len(messages)} SIP messages found.")

flows = group_by_call_id(messages)
errors = find_sip_errors(messages)

m1, m2, m3 = st.columns(3)
m1.metric("SIP messages", len(messages))
m2.metric("Call-ID flows", len(flows))
m3.metric("SIP errors (4xx–6xx)", len(errors))

st.subheader("SIP messages")
rows = []
for message in messages:
    rows.append(
        {
            "Frame": message.frame,
            "Source": message.source or "",
            "Destination": message.destination or "",
            "Message": message.start_line,
            "Call-ID": message.call_id or "",
            "CSeq": message.cseq or "",
            "Status": message.status_code or "",
        }
    )
st.dataframe(rows, use_container_width=True, hide_index=True)

st.subheader("Call flows")
if not flows:
    st.warning("No SIP Call-ID could be reconstructed from the capture.")
else:
    for index, flow in enumerate(flows, start=1):
        label = f"Flow {index} — {flow.call_id} ({len(flow.messages)} messages)"
        with st.expander(label):
            for message in flow.messages:
                direction = f"{message.source or '?'} → {message.destination or '?'}"
                st.markdown(f"**Frame {message.frame or '?'}** · {direction}")
                st.code(message.start_line)
                st.caption(summarize_message(message))

st.subheader("SIP errors")
if errors:
    for message in errors:
        st.error(
            f"Frame {message.frame or '?'} — {message.status_code} {message.reason or ''} — "
            f"CSeq: {message.cseq or 'N/A'}"
        )
else:
    st.success("No 4xx, 5xx or 6xx SIP responses detected.")
