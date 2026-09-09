"""Local Streamlit UI for the Telecom Trace Analyzer."""

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
from telecom_trace_analyzer.sip.analyzer import (
    diagnose_flow,
    diagnose_flows,
    find_sip_errors,
    group_by_call_id,
    is_authentication_challenge,
    summarize_message,
)


def explain_message(message) -> str:
    """Return a deterministic, telecom-friendly explanation of a SIP message."""
    if message.is_request:
        descriptions = {
            "REGISTER": "Registers the UE/contact with the IMS registrar. A 401/407 challenge may be expected before an authenticated REGISTER is accepted.",
            "INVITE": "Initiates a SIP session. In IMS this normally carries SDP describing the proposed media session.",
            "ACK": "Confirms receipt of the final response to an INVITE transaction and completes the INVITE handshake.",
            "BYE": "Terminates an established SIP session.",
            "CANCEL": "Cancels a pending INVITE transaction before a final response is received.",
            "PRACK": "Provides a reliable acknowledgement for a provisional response when 100rel is used.",
            "UPDATE": "Updates session parameters before or during dialog establishment when supported.",
            "SUBSCRIBE": "Creates or refreshes a subscription for event notifications.",
            "NOTIFY": "Carries an event notification, commonly in response to a SUBSCRIBE.",
            "OPTIONS": "Queries SIP endpoint capabilities and reachability.",
            "REFER": "Requests that the recipient initiate a new referenced action, commonly call transfer.",
        }
        return descriptions.get(message.method or "", "SIP request; inspect its method, headers, CSeq and body for the transaction purpose.")

    if message.is_response:
        code = message.status_code or 0
        if code in {401, 407}:
            return "Authentication challenge. In an IMS REGISTER flow this is normally expected: inspect WWW-Authenticate/Proxy-Authenticate, then verify that the UE sends an authenticated follow-up request and receives the expected final response."
        if 100 <= code < 200:
            return "Provisional response. The transaction is still in progress; inspect the next request/response and any reliable provisional-response handling."
        if 200 <= code < 300:
            return "Successful final response. Verify that the corresponding transaction/dialog proceeds to the expected next SIP message."
        if 300 <= code < 400:
            return "Redirection response. Check the Contact header and whether the sender follows the redirect as required by the test scenario."
        if 400 <= code < 500:
            return "Client-side failure response. Check the request, dialog/transaction state, authentication, headers and the exact SIP reason."
        if 500 <= code < 600:
            return "Server-side failure response. Investigate the receiving network element, service state, routing and upstream signaling."
        if 600 <= code < 700:
            return "Global failure response. The failure applies beyond a single server; correlate the transaction and network-side signaling."
    return "SIP message extracted from the packet capture."


st.set_page_config(page_title="Telecom Trace Analyzer", page_icon="📡", layout="wide")
st.title("📡 Telecom Trace Analyzer")
st.caption("V1 — PCAP → SIP extraction → transaction & call-flow inspection")

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

flows = group_by_call_id(messages)
errors = find_sip_errors(messages)
auth_challenges = [m for m in messages if is_authentication_challenge(m)]
diagnostics = diagnose_flows(flows)

st.success(f"Analysis complete: {len(messages)} SIP messages found.")

m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("SIP messages", len(messages))
m2.metric("Call-ID flows", len(flows))
m3.metric("Actual SIP failures", len(errors))
m4.metric("Auth challenges", len(auth_challenges))
m5.metric("Diagnostics", len(diagnostics))

if auth_challenges:
    st.info(f"{len(auth_challenges)} authentication challenge(s) detected (401/407). These are not counted as SIP failures by the analyzer.")

st.subheader("SIP message explorer")
filter_text = st.text_input("Filter messages", placeholder="e.g. INVITE, 401, PRACK, Call-ID")
filtered = messages
if filter_text.strip():
    needle = filter_text.lower()
    filtered = [
        m for m in messages
        if needle in m.start_line.lower()
        or needle in (m.call_id or "").lower()
        or needle in (m.cseq or "").lower()
    ]

rows = [
    {
        "Frame": m.frame,
        "Time": f"{m.timestamp:.6f}" if m.timestamp is not None else "",
        "Source": m.source or "",
        "Destination": m.destination or "",
        "Message": m.start_line,
        "Call-ID": m.call_id or "",
        "CSeq": m.cseq or "",
        "Status": m.status_code or "",
    }
    for m in filtered
]
st.dataframe(rows, use_container_width=True, hide_index=True)
st.caption(f"Showing {len(filtered)} of {len(messages)} SIP messages")

if messages:
    st.subheader("Explain a SIP message")
    options = {
        f"Frame {m.frame} — {m.start_line} — CSeq {m.cseq or 'N/A'}": i
        for i, m in enumerate(messages)
    }
    selected_label = st.selectbox("Select message", list(options))
    selected = messages[options[selected_label]]

    left, right = st.columns([1, 1])
    with left:
        st.markdown("### What it does")
        st.info(explain_message(selected))
        st.markdown("### Message summary")
        st.write(summarize_message(selected))
    with right:
        st.markdown("### Packet context")
        st.write(f"**Frame:** {selected.frame or 'N/A'}")
        st.write(f"**Source:** {selected.source or 'N/A'}")
        st.write(f"**Destination:** {selected.destination or 'N/A'}")
        st.write(f"**Call-ID:** {selected.call_id or 'N/A'}")
        st.write(f"**CSeq:** {selected.cseq or 'N/A'}")
        st.write(f"**Status:** {selected.status_code or 'N/A'}")

    with st.expander("SIP headers"):
        if selected.headers:
            st.json(selected.headers)
        else:
            st.write("No SIP headers were extracted.")

    with st.expander("SIP body / SDP"):
        if selected.body:
            st.code(selected.body, language="text")
        else:
            st.write("No SIP message body was extracted.")

st.subheader("Automatic call-flow diagnostics")
if not diagnostics:
    st.success("No trace-level anomalies detected by the current deterministic checks.")
else:
    st.caption("These are conservative trace checks, not a complete RFC/3GPP conformance verdict.")
    for finding in diagnostics:
        text = f"Frame {finding.frame or '?'} — {finding.title}\n\n{finding.detail}"
        if finding.severity == "error":
            st.error(text)
        else:
            st.warning(text)

st.subheader("Call flows")
if not flows:
    st.warning("No SIP Call-ID could be reconstructed from the capture.")
else:
    for index, flow in enumerate(flows, start=1):
        flow_findings = diagnose_flow(flow)
        label = f"Flow {index} — {flow.call_id} ({len(flow.messages)} messages)"
        with st.expander(label):
            if flow_findings:
                st.markdown("**Flow findings**")
                for finding in flow_findings:
                    icon = "🔴" if finding.severity == "error" else "⚠️"
                    st.markdown(f"{icon} **Frame {finding.frame or '?'} — {finding.title}**")
                    st.caption(finding.detail)
            else:
                st.success("No trace-level anomalies detected in this flow.")

            st.markdown("**SIP sequence**")
            sequence_rows = []
            for message in flow.messages:
                sequence_rows.append(
                    {
                        "Frame": message.frame,
                        "Direction": f"{message.source or '?'} → {message.destination or '?'}",
                        "Message": message.start_line,
                        "CSeq": message.cseq or "",
                    }
                )
            st.dataframe(sequence_rows, use_container_width=True, hide_index=True)

st.subheader("SIP errors")
if errors:
    for message in errors:
        st.error(
            f"Frame {message.frame or '?'} — {message.status_code} {message.reason or ''} — "
            f"CSeq: {message.cseq or 'N/A'}"
        )
else:
    st.success("No actual SIP 4xx/5xx/6xx failures detected. Normal 401/407 authentication challenges are excluded.")
