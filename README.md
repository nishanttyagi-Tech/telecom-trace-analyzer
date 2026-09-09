# Telecom Trace Analyzer

**Telecom PCAP analysis, SIP debugging, trace comparison, RFS validation & AI-assisted troubleshooting.**

## Vision

Telecom Trace Analyzer is being developed as a protocol-aware debugging platform for engineers working with packet captures and telecom signaling. The first release focuses on SIP/IMS traces, with a design that can later expand to LTE and 5G protocols.

## V1 — PCAP to SIP analyzer

The first usable milestone provides a local Streamlit interface that:

- accepts `.pcap` and `.pcapng` files
- uses `tshark` for packet decoding
- extracts SIP requests/responses and key headers
- groups messages by Call-ID
- shows a readable SIP message table
- shows SIP flows
- flags 4xx/5xx/6xx SIP responses

AI explanations, working-vs-failing trace comparison and RFS validation will be added after the deterministic analysis layer is stable.

## Run locally

### 1. Install Wireshark

Install Wireshark with the **TShark** command-line component and make sure `tshark` is available from a terminal.

Verify:

```text
tshark --version
```

### 2. Create a Python environment

Python 3.11 or newer is required.

```text
python -m venv .venv
.venv\\Scripts\\activate
python -m pip install -e .
pip install -r requirements.txt
```

### 3. Start the analyzer

```text
streamlit run app.py
```

A browser window will open. Upload a **sanitized or synthetic** PCAP/PCAPNG and the current V1 analyzer will extract the SIP traffic.

## Planned capabilities

- PCAP/PCAPNG ingestion and packet indexing
- SIP message extraction and transaction/dialog reconstruction
- SIP call-flow visualization
- Human-readable SIP message explanations
- Error and abnormal-sequence detection
- Working-vs-failing PCAP comparison
- RFS/test-case validation against observed signaling
- Evidence-based AI-assisted root-cause analysis
- Future support for 5G/LTE/IMS protocols such as NAS, NGAP, GTP, PFCP and Diameter

## Design principle

**Deterministic protocol parsing first, AI explanation second.**

The analyzer should establish what happened from packet evidence before an AI layer explains why it matters. Answers should be traceable to packet/frame evidence whenever possible.

## Planned architecture

```text
PCAP / PCAPNG
      │
      ▼
Packet Decoder (tshark/Wireshark)
      │
      ▼
Protocol & SIP Analysis
      │
      ├── Transactions / dialogs
      ├── Headers / SDP
      └── Errors / anomalies
      │
      ├───────────────┐
      ▼               ▼
Trace Comparison   RFS Engine
      │               │
      └───────┬───────┘
              ▼
       AI Debug Assistant
              │
              ▼
       Engineer-friendly report
```

## Security

Do not commit confidential, customer, operator, or work-related PCAP files to this repository. Use sanitized or synthetic captures for development and testing.

## License

MIT License. See `LICENSE`.
