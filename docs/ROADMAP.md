# Development Roadmap

## V1 — SIP PCAP Analyzer

- [x] Repository and Python package structure
- [x] Normalized SIP message model
- [x] Dependency-free SIP text parser
- [x] SIP flow grouping by Call-ID
- [x] Initial SIP error detection
- [x] tshark PCAP-to-SIP adapter
- [ ] Real PCAP fixture and end-to-end decoder tests
- [ ] SIP ladder / call-flow output
- [ ] SDP extraction and interpretation
- [ ] Transaction and dialog correlation

## V2 — Trace Comparison

- [ ] Working vs failing trace comparison
- [ ] First-deviation detection
- [ ] Timing differences
- [ ] Header/SDP differences
- [ ] Evidence-linked comparison report

## V3 — RFS Validation

- [ ] RFS requirement model
- [ ] Expected signaling sequence rules
- [ ] PASS/FAIL evaluation
- [ ] Requirement-to-frame evidence mapping
- [ ] Validation report

## V4 — AI Debug Assistant

- [ ] Natural-language questions over structured trace data
- [ ] SIP message explanations
- [ ] Root-cause hypotheses with evidence
- [ ] RFS-aware debugging
- [ ] Guardrails against unsupported conclusions

## V5 — Telecom Protocol Expansion

- [ ] 5G NAS
- [ ] NGAP
- [ ] GTP / PFCP
- [ ] LTE S1AP / NAS
- [ ] Diameter
- [ ] IMS correlation across layers
