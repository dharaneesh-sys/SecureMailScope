# User guide

1. **Overview** – metrics, charts, recent analyses. *Load demo dataset* adds clearly-labelled synthetic captures.
2. **New Analysis** – drag-and-drop a `.pcap`/`.pcapng` (≤ 50 MB). Choose options (protocol detection, TLS and certificate inspection, rule application) and start. A live page shows each stage and can cancel.
3. **Results** – counts, severity breakdown, limitations of the capture, findings, evidence overview, optional AI explanation, report download.
4. **Capture Library / Analysis History** – search, sort, re-analyse, download, delete (with confirmation).
5. **Protocol Explorer** – SMTP/IMAP/POP3 sessions, negotiation checklist, event timeline, TCP reassembly quality.
6. **TLS Inspector** – negotiated vs *offered* versions and cipher suites. **Certificate Inspector** – parsed metadata and local checks.
7. **Security Findings** – filter and triage (open, under review, resolved, accepted risk). A drawer explains impact, technical detail, remediation and links to evidence.
8. **Evidence Explorer** – extracted fields, decoded packet tree and hex view; jump to the session.
9. **Risk** – prioritised findings and how the score is built. **Reports** – PDF/HTML/JSON/CSV with preview.
10. **Rules** – read and toggle rules; rule-set history. **Settings** – TShark status, retention, local-only mode, optional AI, logs, audit.

Reading results: *Offered* ≠ *negotiated*. *Not observed* means the capture did not contain the event — not that it did not happen.
