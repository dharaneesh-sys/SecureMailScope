# Architecture

```
Browser (React + TS + Vite + Tailwind, :5173)
   │  /api  (Vite proxy)
FastAPI (:8000) ── routes → services → SQLite (SQLAlchemy)
   │                         │
   │                         └─ tshark_runner → TShark subprocess (whitelisted args, timeout, cancellable)
   └─ workers/pipeline.py (ThreadPoolExecutor) runs analyses in the background; progress is written to the DB
```

## Backend layout (`backend/app`)
| Path | Responsibility |
|---|---|
| `core/` | settings (`SMS_*` env), rotating log, filename/path-traversal guards |
| `services/capture_service.py` | upload validation by *content* (magic, link type), SHA-256, duplicate detection |
| `services/tshark_runner.py` | the only place a subprocess is started; argument whitelist, no shell, timeout, cancel registry |
| `services/tcp_reassembly.py`, `protocol_detection.py` | stream table, client/server orientation, SMTP/IMAP/POP3 detection by banner + commands + port, decode-as |
| `services/{smtp,imap,pop3}_analyzer.py` | event timelines and STARTTLS/STLS state machines |
| `services/tls_analyzer.py`, `certificate_analyzer.py`, `cipher_catalog.py` | handshake metadata, IANA cipher classification, DER certificate parsing (`cryptography`) |
| `services/engine.py` | orchestrates 13 named stages, builds the in-memory result; **carving** for IMAP (see below) |
| `rules/` | deterministic rule classes; each returns drafts with evidence references |
| `services/risk_engine.py` | SMRS-1 scoring (documented in RULES.md) |
| `ai/` | optional explanation layer (provider adapters, structured-metadata-only prompts, validation) |
| `services/persistence.py`, `models/tables.py` | result storage; 16 tables |
| `services/report_service.py` | JSON / HTML (autoescaped, CSP sandbox) / CSV (formula-neutralised) / PDF (reportlab) |

## Key design decisions
- **Facts vs. explanation.** Rules decide; AI may only rephrase. AI output citing an unknown rule ID is dropped.
- **Observation types.** `weakness_observed`, `weak_option_offered`, `secure_configuration`, `protocol_feature`, `insufficient_evidence`. An *offered* weak cipher is not reported as negotiated; missing evidence is "not observed".
- **No sensitive storage.** Only protocol verbs/capabilities are kept. AUTH payloads, credentials, addresses and bodies are replaced by placeholders before persistence. Raw bytes are kept only for TLS handshake frames.
- **Two-pass TShark (`-2`)** for correct reassembly; JSON for decoded trees, field extraction for tables.
- **IMAP STARTTLS carving.** TShark does not switch IMAP into TLS after STARTTLS, so post-STARTTLS frames are exported to a derived pcap and re-dissected with `-d tcp.port==P,tls`; frame/stream numbers are mapped back to the original capture. POP3 CAPA lines blanked by TShark are read from `tcp.payload` in memory only.
- **TLS 1.3.** Negotiated version comes from `supported_versions`; the legacy 0x0303 field is ignored. Certificates are encrypted → SMS-CRT-005 (info).
- **Rule-set versioning.** A signature of rule metadata/enabled state is stored in `rule_versions`; every analysis records the version it used.
- **Certificate time.** Validity is judged at capture time by default (setting `cert_reference`), so old captures do not all show "expired".
- **Jobs.** Real stage progress is persisted; cancel kills TShark; jobs left running at crash are marked failed on restart; retention policy removes expired originals.

## Frontend layout (`frontend/src`)
`pages/` (one per screen) · `components/{ui,layout,findings,analysis}` · `hooks/queries.ts` (TanStack Query) · `services/api.ts` (fetch + XHR upload progress) · `types/api.ts` · `utils/format.ts`. Filters, pagination and open drawers are kept in the URL so views are linkable.
