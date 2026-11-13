# API

Base URL `http://localhost:8000/api` (interactive docs at `/docs`). JSON everywhere; errors are `{"detail": ...}`. Lists return `{items,total,page,page_size,pages}`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | liveness, TShark flag, rule count |
| GET | `/system/dependencies` | TShark/editcap path+version, limits, install guidance |
| GET | `/dashboard` | aggregate metrics and charts |
| GET/PUT | `/settings` | app settings (retention, local-only, AI, reports) |
| GET | `/system/logs`, `/system/audit` | recent log lines; audit trail |
| POST | `/system/retention/run` | apply retention now |
| POST | `/captures` (multipart `file`) | upload + validate (400 with a code: `corrupt`, `empty`, `unsupported_linktype`, `unrecognised_format`; 413 too large) |
| GET | `/captures`, `/captures/{id}` | library (`q`, `sort`, `order`, `page`) / detail |
| GET | `/captures/{id}/download` | original file (if retained) |
| DELETE | `/captures/{id}` | permanent delete incl. analyses, findings, evidence, reports |
| GET/POST/DELETE | `/demo/status`, `/demo/load`, `/demo` | synthetic demo dataset |
| POST | `/analyses` | start (202) `{capture_id, options}` |
| GET | `/analyses`, `/analyses/{id}`, `/analyses/{id}/status` | list / detail / live stage progress |
| POST | `/analyses/{id}/cancel`, `/analyses/{id}/rerun` | cancel / re-run with current rules |
| GET | `/analyses/{id}/summary,protocols,tls,certificates,evidence,findings` | result views |
| GET | `/findings`, `/findings/{id}` | cross-analysis findings (`severity`,`status`,`rule`,`protocol`,`q`,`sort`…) |
| PATCH | `/findings/{id}/status` | triage state + note (history kept; evidence untouched) |
| GET | `/evidence/{id}` | evidence + decoded packet + raw hex + linked sessions |
| GET | `/rules`, `/rules/{id}`; PATCH `/rules/{id}` | catalogue / enable-disable (new rule-set version) |
| POST | `/analyses/{id}/reports` `{format}` | generate `json|html|csv|pdf` |
| GET | `/analyses/{id}/report-preview` | sandboxed HTML preview |
| GET | `/reports`, `/reports/{id}/download` | list / download |
