"""Report generation (JSON / HTML / CSV / PDF) from *stored* analysis data only."""

from __future__ import annotations

import csv
import datetime as dt
import hashlib
import io
import json
from pathlib import Path
from xml.sax.saxutils import escape

from jinja2 import Environment, select_autoescape
from sqlalchemy.orm import Session

from app.ai.explanation_service import builtin_summary, group_findings
from app.core.config import settings
from app.core.security import sanitize_filename
from app.models.tables import (Analysis, CertificateRow, EmailSessionRow, Finding, GeneratedReport, TlsSessionRow)

from . import app_settings
from .risk_engine import MODEL_VERSION
from .serializers import SEV_ORDER, cert_dict, finding_dict, iso, session_dict, summary_dict, tls_dict

TITLE = "SecureMailScope: AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications"
FORMATS = ("json", "html", "csv", "pdf")
METHODOLOGY = [
    "The capture is validated by file content (PCAP/PCAPNG magic, link-layer type, record integrity) and hashed with SHA-256.",
    "TShark performs two-pass TCP reassembly and protocol dissection; SecureMailScope normalises TShark's output into SMTP/IMAP/POP3 events and TLS handshake observations.",
    "Email protocols are identified from payload signatures and ports; STARTTLS/STLS transitions are tracked per TCP stream.",
    "Deterministic, versioned rules evaluate only parsed observations. A rule that lacks evidence reports 'insufficient evidence', never a weakness.",
    f"Risk scores use the SecureMailScope Risk Score model {MODEL_VERSION} (documented in docs/RULES.md). It is not CVSS.",
    "Optional AI text is labelled separately and is never a source of facts.",
]
REFERENCES = [
    "RFC 8446 - TLS 1.3", "RFC 8996 - Deprecating TLS 1.0 and 1.1", "RFC 9325 - Recommendations for Secure Use of TLS", "RFC 3207 - SMTP STARTTLS",
    "RFC 8314 - Cleartext Considered Obsolete (mail submission/access over TLS)", "RFC 5280 - X.509 PKI Certificate Profile", "NIST SP 800-52 Rev. 2 - TLS Guidelines",
]


def build_report_data(db: Session, analysis_id: str) -> dict:
    a = db.get(Analysis, analysis_id)
    if a is None:
        raise KeyError(analysis_id)
    cfg = app_settings.get_all(db)
    findings = db.query(Finding).filter(Finding.analysis_id == a.id).all()
    findings.sort(key=lambda f: (SEV_ORDER[f.severity], -f.risk_score, f.ref))
    fd = [finding_dict(f, with_evidence=True, capture_name=a.capture.filename, capture_id=a.capture_id) for f in findings]
    summ = summary_dict(db, a)
    return {
        "title": TITLE, "project": {"team": "ALPHA HUSTLERS", "project_id": "P-2025-29-CS-024-AY-26-27", "institution": "KGiSL Institute of Technology", "domain": "CS - Cyber Security"},
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "organisation": cfg["report_organisation"], "analyst": cfg["analyst_name"],
        "is_demo": a.capture.is_demo,
        "capture": {"filename": a.capture.filename, "sha256": a.capture.sha256, "size_bytes": a.capture.size_bytes, "format": a.capture.format, "linktype": a.capture.linktype, "packets": a.capture.packet_count},
        "analysis": {"id": a.id, "status": a.status, "started_at": iso(a.started_at), "finished_at": iso(a.finished_at), "ruleset_version": a.ruleset_version, "tool": a.tool_info.get("version")},
        "counters": a.counters, "severity": summ["severity"],
        "executive_summary": builtin_summary(fd, a.counters, a.limitations), "ai_summary": a.ai_summary,
        "protocols": [session_dict(s) for s in db.query(EmailSessionRow).filter_by(analysis_id=a.id).order_by(EmailSessionRow.stream_id)],
        "tls": [tls_dict(t) for t in db.query(TlsSessionRow).filter_by(analysis_id=a.id).order_by(TlsSessionRow.stream_id)],
        "certificates": [cert_dict(c) for c in db.query(CertificateRow).filter_by(analysis_id=a.id).order_by(CertificateRow.stream_id, CertificateRow.position)],
        "findings": fd, "finding_groups": group_findings(fd), "limitations": a.limitations, "engine_errors": a.engine_errors,
        "methodology": METHODOLOGY, "references": REFERENCES, "risk_model": MODEL_VERSION,
        "disclaimer": "Passive assessment of the supplied capture only. Student proof-of-concept: results are not a substitute for a full security audit. Certificate metadata was extracted; trust (chain/revocation) was not validated.",
    }


# ------------------------------------------------------------------ HTML
_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<title>SecureMailScope report - {{ d.capture.filename }}</title>
<style>
body{font:14px/1.55 -apple-system,Segoe UI,Inter,Roboto,sans-serif;color:#18212f;max-width:980px;margin:32px auto;padding:0 20px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;border-bottom:2px solid #36d6b0;padding-bottom:4px;margin-top:30px}h3{font-size:14px;margin:16px 0 4px}
.sub{color:#5a6a80}.banner{background:#fff6e0;border:1px solid #f5b942;padding:8px 12px;border-radius:6px;margin:12px 0;font-weight:600}
table{border-collapse:collapse;width:100%;margin:8px 0;font-size:13px}th,td{border:1px solid #d7dfea;padding:6px 8px;text-align:left;vertical-align:top}th{background:#eef3f9}
.sev{display:inline-block;padding:1px 8px;border-radius:10px;color:#fff;font-size:12px;font-weight:600}.critical{background:#c0303b}.high{background:#e0626a;}.medium{background:#d69a1e}.low{background:#3f7fd6}.info{background:#6b7b90}
code{background:#eef3f9;padding:1px 4px;border-radius:3px;font-size:12px;word-break:break-all}.finding{border:1px solid #d7dfea;border-radius:8px;padding:10px 14px;margin:12px 0;page-break-inside:avoid}
.ai{border-left:4px solid #68a7ff;background:#f1f7ff;padding:8px 12px;margin:10px 0}.muted{color:#5a6a80;font-size:12px}
</style></head><body>
<h1>{{ d.title }}</h1>
<div class="sub">Team {{ d.project.team }} · Project {{ d.project.project_id }} · {{ d.project.institution }} · {{ d.project.domain }}</div>
{% if d.is_demo %}<div class="banner">CONTROLLED SYNTHETIC DEMONSTRATION DATA - NOT REAL CUSTOMER TRAFFIC.</div>{% endif %}
<h2>1. Capture metadata</h2>
<table><tr><th>File</th><td>{{ d.capture.filename }}</td><th>Format</th><td>{{ d.capture.format }} ({{ d.capture.linktype }})</td></tr>
<tr><th>SHA-256</th><td colspan="3"><code>{{ d.capture.sha256 }}</code></td></tr>
<tr><th>Size</th><td>{{ d.capture.size_bytes }} bytes</td><th>Packets</th><td>{{ d.capture.packets }}</td></tr>
<tr><th>Analysis ID</th><td>{{ d.analysis.id }}</td><th>Analysed with</th><td>{{ d.analysis.tool }}</td></tr>
<tr><th>Rule-set version</th><td>{{ d.analysis.ruleset_version }}</td><th>Generated</th><td>{{ d.generated_at }}</td></tr></table>
<h2>2. Executive summary</h2><p>{{ d.executive_summary.text }}</p>
<p class="muted">Source: {{ d.executive_summary.source }}. Severity counts - {% for s,n in d.severity.items() %}{{ s }}: {{ n }}{{ ", " if not loop.last }}{% endfor %}.</p>
{% if d.ai_summary and d.ai_summary.status == 'generated' %}<div class="ai"><b>AI-generated explanation</b> ({{ d.ai_summary.provider }} / {{ d.ai_summary.model }}). <i>{{ d.ai_summary.label }}</i><p>{{ d.ai_summary.executive_summary }}</p>
{% for p in d.ai_summary.priorities %}<div>• <code>{{ p.rule_id }}</code> {{ p.rationale }}</div>{% endfor %}</div>{% endif %}
<h2>3. Protocol analysis</h2>
{% for s in d.protocols %}<h3>{{ s.protocol|upper }} session (stream {{ s.stream_id }}) {{ s.client }} → {{ s.server }}</h3>
<div class="muted">Detected by {{ s.detected_by }} · completeness {{ s.completeness }}{% if s.implicit_tls %} · implicit TLS{% endif %}</div>
<table><tr><th>Item</th><th>State</th></tr>{% for k,v in s.states.items() %}<tr><td>{{ k.replace('_',' ') }}</td><td>{{ v.replace('_',' ') }}</td></tr>{% endfor %}</table>
{% else %}<p>No SMTP, IMAP or POP3 sessions were identified.</p>{% endfor %}
<h2>4. TLS posture</h2>
{% for t in d.tls %}<h3>Stream {{ t.stream_id }} ({{ t.carrier_protocol }}{% if t.via_starttls %}, via STARTTLS/STLS{% endif %}) - evidence {{ t.completeness }}</h3>
<table><tr><th>Negotiated version</th><td>{{ t.selected_version or 'not observed' }}{% if t.server_hello %} ({{ t.server_hello.version_source }}){% endif %}</td><th>Selected cipher</th><td>{{ t.selected_cipher or 'not observed' }}</td></tr>
<tr><th>Client offered</th><td>{{ t.client_hello.cipher_suites|length if t.client_hello else 'ClientHello unavailable' }} suites</td><th>SNI</th><td>{{ (t.client_hello.sni if t.client_hello else None) or 'not visible' }}</td></tr></table>
{% for n in t.notes %}<div class="muted">Note: {{ n }}</div>{% endfor %}{% else %}<p>No TLS handshakes were observed.</p>{% endfor %}
<h2>5. Certificate observations</h2>
<p class="muted">Metadata extraction only. Trust-chain and revocation validation were <b>not</b> performed.</p>
{% for c in d.certificates %}<table><tr><th>Subject</th><td>{{ c.subject }}</td><th>Issuer</th><td>{{ c.issuer }}</td></tr>
<tr><th>Validity</th><td>{{ c.not_before[:10] }} to {{ c.not_after[:10] }}</td><th>Key / signature</th><td>{{ c.key_algorithm }} {{ c.key_size }} / {{ c.sig_algorithm }}</td></tr>
<tr><th>SHA-256</th><td colspan="3"><code>{{ c.sha256 }}</code></td></tr></table>{% else %}<p>No certificates were observable (none present, or encrypted under TLS 1.3).</p>{% endfor %}
<h2>6. Security findings</h2>
{% for f in d.findings %}<div class="finding"><b>{{ f.ref }} · {{ f.title }}</b> <span class="sev {{ f.severity }}">{{ f.severity|upper }}</span> <code>{{ f.rule_id }}</code>
<div class="muted">{{ f.category }} · {{ f.protocol or '-' }} · stream {{ f.stream_id }} · {{ f.observation_type.replace('_',' ') }} · evidence {{ f.completeness }} · risk {{ f.risk_score }}/100</div>
<p>{{ f.description }}</p><p><b>Technical:</b> {{ f.technical }}</p><p><b>Impact:</b> {{ f.impact }}</p><p><b>Remediation:</b> {{ f.remediation }}</p>
<div class="muted">Evidence: {% for e in f.evidence %}{{ e.ref }} (frame {{ e.frame or 'n/a' }}, stream {{ e.stream_id }}){{ ", " if not loop.last }}{% endfor %}</div></div>
{% else %}<p>No findings.</p>{% endfor %}
<h2>7. Risk prioritisation</h2><p class="muted">Model {{ d.risk_model }} - deterministic and explainable; not CVSS.</p>
<table><tr><th>Rule</th><th>Finding</th><th>Severity</th><th>Max score</th><th>Sessions</th></tr>{% for g in d.finding_groups %}<tr><td><code>{{ g.rule_id }}</code></td><td>{{ g.title }}</td><td>{{ g.severity }}</td><td>{{ g.risk_score }}</td><td>{{ g.count }}</td></tr>{% endfor %}</table>
<h2>8. Analysis limitations</h2><ul>{% for l in d.limitations %}<li>{{ l }}</li>{% endfor %}{% for e in d.engine_errors %}<li><b>Engine error:</b> {{ e }}</li>{% endfor %}</ul>
<h2>9. Methodology</h2><ol>{% for m in d.methodology %}<li>{{ m }}</li>{% endfor %}</ol>
<h2>10. Technical references</h2><ul>{% for r in d.references %}<li>{{ r }}</li>{% endfor %}</ul>
<p class="muted">{{ d.disclaimer }}</p></body></html>"""
_env = Environment(autoescape=select_autoescape(["html"], default=True), trim_blocks=True, lstrip_blocks=True)


def render_html(d: dict) -> bytes:
    return _env.from_string(_HTML).render(d=d).encode("utf-8")


def render_json(d: dict) -> bytes:
    return json.dumps(d, indent=2, default=str).encode("utf-8")


def _csv_safe(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s  # neutralise spreadsheet formula injection


def render_csv(d: dict) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["finding_id", "rule_id", "title", "severity", "category", "protocol", "stream", "observation_type", "evidence_completeness", "risk_score", "status", "description", "technical", "impact", "remediation", "evidence_refs"])
    for f in d["findings"]:
        w.writerow([_csv_safe(x) for x in (f["ref"], f["rule_id"], f["title"], f["severity"], f["category"], f["protocol"], f["stream_id"], f["observation_type"], f["completeness"], f["risk_score"], f["status"],
                                         f["description"], f["technical"], f["impact"], f["remediation"], "; ".join(f"{e['ref']}@frame{e['frame']}" for e in f["evidence"]))])
    return buf.getvalue().encode("utf-8")


def render_pdf(d: dict) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    ss = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], fontSize=16, textColor=colors.HexColor("#0d1421"))
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontSize=12.5, textColor=colors.HexColor("#0d6b57"), spaceBefore=12)
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9, leading=12)
    small = ParagraphStyle("s", parent=body, fontSize=8, textColor=colors.HexColor("#5a6a80"))
    sevc = {"critical": "#c0303b", "high": "#e0626a", "medium": "#d69a1e", "low": "#3f7fd6", "info": "#6b7b90"}
    P = lambda t, st=body: Paragraph(escape(str(t)), st)  # noqa: E731
    out = io.BytesIO()
    doc = SimpleDocTemplate(out, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=14 * mm, bottomMargin=14 * mm, title="SecureMailScope report", author="SecureMailScope")
    s: list = [P(d["title"], h1), P(f"Team {d['project']['team']} · Project {d['project']['project_id']} · {d['project']['institution']}", small)]
    if d["is_demo"]:
        s.append(P("CONTROLLED SYNTHETIC DEMONSTRATION DATA - NOT REAL CUSTOMER TRAFFIC.", ParagraphStyle("w", parent=body, textColor=colors.HexColor("#a66a00"), fontName="Helvetica-Bold")))
    c = d["capture"]
    s += [P("1. Capture metadata", h2)]
    t = Table([[P("File"), P(c["filename"])], [P("SHA-256"), P(c["sha256"], small)], [P("Format / link"), P(f"{c['format']} / {c['linktype']}")], [P("Packets / size"), P(f"{c['packets']} / {c['size_bytes']} bytes")],
               [P("Analysis"), P(f"{d['analysis']['id']} · rule-set {d['analysis']['ruleset_version']} · {d['analysis']['tool']}")]], colWidths=[32 * mm, 140 * mm])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#c4cfdd")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    s += [t, P("2. Executive summary", h2), P(d["executive_summary"]["text"])]
    ai = d.get("ai_summary")
    if ai and ai.get("status") == "generated":
        s += [Spacer(1, 4), P("AI-generated explanation (" + f"{ai.get('provider')}/{ai.get('model')}" + "): " + ai.get("executive_summary", ""), small), P(ai["label"], small)]
    s.append(P("3. Protocol analysis", h2))
    for x in d["protocols"] or [None]:
        s.append(P(f"{x['protocol'].upper()} stream {x['stream_id']} {x['client']} -> {x['server']} (completeness {x['completeness']})" if x else "No SMTP/IMAP/POP3 sessions identified."))
        if x:
            s.append(P("; ".join(f"{k.replace('_', ' ')}: {v.replace('_', ' ')}" for k, v in x["states"].items()), small))
    s.append(P("4. TLS posture", h2))
    for x in d["tls"] or [None]:
        s.append(P(f"Stream {x['stream_id']}: version {x['selected_version'] or 'not observed'}, cipher {x['selected_cipher'] or 'not observed'} (evidence {x['completeness']})" if x else "No TLS handshakes observed."))
        if x:
            for n in x["notes"]:
                s.append(P("Note: " + n, small))
    s += [P("5. Certificate observations", h2), P("Metadata extraction only - trust chain and revocation were not validated.", small)]
    for x in d["certificates"] or [None]:
        s.append(P(f"{x['subject']} (issuer {x['issuer']}), valid {x['not_before'][:10]} to {x['not_after'][:10]}, {x['key_algorithm']} {x['key_size']}, {x['sig_algorithm']}" if x else "No certificates observable."))
    s.append(P("6. Security findings", h2))
    for f in d["findings"]:
        head = Table([[P(f"{f['ref']} {f['title']}"), P(f["severity"].upper(), ParagraphStyle("sv", parent=body, textColor=colors.white, fontName="Helvetica-Bold", alignment=1))]],
                     colWidths=[150 * mm, 22 * mm])
        head.setStyle(TableStyle([("BACKGROUND", (1, 0), (1, 0), colors.HexColor(sevc[f["severity"]])), ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
        s += [Spacer(1, 5), head, P(f"{f['rule_id']} · {f['category']} · {f['observation_type'].replace('_', ' ')} · evidence {f['completeness']} · risk {f['risk_score']}/100", small),
              P(f["description"]), P("Technical: " + f["technical"], small), P("Impact: " + f["impact"], small), P("Remediation: " + f["remediation"]),
              P("Evidence: " + ", ".join(f"{e['ref']} (frame {e['frame'] or 'n/a'})" for e in f["evidence"]), small)]
    if not d["findings"]:
        s.append(P("No findings."))
    s.append(P("7. Risk prioritisation", h2))
    rows = [[P("Rule"), P("Finding"), P("Sev."), P("Score")]] + [[P(g["rule_id"], small), P(g["title"], small), P(g["severity"]), P(g["risk_score"])] for g in d["finding_groups"]]
    rt = Table(rows, colWidths=[24 * mm, 108 * mm, 20 * mm, 20 * mm], repeatRows=1)
    rt.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#c4cfdd")), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef3f9"))]))
    s += [rt, P(f"Scoring model {d['risk_model']} (deterministic; not CVSS).", small), P("8. Analysis limitations", h2)]
    s += [P("• " + x) for x in d["limitations"]] + [P("• Engine error: " + e) for e in d["engine_errors"]]
    s += [P("9. Methodology", h2)] + [P(f"{i}. {m}") for i, m in enumerate(d["methodology"], 1)]
    s += [P("10. Technical references", h2)] + [P("• " + r) for r in d["references"]] + [Spacer(1, 8), P(d["disclaimer"], small)]
    doc.build(s)
    return out.getvalue()


RENDERERS = {"json": render_json, "html": render_html, "csv": render_csv, "pdf": render_pdf}
MIME = {"json": "application/json", "html": "text/html; charset=utf-8", "csv": "text/csv; charset=utf-8", "pdf": "application/pdf"}


def generate(db: Session, analysis_id: str, fmt: str) -> GeneratedReport:
    if fmt not in RENDERERS:
        raise ValueError(f"unsupported report format '{fmt}'")
    d = build_report_data(db, analysis_id)
    blob = RENDERERS[fmt](d)
    settings.ensure_dirs()
    base = sanitize_filename(Path(d["capture"]["filename"]).stem)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S")
    name = f"securemailscope_{base}_{analysis_id[:8]}_{stamp}.{fmt if fmt != 'csv' else 'findings.csv'}"
    path = settings.reports_path / name
    path.write_bytes(blob)
    row = GeneratedReport(analysis_id=analysis_id, format=fmt, filename=name, path=str(path), size_bytes=len(blob), sha256=hashlib.sha256(blob).hexdigest())
    db.add(row)
    db.commit()
    return row
