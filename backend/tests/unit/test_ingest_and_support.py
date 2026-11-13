import json
import shutil
import struct
import subprocess

import pytest

from app.services.capture_service import CaptureRejected, validate_capture
from app.services.cipher_catalog import classify, version_name
from tests.conftest import DEMO


def test_valid_pcap_metadata():
    m = validate_capture(DEMO / "smtp_starttls_tls12_complete.pcap")
    assert m.format == "pcap" and m.linktype == 1 and m.packet_count == 28 and not m.truncated_tail


@pytest.mark.parametrize("name,code", [("corrupted.pcap", "corrupt"), ("empty.pcap", "empty"), ("unsupported_linktype.pcap", "unsupported_linktype")])
def test_rejections(name, code):
    with pytest.raises(CaptureRejected) as e:
        validate_capture(DEMO / name)
    assert e.value.code == code


def test_non_capture_and_zero_byte(tmp_path):
    p = tmp_path / "a.pcap"
    p.write_bytes(b"")
    with pytest.raises(CaptureRejected) as e:
        validate_capture(p)
    assert e.value.code == "empty"
    p.write_bytes(b"MZ" + b"\x00" * 100)
    with pytest.raises(CaptureRejected) as e:
        validate_capture(p)
    assert e.value.code == "unrecognised_format"


def test_truncated_tail_is_warning_not_failure(tmp_path):
    p = tmp_path / "t.pcap"
    p.write_bytes((DEMO / "smtp_starttls_tls12_complete.pcap").read_bytes()[:-20])
    m = validate_capture(p)
    assert m.truncated_tail and m.warnings


@pytest.mark.skipif(not shutil.which("editcap"), reason="editcap not installed")
def test_pcapng_accepted_and_analysable(tmp_path):
    out = tmp_path / "x.pcapng"
    subprocess.run(["editcap", "-F", "pcapng", str(DEMO / "smtp_starttls_tls12_complete.pcap"), str(out)], check=True, capture_output=True)
    m = validate_capture(out)
    assert m.format == "pcapng" and m.packet_count == 28
    from app.services.engine import run_engine

    r = run_engine(out, "x.pcapng")
    assert {d.rule_id for d in r.drafts} == {"SMS-STL-001", "SMS-TLS-014"}


def test_cipher_classification():
    assert classify(0xC030).weak_class is None and classify(0xC030).forward_secret and classify(0xC030).aead
    assert classify(0x000A).weak_class == "3des" and classify(0x0005).weak_class == "rc4" and classify(0x0002).weak_class == "null"
    assert classify(0x0003).weak_class == "export" and classify(0x0018).weak_class == "anon"
    assert classify(0x0035).forward_secret is False and classify(0x1301).forward_secret is True
    u = classify(0xABCD)
    assert not u.known and u.weak_class is None and u.name == "UNKNOWN_0xABCD"
    assert version_name(0x0304) == "TLSv1.3" and version_name(0x0301) == "TLSv1.0"


def test_risk_scores_are_deterministic_and_explainable():
    from app.rules.base import FindingDraft
    from app.services.risk_engine import score_findings

    def d(sev, obs, comp, rid="X"):
        return FindingDraft(rid, "t", sev, "c", None, 0, "", "", "", "", obs, comp)

    r = score_findings([d("high", "weakness_observed", "complete", "A"), d("high", "weakness_observed", "incomplete", "B"), d("info", "secure_configuration", "complete", "C"), d("critical", "weakness_observed", "complete", "D")])
    assert [x["score"] for x in r] == [70, 42, 1, 90] and r[0]["model"] == "SMRS-1" and r[0]["factors"]
    many = score_findings([d("medium", "weakness_observed", "complete", "R")] * 3)
    assert many[0]["score"] == 45 + 6 and "NOT" not in many[0]["explanation"]
    assert all(0 <= x["score"] <= 100 for x in score_findings([d("critical", "weakness_observed", "complete", "A")] * 12))


def test_ai_validation_blocks_invented_findings_and_remote_hosts():
    from app.ai.prioritizer import parse_and_validate
    from app.ai.provider import AiError, build_provider, check_endpoint

    raw = json.dumps({"executive_summary": "ok", "priorities": [{"rule_id": "SMS-TLS-001", "rationale": "x"}, {"rule_id": "SMS-FAKE-999", "rationale": "invented"}]})
    out = parse_and_validate(raw, {"SMS-TLS-001"})
    assert [p["rule_id"] for p in out["priorities"]] == ["SMS-TLS-001"] and out["discarded_unknown_rule_ids"] == ["SMS-FAKE-999"]
    with pytest.raises(ValueError):
        parse_and_validate("not json", {"A"})
    with pytest.raises(AiError):
        check_endpoint("https://api.example.com", local_only=True)
    check_endpoint("http://localhost:11434", local_only=True)
    assert build_provider({"ai_provider": "none"}) is None


def test_ai_summary_uses_only_structured_metadata_and_labels_output():
    import httpx

    from app.ai.explanation_service import AI_LABEL, generate_ai_summary
    from app.ai.provider import OllamaProvider

    seen = {}

    def handler(request: httpx.Request):
        seen["body"] = request.content.decode()
        return httpx.Response(200, json={"response": json.dumps({"executive_summary": "Summary", "priorities": [{"rule_id": "SMS-TLS-001", "rationale": "r"}]})})

    import app.ai.explanation_service as svc

    orig = svc.build_provider
    svc.build_provider = lambda cfg, key=None: OllamaProvider(cfg["ai_endpoint"], cfg["ai_model"], httpx.Client(transport=httpx.MockTransport(handler)))
    try:
        f = [{"rule_id": "SMS-TLS-001", "title": "Deprecated", "severity": "high", "category": "c", "protocol": "SMTP", "observation_type": "weakness_observed", "completeness": "complete", "risk_score": 70}]
        res = generate_ai_summary({"ai_provider": "ollama", "ai_endpoint": "http://localhost:11434", "ai_model": "m", "local_only_mode": True}, f)
    finally:
        svc.build_provider = orig
    assert res["status"] == "generated" and res["label"] == AI_LABEL and res["priorities"][0]["rule_id"] == "SMS-TLS-001"
    assert "192.0.2" not in seen["body"] and "pcap" not in seen["body"].lower()


def test_disabled_ai_still_gives_builtin_summary():
    from app.ai.explanation_service import builtin_summary, generate_ai_summary

    assert generate_ai_summary({"ai_provider": "none"}, [])["status"] == "disabled"
    s = builtin_summary([{"severity": "high", "observation_type": "weakness_observed", "title": "T", "rule_id": "SMS-TLS-001", "risk_score": 70}], {"packets": 5, "email_sessions": 1}, [])
    assert "1 high" in s["text"] and s["source"].startswith("built-in")


def test_report_html_escapes_and_csv_neutralises_formulas():
    from app.services.report_service import _csv_safe, render_csv, render_html

    assert _csv_safe("=HYPERLINK(\"http://evil\")") .startswith("'") and _csv_safe("+1") == "'+1" and _csv_safe("normal") == "normal"
    d = {"title": "T", "project": {"team": "t", "project_id": "p", "institution": "i", "domain": "d"}, "is_demo": False, "generated_at": "now", "capture": {"filename": "<script>alert(1)</script>.pcap", "sha256": "a", "size_bytes": 1,
         "format": "pcap", "linktype": "Ethernet", "packets": 1}, "analysis": {"id": "1", "ruleset_version": "v", "tool": "t"}, "executive_summary": {"text": "<img src=x onerror=1>", "source": "s"},
         "severity": {}, "ai_summary": None, "protocols": [], "tls": [], "certificates": [], "findings": [{"ref": "F", "title": "=cmd|' /C calc'!A0", "severity": "high", "rule_id": "R", "category": "c", "protocol": "SMTP", "stream_id": 0,
         "observation_type": "weakness_observed", "completeness": "complete", "risk_score": 1, "status": "open", "description": "<b>x</b>", "technical": "t", "impact": "i", "remediation": "r", "evidence": []}],
         "finding_groups": [], "limitations": ["<l>"], "engine_errors": [], "methodology": [], "references": [], "risk_model": "SMRS-1", "disclaimer": "d"}
    html = render_html(d).decode()
    assert "<script>" not in html and "&lt;script&gt;" in html and "<img src=x" not in html and "<b>x</b>" not in html
    assert b"'=cmd" in render_csv(d)


def test_tshark_runner_rejects_unsafe_arguments(tmp_path):
    from app.services import tshark_runner as t

    with pytest.raises(ValueError):
        list(t.run_fields(tmp_path / "x.pcap", ["frame.number; rm -rf /"]))
    with pytest.raises(ValueError):
        t.run_json(tmp_path / "x.pcap", display_filter="tcp; $(id)")
    with pytest.raises(ValueError):
        t._decode_args([(25, "bash")])
    with pytest.raises(ValueError):
        t._decode_args([(70000, "smtp")])


def test_ensure_within_blocks_traversal(tmp_path):
    from app.core.security import ensure_within, sanitize_filename

    with pytest.raises(ValueError):
        ensure_within(tmp_path, tmp_path / ".." / "etc" / "passwd")
    assert sanitize_filename("../../../x y.pcap") == "x_y.pcap" and sanitize_filename("..") == "capture"
