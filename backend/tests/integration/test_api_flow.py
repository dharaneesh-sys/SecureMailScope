"""End-to-end API flow against real TShark analysis of the synthetic fixtures."""

import io

import pytest

from tests.conftest import DEMO, wait_done


def test_health_and_dependencies(client):
    h = client.get("/api/health").json()
    assert h["status"] == "ok" and h["tshark"] is True and h["rules"] >= 20
    d = client.get("/api/system/dependencies").json()
    assert d["tshark"]["available"] and d["tshark"]["version"].startswith("TShark")


@pytest.mark.parametrize("name,code", [("corrupted.pcap", "corrupt"), ("empty.pcap", "empty"), ("unsupported_linktype.pcap", "unsupported_linktype")])
def test_invalid_captures_rejected_at_upload(client, name, code):
    with open(DEMO / name, "rb") as fh:
        r = client.post("/api/captures", files={"file": (name, fh, "application/octet-stream")})
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == code


def test_rejects_wrong_extension_and_non_pcap_content(client):
    r = client.post("/api/captures", files={"file": ("notes.txt", io.BytesIO(b"hello"), "text/plain")})
    assert r.status_code == 415
    r = client.post("/api/captures", files={"file": ("fake.pcap", io.BytesIO(b"This is not a capture file at all, just text." * 3), "application/octet-stream")})
    assert r.status_code == 422 and r.json()["detail"]["code"] == "unrecognised_format"


def test_path_traversal_filename_is_neutralised(client):
    data = (DEMO / "smtp_plaintext_auth.pcap").read_bytes()
    r = client.post("/api/captures", files={"file": ("../../etc/passwd.pcap", io.BytesIO(data), "application/octet-stream")})
    assert r.status_code in (201, 200)
    assert "/" not in r.json()["capture"]["filename"] and ".." not in r.json()["capture"]["filename"]


def test_analysis_requires_authorisation_confirmation(client, analyse):
    cap = analyse("smtp_starttls_rejected.pcap")["capture"]
    r = client.post("/api/analyses", json={"capture_id": cap["id"], "authorised_confirmation": False})
    assert r.status_code == 422
    assert client.post("/api/analyses", json={"capture_id": "deadbeef", "authorised_confirmation": True}).status_code == 404


def test_full_workflow_complete_handshake(client, analyse):
    run = analyse("smtp_starttls_tls12_complete.pcap")
    assert run["status"]["status"] == "completed", run["status"]
    st = run["status"]
    assert st["progress"] == 100 and all(s["status"] == "done" for s in st["stage_log"])
    assert [s["key"] for s in st["stage_log"]][:3] == ["file_validation", "pcap_metadata", "packet_decoding"]
    aid = run["analysis_id"]
    summary = client.get(f"/api/analyses/{aid}/summary").json()
    assert summary["counters"]["email_sessions"] == 1 and summary["counters"]["tls_handshakes"] == 1 and summary["counters"]["certificates"] == 2
    tls = client.get(f"/api/analyses/{aid}/tls").json()["sessions"][0]
    assert tls["selected_version"] == "TLSv1.2" and tls["selected_cipher"] == "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    assert tls["client_hello"]["sni"] == "mail.example.test" and tls["completeness"] == "complete"
    certs = client.get(f"/api/analyses/{aid}/certificates").json()
    assert certs["certificates"][0]["key_algorithm"] == "RSA" and certs["certificates"][0]["key_size"] == 2048
    assert "NOT performed" in certs["notice"]
    proto = client.get(f"/api/analyses/{aid}/protocols").json()["sessions"][0]
    assert proto["protocol"] == "smtp" and proto["starttls"]["accepted"] is True and proto["starttls"]["tls_followed"] is True
    assert proto["states"]["tls_transition"] == "observed" and proto["states"]["content_after_tls"] == "undecodable"


def test_findings_filters_evidence_and_status_history(client, analyse):
    aid = analyse("smtp_deprecated_tls10.pcap")["analysis_id"]
    all_f = client.get(f"/api/analyses/{aid}/findings?page_size=100").json()
    assert all_f["total"] >= 8
    hi = client.get(f"/api/analyses/{aid}/findings?severity=high").json()
    assert hi["total"] >= 1 and all(f["severity"] == "high" for f in hi["items"])
    assert client.get(f"/api/analyses/{aid}/findings?q=expired").json()["total"] == 1
    assert client.get(f"/api/analyses/{aid}/findings?protocol=smtp&category=Deprecated%20TLS").json()["total"] >= 1
    f = next(x for x in all_f["items"] if x["rule_id"] == "SMS-TLS-001")
    detail = client.get(f"/api/findings/{f['id']}").json()
    assert detail["evidence"] and detail["evidence"][0]["frame"] and detail["tls_session"]["selected_version"] == "TLSv1.0"
    # evidence -> packet -> session navigation
    ev = client.get(f"/api/evidence/{detail['evidence'][0]['id']}").json()
    assert ev["finding"]["id"] == f["id"] and ev["packet"]["raw_hex"] and ev["packet"]["tree"]["tls"]
    assert ev["session"]["protocol"] == "smtp"
    # status changes keep history and never alter evidence
    ev_before = [e["fields"] for e in detail["evidence"]]
    r = client.patch(f"/api/findings/{f['id']}/status", json={"status": "under_review", "note": "checking"}).json()
    r = client.patch(f"/api/findings/{f['id']}/status", json={"status": "resolved"}).json()
    assert r["status"] == "resolved" and [h["new_status"] for h in r["history"]] == ["under_review", "resolved"]
    assert [e["fields"] for e in r["evidence"]] == ev_before
    assert client.patch(f"/api/findings/{f['id']}/status", json={"status": "bogus"}).status_code == 422


def test_plaintext_credentials_never_stored(client, analyse):
    aid = analyse("smtp_plaintext_auth.pcap")["analysis_id"]
    blob = str(client.get(f"/api/analyses/{aid}/protocols").json()) + str(client.get(f"/api/analyses/{aid}/evidence").json()) + str(client.get(f"/api/analyses/{aid}/findings?page_size=100").json())
    assert "AAAAAAAA" not in blob and "sender@example.test" not in blob
    assert "[credentials not stored]" in blob


def test_incomplete_capture_is_safe_fallback(client, analyse):
    aid = analyse("smtp_incomplete_clienthello_only.pcap")["analysis_id"]
    items = client.get(f"/api/analyses/{aid}/findings?page_size=100").json()["items"]
    rules = {f["rule_id"] for f in items}
    assert {"SMS-TLS-012", "SMS-TLS-013"} <= rules
    assert not rules & {"SMS-TLS-001", "SMS-CIP-001", "SMS-CIP-003", "SMS-TLS-014"}  # nothing fabricated
    assert all(f["observation_type"] in ("insufficient_evidence", "protocol_feature") for f in items)
    tls = client.get(f"/api/analyses/{aid}/tls").json()["sessions"][0]
    assert tls["server_hello"] is None and tls["selected_version"] is None and tls["selected_cipher"] is None


def test_tls13_certificate_reported_unavailable(client, analyse):
    aid = analyse("smtp_starttls_tls13.pcap")["analysis_id"]
    certs = client.get(f"/api/analyses/{aid}/certificates").json()
    assert certs["certificates"] == [] and "TLS 1.3" in certs["unavailable"][0]["reason"]
    tls = client.get(f"/api/analyses/{aid}/tls").json()["sessions"][0]
    assert tls["selected_version"] == "TLSv1.3" and tls["server_hello"]["version_source"] == "supported_versions"
    assert tls["server_hello"]["legacy_version"] == "TLSv1.2"  # legacy field must not be mistaken for the negotiated version


def test_retransmission_and_reordering_handled(client, analyse):
    aid = analyse("smtp_retransmit_reorder.pcap")["analysis_id"]
    streams = client.get(f"/api/analyses/{aid}/protocols").json()["streams"]
    q = streams[0]["quality"]
    assert q["retransmissions"] + q["out_of_order"] >= 1
    tls = client.get(f"/api/analyses/{aid}/tls").json()["sessions"][0]
    assert tls["completeness"] == "complete" and tls["selected_version"] == "TLSv1.2"


def test_options_actually_change_behaviour(client, analyse):
    run = analyse("smtp_deprecated_tls10.pcap", options={"inspect_certificates": False})
    assert run["status"]["status"] == "completed"
    aid = run["analysis_id"]
    assert client.get(f"/api/analyses/{aid}/certificates").json()["certificates"] == []
    rules = {f["rule_id"] for f in client.get(f"/api/analyses/{aid}/findings?page_size=100").json()["items"]}
    assert "SMS-CRT-001" not in rules and "SMS-TLS-001" in rules
    run2 = analyse("smtp_deprecated_tls10.pcap", options={"detect_smtp": False})
    assert client.get(f"/api/analyses/{run2['analysis_id']}/summary").json()["counters"]["email_sessions"] == 0


def test_duplicate_upload_warning(client, analyse):
    analyse("smtp_starttls_rejected.pcap")
    with open(DEMO / "smtp_starttls_rejected.pcap", "rb") as fh:
        r = client.post("/api/captures", files={"file": ("copy.pcap", fh, "application/octet-stream")})
    assert r.status_code == 201 and r.json()["duplicate"] is True


def test_dashboard_metrics_come_from_database(client, analyse):
    analyse("smtp_starttls_tls12_complete.pcap")
    d = client.get("/api/dashboard").json()
    m = d["metrics"]
    assert m["captures"] >= 1 and m["analyses_completed"] >= 1 and m["email_sessions"] >= 1
    sess_total = sum(p["value"] for p in d["protocols"])
    assert sess_total == m["email_sessions"]
    assert sum(d["severity"].values()) == m["findings"]
    assert m["success_rate"] is not None


@pytest.mark.parametrize("fmt,ctype,magic", [("json", "application/json", b"{"), ("html", "text/html", b"<!doctype html>"), ("csv", "text/csv", b"finding_id"), ("pdf", "application/pdf", b"%PDF")])
def test_report_generation_and_download(client, analyse, fmt, ctype, magic):
    aid = analyse("smtp_deprecated_tls10.pcap")["analysis_id"]
    r = client.post(f"/api/analyses/{aid}/reports", json={"format": fmt})
    assert r.status_code == 201, r.text
    d = client.get(f"/api/reports/{r.json()['id']}/download")
    assert d.status_code == 200 and d.headers["content-type"].startswith(ctype) and d.content.startswith(magic)
    assert "attachment" in d.headers["content-disposition"]
    if fmt == "json":
        data = d.json()
        assert data["findings"] and data["capture"]["filename"] == "smtp_deprecated_tls10.pcap" and "NOT" not in data["disclaimer"][:0]
    if fmt == "html":
        assert "default-src 'none'" in d.headers["content-security-policy"]
        assert b"CONTROLLED SYNTHETIC" not in d.content  # only shown for demo-flagged captures
    assert any(x["id"] == r.json()["id"] for x in client.get("/api/reports").json()["items"])


def test_report_preview_is_sandboxed_html(client, analyse):
    aid = analyse("smtp_deprecated_tls10.pcap")["analysis_id"]
    r = client.get(f"/api/analyses/{aid}/report-preview")
    assert r.status_code == 200 and "sandbox" in r.headers["content-security-policy"] and b"SMS-TLS-001" in r.content


def test_rule_toggle_creates_new_ruleset_version_and_old_results_unchanged(client, analyse):
    aid = analyse("smtp_legacy_cipher_tls12.pcap")["analysis_id"]
    before = client.get(f"/api/analyses/{aid}/summary").json()
    old_ver = before["analysis"]["ruleset_version"]
    r = client.patch("/api/rules/SMS-CIP-002", json={"enabled": False})
    assert r.status_code == 200 and r.json()["enabled"] is False
    rules = client.get("/api/rules").json()
    assert rules["current_ruleset"] != old_ver and any(h["signature"] == old_ver for h in rules["history"])
    after = client.get(f"/api/analyses/{aid}/summary").json()
    assert after["analysis"]["ruleset_version"] == old_ver and after["severity"] == before["severity"]
    rerun = client.post(f"/api/analyses/{aid}/rerun").json()
    wait_done(client, rerun["id"])
    new_rules = {f["rule_id"] for f in client.get(f"/api/analyses/{rerun['id']}/findings?page_size=100").json()["items"]}
    assert "SMS-CIP-002" not in new_rules and "SMS-CIP-001" in new_rules
    assert client.get(f"/api/analyses/{rerun['id']}/summary").json()["analysis"]["ruleset_version"] == rules["current_ruleset"]
    client.patch("/api/rules/SMS-CIP-002", json={"enabled": True})


def test_cancel_queued_analysis(client, analyse, monkeypatch):
    from app.workers import pipeline

    cap = analyse("smtp_starttls_rejected.pcap")["capture"]
    monkeypatch.setattr(pipeline, "submit", lambda _id: None)
    a = client.post("/api/analyses", json={"capture_id": cap["id"], "authorised_confirmation": True}).json()
    assert a["status"] == "queued"
    assert client.post(f"/api/analyses/{a['id']}/cancel").json()["status"] == "cancelled"
    assert client.post(f"/api/analyses/{a['id']}/cancel").status_code == 409
    assert client.get(f"/api/analyses/{a['id']}/summary").status_code == 409  # results gated on completion


def test_tshark_missing_gives_clear_error(client, analyse, monkeypatch):
    from app.core.config import settings

    cap = analyse("smtp_starttls_rejected.pcap")["capture"]
    monkeypatch.setattr(settings, "tshark_path", "/nonexistent/tshark")
    d = client.get("/api/system/dependencies").json()
    assert d["tshark"]["available"] is False and "Install" in d["guidance"]
    r = client.post("/api/analyses", json={"capture_id": cap["id"], "authorised_confirmation": True})
    assert r.status_code == 503 and r.json()["detail"]["code"] == "tshark_missing"


def test_demo_dataset_uses_real_pipeline_and_can_be_removed(client):
    r = client.post("/api/demo/load")
    assert r.status_code == 201
    created = r.json()["created"]
    assert "SYNTHETIC" in r.json()["label"]
    for c in created:
        assert wait_done(client, c["analysis_id"])["status"] == "completed"
    caps = client.get("/api/captures?page_size=100").json()["items"]
    assert any(c["is_demo"] for c in caps)
    assert client.get("/api/dashboard").json()["demo_loaded"] is True
    assert client.delete("/api/demo").json()["removed"] >= 0


def test_delete_capture_removes_everything(client, analyse):
    run = analyse("smtp_nonstandard_port.pcap")
    cid = run["capture"]["id"]
    assert client.delete(f"/api/captures/{cid}").status_code == 200
    assert client.get(f"/api/captures/{cid}").status_code == 404
    assert client.get(f"/api/analyses/{run['analysis_id']}").status_code == 404
    analyse.cache.pop("smtp_nonstandard_port.pcap", None)  # the cached run no longer exists


def test_settings_validation(client):
    assert client.put("/api/settings", json={"retention_days": "x"}).status_code == 422
    assert client.put("/api/settings", json={"nonsense": 1}).status_code == 422
    assert client.put("/api/settings", json={"analyst_name": "Dhinesh"}).json()["settings"]["analyst_name"] == "Dhinesh"
    assert client.get("/api/system/audit").json()["items"]
