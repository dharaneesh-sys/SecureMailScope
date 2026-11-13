"""Every rule: fires on its condition, stays silent otherwise, and carries evidence."""

import pytest

from tests.unit.helpers import cert, ctx, ev, fire, session, tls


def test_tls001_deprecated_selected():
    for ver, sev in ((0x0301, "high"), (0x0302, "high"), (0x0300, "critical")):
        f = fire("SMS-TLS-001", ctx(tls_sessions=[tls(selected_version=ver)]))
        assert len(f) == 1 and f[0].severity == sev and f[0].evidence[0].frame == 16 and f[0].observation_type == "weakness_observed"
    assert fire("SMS-TLS-001", ctx(tls_sessions=[tls(selected_version=0x0303)])) == []
    assert fire("SMS-TLS-001", ctx(tls_sessions=[tls(selected_version=0x0304)])) == []
    assert fire("SMS-TLS-001", ctx(tls_sessions=[tls(server_hello_frame=None, selected_version=None)])) == []


def test_tls_legacy_version_field_is_not_negotiated_version():
    """TLS1.3 ServerHello carries legacy_version 0x0303; the rule must use supported_versions."""
    t = tls(selected_version=0x0304, selected_version_source="supported_versions", server_legacy_version=0x0303)
    assert fire("SMS-TLS-001", ctx(tls_sessions=[t])) == []
    assert len(fire("SMS-TLS-014", ctx(tls_sessions=[t]))) == 1


def test_tls002_deprecated_offered_not_selected():
    t = tls(client_supported_versions=[0x0304, 0x0303, 0x0301])
    f = fire("SMS-TLS-002", ctx(tls_sessions=[t]))
    assert len(f) == 1 and f[0].observation_type == "weak_option_offered" and f[0].severity == "low"
    assert fire("SMS-TLS-002", ctx(tls_sessions=[tls(client_supported_versions=[0x0304, 0x0303])])) == []
    assert fire("SMS-TLS-002", ctx(tls_sessions=[tls(client_supported_versions=[0x0301], selected_version=0x0301)])) == []  # selected: covered by TLS-001


def test_tls010_partial_handshake():
    t = tls(server_hello_done=False, certificate_frame=None)
    assert t.completeness == "partial"
    f = fire("SMS-TLS-010", ctx(tls_sessions=[t]))
    assert len(f) == 1 and f[0].observation_type == "insufficient_evidence"
    assert fire("SMS-TLS-010", ctx(tls_sessions=[tls()])) == []


def test_tls011_and_012_missing_hello():
    assert len(fire("SMS-TLS-011", ctx(tls_sessions=[tls(client_hello_frame=None)]))) == 1
    assert len(fire("SMS-TLS-012", ctx(tls_sessions=[tls(server_hello_frame=None, selected_version=None, selected_cipher=None)]))) == 1
    assert fire("SMS-TLS-011", ctx(tls_sessions=[tls()])) == [] and fire("SMS-TLS-012", ctx(tls_sessions=[tls()])) == []


def test_tls013_insufficient_evidence_never_flags_weakness():
    s = session(starttls_accepted=True, starttls_response=ev(12, "220 Ready", "server->client"), starttls_command=ev(10))
    f = fire("SMS-TLS-013", ctx(sessions=[s]))
    assert len(f) == 1 and f[0].observation_type == "insufficient_evidence" and f[0].severity == "info"
    f2 = fire("SMS-TLS-013", ctx(tls_sessions=[tls(server_hello_frame=None, selected_version=None, selected_cipher=None)]))
    assert len(f2) == 1 and f2[0].severity == "info"
    assert fire("SMS-TLS-013", ctx(sessions=[s], tls_sessions=[tls()])) == []


def test_tls014_secure_config():
    assert len(fire("SMS-TLS-014", ctx(tls_sessions=[tls()]))) == 1
    assert fire("SMS-TLS-014", ctx(tls_sessions=[tls(selected_cipher=0x0035)])) == []  # CBC static RSA: neutral, not "secure"
    assert fire("SMS-TLS-014", ctx(tls_sessions=[tls(selected_cipher=0x9999)])) == []  # unknown suite: no claim either way


@pytest.mark.parametrize("cid,sev", [(0x0002, "critical"), (0x0003, "critical"), (0x0018, "critical"), (0x0005, "high"), (0x0009, "high"), (0x0004, "high"), (0x000A, "medium")])
def test_cip001_weak_selected_severity(cid, sev):
    f = fire("SMS-CIP-001", ctx(tls_sessions=[tls(selected_cipher=cid)]))
    assert len(f) == 1 and f[0].severity == sev


def test_cip001_ignores_modern_and_unknown():
    assert fire("SMS-CIP-001", ctx(tls_sessions=[tls(selected_cipher=0xC030)])) == []
    assert fire("SMS-CIP-001", ctx(tls_sessions=[tls(selected_cipher=0xBEEF)])) == []  # unknown suites are never guessed weak


def test_cip002_offered_weak_excludes_selected_and_scsv():
    t = tls(offered_ciphers=[0xC030, 0x0005, 0x00FF], selected_cipher=0xC030)
    f = fire("SMS-CIP-002", ctx(tls_sessions=[t]))
    assert len(f) == 1 and f[0].detail["weak_offered"] == ["TLS_RSA_WITH_RC4_128_SHA"]
    assert fire("SMS-CIP-002", ctx(tls_sessions=[tls(offered_ciphers=[0xC030, 0x00FF])])) == []
    assert len(fire("SMS-CIP-002", ctx(tls_sessions=[tls(offered_ciphers=[0x0005], server_hello_frame=None, selected_cipher=None, selected_version=None)]))) == 1


def test_cip003_no_forward_secrecy():
    assert len(fire("SMS-CIP-003", ctx(tls_sessions=[tls(selected_cipher=0x0035)]))) == 1
    assert fire("SMS-CIP-003", ctx(tls_sessions=[tls(selected_cipher=0xC030)])) == []
    assert fire("SMS-CIP-003", ctx(tls_sessions=[tls(selected_cipher=0x1301, selected_version=0x0304)])) == []


def test_crt001_expired_uses_capture_time():
    c = cert(not_after="2025-06-01T00:00:00+00:00")
    f = fire("SMS-CRT-001", ctx(tls_sessions=[tls(certificates=[c])]))
    assert len(f) == 1 and f[0].severity == "high"
    assert fire("SMS-CRT-001", ctx(tls_sessions=[tls(certificates=[cert()])])) == []


def test_crt002_not_yet_valid():
    assert len(fire("SMS-CRT-002", ctx(tls_sessions=[tls(certificates=[cert(not_before="2026-06-01T00:00:00+00:00")])]))) == 1
    assert fire("SMS-CRT-002", ctx(tls_sessions=[tls(certificates=[cert()])])) == []


def test_crt003_weak_signature_exempts_self_signed_anchor():
    assert len(fire("SMS-CRT-003", ctx(tls_sessions=[tls(certificates=[cert(sig_hash="sha1")])]))) == 1
    md5 = fire("SMS-CRT-003", ctx(tls_sessions=[tls(certificates=[cert(sig_hash="md5")])]))
    assert md5[0].severity == "high"
    root = cert(position=1, sig_hash="sha1", self_signed=True)
    assert fire("SMS-CRT-003", ctx(tls_sessions=[tls(certificates=[cert(), root])])) == []


@pytest.mark.parametrize("alg,bits,sev", [("RSA", 1024, "high"), ("RSA", 1536, "medium"), ("EC (secp192r1)", 192, "high")])
def test_crt004_weak_key(alg, bits, sev):
    f = fire("SMS-CRT-004", ctx(tls_sessions=[tls(certificates=[cert(key_algorithm=alg, key_size=bits)])]))
    assert len(f) == 1 and f[0].severity == sev


def test_crt004_strong_keys_pass():
    for alg, bits in (("RSA", 2048), ("RSA", 4096), ("EC (secp256r1)", 256), ("Ed25519", 256)):
        assert fire("SMS-CRT-004", ctx(tls_sessions=[tls(certificates=[cert(key_algorithm=alg, key_size=bits)])])) == []


def test_crt005_unavailable_for_tls13_and_missing():
    t13 = tls(selected_version=0x0304, certificates=[])
    f = fire("SMS-CRT-005", ctx(tls_sessions=[t13]))
    assert len(f) == 1 and "TLS 1.3" in f[0].description and f[0].observation_type == "insufficient_evidence"
    assert fire("SMS-CRT-005", ctx(tls_sessions=[tls(certificates=[cert()])])) == []
    assert fire("SMS-CRT-005", ctx(tls_sessions=[tls(server_hello_frame=None, certificates=[])])) == []


def test_crt006_self_signed_leaf_is_observation_not_trust_claim():
    f = fire("SMS-CRT-006", ctx(tls_sessions=[tls(certificates=[cert(self_signed=True)])]))
    assert len(f) == 1 and f[0].severity == "low" and "does not evaluate trust" in f[0].technical
    assert fire("SMS-CRT-006", ctx(tls_sessions=[tls(certificates=[cert()])])) == []


def test_crt007_chain_without_issuer_only_when_single_non_self_signed():
    assert len(fire("SMS-CRT-007", ctx(tls_sessions=[tls(certificates=[cert()])]))) == 1
    assert fire("SMS-CRT-007", ctx(tls_sessions=[tls(certificates=[cert(), cert(position=1)])])) == []
    assert fire("SMS-CRT-007", ctx(tls_sessions=[tls(certificates=[cert(self_signed=True)])])) == []


def test_crt008_sni_mismatch_and_wildcards():
    assert len(fire("SMS-CRT-008", ctx(tls_sessions=[tls(sni="other.example.test", certificates=[cert()])]))) == 1
    assert fire("SMS-CRT-008", ctx(tls_sessions=[tls(sni="mail.example.test", certificates=[cert()])])) == []
    assert fire("SMS-CRT-008", ctx(tls_sessions=[tls(sni="a.example.test", certificates=[cert(san=["*.example.test"])])])) == []
    assert len(fire("SMS-CRT-008", ctx(tls_sessions=[tls(sni="a.b.example.test", certificates=[cert(san=["*.example.test"])])]))) == 1
    assert fire("SMS-CRT-008", ctx(tls_sessions=[tls(sni=None, certificates=[cert()])])) == []  # SNI not visible -> no claim


def test_stl001_requires_accept_and_clienthello():
    s = session(starttls_command=ev(10), starttls_response=ev(12, "220", "server->client"), starttls_accepted=True)
    assert len(fire("SMS-STL-001", ctx(sessions=[s], tls_sessions=[tls()]))) == 1
    assert fire("SMS-STL-001", ctx(sessions=[s])) == []
    s2 = session(starttls_command=ev(10), starttls_response=ev(12), starttls_accepted=False)
    assert fire("SMS-STL-001", ctx(sessions=[s2], tls_sessions=[tls()])) == []


def test_stl002_rejected():
    s = session(starttls_command=ev(10), starttls_response=ev(12, "454 TLS not available", "server->client"), starttls_accepted=False)
    f = fire("SMS-STL-002", ctx(sessions=[s]))
    assert len(f) == 1 and f[0].severity == "medium"
    assert fire("SMS-STL-002", ctx(sessions=[session(starttls_command=ev(10), starttls_accepted=None)])) == []  # no response observed -> no claim


def test_stl003_offered_but_plaintext():
    cap = ev(8, "250 capabilities", "server->client")
    cap.kind = "capability"
    s = session(starttls_offered=True, events=[cap], plaintext_transaction=[ev(20, "MAIL")])
    assert len(fire("SMS-STL-003", ctx(sessions=[s]))) == 1
    assert fire("SMS-STL-003", ctx(sessions=[session(starttls_offered=True, events=[cap])])) == []  # nothing happened in cleartext
    assert fire("SMS-STL-003", ctx(sessions=[session(starttls_offered=None, plaintext_transaction=[ev(20)])])) == []  # capability list never observed
    assert fire("SMS-STL-003", ctx(sessions=[session(starttls_offered=True, plaintext_transaction=[ev(20)], implicit_tls=True)])) == []


def test_stl004_plaintext_auth_records_verb_only():
    s = session(auth_events=[ev(9, "AUTH PLAIN [credentials not stored]")])
    f = fire("SMS-STL-004", ctx(sessions=[s]))
    assert len(f) == 1 and f[0].severity == "high" and "[credentials not stored]" in f[0].evidence[0].fields["event"]
    assert fire("SMS-STL-004", ctx(sessions=[session()])) == []


def test_every_rule_has_documentation_fields():
    from app.rules.registry import all_rules

    ids = set()
    for r in all_rules():
        m = r.meta
        assert m.rule_id not in ids
        ids.add(m.rule_id)
        assert all([m.name, m.category, m.description, m.detection, m.evidence_requirements, m.remediation]) and m.severity in ("critical", "high", "medium", "low", "info")
