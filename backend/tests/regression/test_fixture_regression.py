"""Regression: every synthetic fixture -> expected observations + expected rule results.

Writes docs/TEST_RESULTS.md from the *actual* results of this run (no hand-written outcomes).
"""

import datetime as dt
from pathlib import Path

import pytest

from tests.conftest import DEMO, wait_done

RESULTS: list[dict] = []
DOC = Path(__file__).resolve().parents[3] / "docs" / "TEST_RESULTS.md"


def _valid_names():
    import json

    return list(json.loads((DEMO / "manifest.json").read_text())["valid"].items())


@pytest.mark.parametrize("name,exp", _valid_names(), ids=[n for n, _ in _valid_names()])
def test_fixture(client, analyse, name, exp):
    run = analyse(name)
    aid = run["analysis_id"]
    row = {"fixture": name, "title": exp["title"], "expected_protocols": exp["protocols"], "expected_version": exp["tls_version"], "expected_cipher": exp["cipher"],
           "expected_rules": sorted(exp["rules"]), "absent_rules": sorted(exp["absent"])}
    try:
        assert run["status"]["status"] == "completed", run["status"].get("error")
        protos = sorted({s["protocol"] for s in client.get(f"/api/analyses/{aid}/protocols").json()["sessions"]})
        tls = client.get(f"/api/analyses/{aid}/tls").json()["sessions"]
        version = tls[0]["selected_version"] if tls else None
        cipher = tls[0]["selected_cipher"] if tls else None
        items = client.get(f"/api/analyses/{aid}/findings?page_size=200").json()["items"]
        fired = sorted({f["rule_id"] for f in items})
        ev = client.get(f"/api/analyses/{aid}/evidence?page_size=200").json()["items"]
        by_rule = {}
        for e in ev:
            by_rule.setdefault(e["finding"]["rule_id"], e["ref"])
        row.update(actual_protocols=protos, actual_version=version, actual_cipher=cipher, actual_rules=fired,
                   evidence_ids=", ".join(f"{r}:{by_rule[r]}" for r in sorted(exp["rules"]) if r in by_rule) or "-")
        assert protos == sorted(exp["protocols"])
        assert version == exp["tls_version"] and cipher == exp["cipher"]
        assert set(exp["rules"]) <= set(fired), f"missing rules {set(exp['rules']) - set(fired)}"
        assert not (set(exp["absent"]) & set(fired)), f"unexpected rules {set(exp['absent']) & set(fired)}"
        for f in items:  # nothing without evidence (except none) and every finding links to a parser observation
            assert f["evidence_count"] >= 1, f"{f['rule_id']} has no evidence"
        row["status"] = "PASS"
    except AssertionError:
        row["status"] = "FAIL"
        raise
    finally:
        RESULTS.append(row)


@pytest.mark.parametrize("name,kind", [("corrupted.pcap", "corrupt"), ("empty.pcap", "empty"), ("unsupported_linktype.pcap", "unsupported_linktype")])
def test_invalid_fixture(client, name, kind):
    row = {"fixture": name, "title": f"Rejected at ingestion ({kind})", "expected_protocols": [], "expected_version": None, "expected_cipher": None, "expected_rules": [], "absent_rules": []}
    with open(DEMO / name, "rb") as fh:
        r = client.post("/api/captures", files={"file": (name, fh, "application/octet-stream")})
    row.update(actual_protocols=[], actual_version=None, actual_cipher=None, actual_rules=[], evidence_ids="-", status="PASS" if r.status_code == 422 and r.json()["detail"]["code"] == kind else "FAIL")
    RESULTS.append(row)
    assert row["status"] == "PASS"


def test_write_results_document():
    """Runs last in this module: emit the table from the recorded results."""
    if not RESULTS:
        pytest.skip("no results recorded")
    lines = ["# Test results - synthetic fixture regression", "",
             f"Generated automatically by `backend/tests/regression/test_fixture_regression.py` on {dt.datetime.now(dt.timezone.utc):%Y-%m-%d %H:%M UTC}. ",
             "Every value below was produced by running the real TShark-backed pipeline; nothing is hand-written.", "",
             "| Fixture | Expected observation | Actual observation | Expected rules | Actual rules | Evidence IDs | Status |", "|---|---|---|---|---|---|---|"]
    for r in RESULTS:
        exp = f"{'/'.join(r['expected_protocols']) or '-'}; {r['expected_version'] or 'no TLS params'}; {r['expected_cipher'] or '-'}"
        act = f"{'/'.join(r['actual_protocols']) or '-'}; {r['actual_version'] or 'no TLS params'}; {r['actual_cipher'] or '-'}"
        lines.append(f"| `{r['fixture']}` | {exp} | {act} | {', '.join(r['expected_rules']) or '-'} | {', '.join(r['actual_rules']) or '-'} | {r['evidence_ids']} | **{r['status']}** |")
    passed = sum(r["status"] == "PASS" for r in RESULTS)
    lines += ["", f"**{passed}/{len(RESULTS)} fixtures passed.**", ""]
    DOC.parent.mkdir(exist_ok=True)
    DOC.write_text("\n".join(lines))
    assert passed == len(RESULTS)
