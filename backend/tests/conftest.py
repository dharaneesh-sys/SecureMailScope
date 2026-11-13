import json
import os
import tempfile
import time
from pathlib import Path

# The data dir must be set before the app is imported.
_TMP = tempfile.mkdtemp(prefix="sms_test_")
os.environ["SMS_DATA_DIR"] = _TMP
os.environ["SMS_DEMO_DIR"] = str(Path(__file__).resolve().parents[2] / "sample_data" / "authorised_demo_captures")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

DEMO = Path(os.environ["SMS_DEMO_DIR"])


@pytest.fixture(scope="session")
def manifest():
    return json.loads((DEMO / "manifest.json").read_text())


@pytest.fixture(scope="session")
def client():
    from app.main import app

    with TestClient(app) as c:
        yield c


def wait_done(client, analysis_id, timeout=90):
    t0 = time.time()
    while time.time() - t0 < timeout:
        s = client.get(f"/api/analyses/{analysis_id}/status").json()
        if s["status"] in ("completed", "failed", "cancelled"):
            return s
        time.sleep(0.15)
    raise TimeoutError(analysis_id)


@pytest.fixture(scope="session")
def analyse(client):
    cache: dict[str, dict] = {}

    def _run(name: str, options=None):
        if name in cache and options is None:
            return cache[name]
        with open(DEMO / name, "rb") as fh:
            up = client.post("/api/captures", files={"file": (name, fh, "application/octet-stream")})
        assert up.status_code == 201, up.text
        cap = up.json()["capture"]
        body = {"capture_id": cap["id"], "authorised_confirmation": True}
        if options:
            body["options"] = options
        r = client.post("/api/analyses", json=body)
        assert r.status_code == 202, r.text
        aid = r.json()["id"]
        status = wait_done(client, aid)
        out = {"capture": cap, "analysis_id": aid, "status": status}
        if options is None:
            cache[name] = out
        return out

    _run.cache = cache
    return _run
