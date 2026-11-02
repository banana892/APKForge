"""Phase 9.1 - local web workbench API (token/Host guard, jobs, ModKit runs/chains)."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from apkforge.gui.app import TOKEN_HEADER, create_app
from apkforge.gui.jobs import JobManager, JobStatus
from apkforge.modkit.config import CONFIG_ENV_VAR
from apkforge.modkit.manager import TEST_MODKIT_ENV_VAR
from apkforge.modkit.testing import TEST_MODKIT_ID
from tests.fixtures import create_synthetic_apk

TOKEN = "test-token-0123456789"
SECRET = "tok-9f8e7d6c5b4a-SECRET"


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv(CONFIG_ENV_VAR, raising=False)
    monkeypatch.setenv(TEST_MODKIT_ENV_VAR, "1")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))


@pytest.fixture()
def client() -> TestClient:
    return TestClient(create_app(TOKEN), base_url="http://127.0.0.1:8765")


@pytest.fixture()
def apk(tmp_path: Path) -> Path:
    return create_synthetic_apk(tmp_path / "in" / "app.apk")


H = {TOKEN_HEADER: TOKEN}


def _wait(client: TestClient, job: dict[str, Any], timeout: float = 180) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while job["status"] in ("QUEUED", "RUNNING"):
        assert time.monotonic() < deadline, f"job {job['id']} did not finish"
        time.sleep(0.1)
        job = client.get(f"/api/jobs/{job['id']}", headers=H).json()
    return job


# -- guard ---------------------------------------------------------------------------


def test_api_requires_the_token(client: TestClient) -> None:
    assert client.get("/api/health").status_code == 401
    assert client.get("/api/health", headers={TOKEN_HEADER: "wrong"}).status_code == 401
    ok = client.get("/api/health", headers=H)
    assert ok.status_code == 200 and ok.json()["status"] == "ok"


def test_foreign_host_is_rejected_even_with_token() -> None:
    """DNS rebinding: a page on evil.example resolving to 127.0.0.1 sends its own Host."""
    c = TestClient(create_app(TOKEN), base_url="http://evil.example")
    assert c.get("/api/health", headers=H).status_code == 403
    assert c.get("/").status_code == 403
    assert (
        TestClient(create_app(TOKEN), base_url="http://localhost:1")
        .get("/api/health", headers=H)
        .status_code
        == 200
    )


def test_page_is_static_and_hardened(client: TestClient) -> None:
    page = client.get("/")
    assert page.status_code == 200 and "APKForge Workbench" in page.text
    assert TOKEN not in page.text  # the token only ever travels in the URL fragment
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    assert page.headers["cache-control"] == "no-store"
    js = client.get("/app.js")
    assert js.status_code == 200 and "textContent" in js.text and ".innerHTML" not in js.text
    assert client.get("/docs").status_code == 404  # no interactive API docs exposed


@pytest.mark.parametrize(
    ("path", "body", "fragment"),
    [
        ("/api/jobs/analyze", {"apk": "relative.apk"}, "absolute path"),
        ("/api/jobs/analyze", {"apk": "/nonexistent/x.apk"}, "not an existing file"),
        ("/api/jobs/diff", {"original": "/nonexistent/a.apk", "modified": "/x"}, "original"),
    ],
)
def test_bad_paths_are_rejected_before_queueing(
    client: TestClient, path: str, body: dict[str, str], fragment: str
) -> None:
    r = client.post(path, json=body, headers=H)
    assert r.status_code == 422 and fragment in r.text
    assert client.get("/api/jobs", headers=H).json() == []


# -- jobs ----------------------------------------------------------------------------


def test_analyze_job(client: TestClient, apk: Path) -> None:
    r = client.post("/api/jobs/analyze", json={"apk": str(apk)}, headers=H)
    assert r.status_code == 202
    job = _wait(client, r.json())
    assert job["status"] == "DONE", job["error"]
    assert job["result"]["package_name"] and "security_findings" in job["result"]
    listed = client.get("/api/jobs", headers=H).json()
    assert [j["id"] for j in listed] == [job["id"]] and listed[0]["result"] is None


def test_diff_job_returns_summary_and_observations(client: TestClient, tmp_path: Path) -> None:
    a = create_synthetic_apk(tmp_path / "a" / "app.apk")
    b = create_synthetic_apk(tmp_path / "b" / "app.apk", extra_files={"assets/new.txt": b"hi"})
    job = _wait(client, client.post("/api/jobs/diff", json={"original": str(a), "modified": str(b)},
                                    headers=H).json())  # fmt: skip
    assert job["status"] == "DONE", job["error"]
    obs = job["result"]["observations"]
    assert {"category": "file", "kind": "added", "identifier": "assets/new.txt"}.items() <= next(
        o for o in obs if o["identifier"] == "assets/new.txt"
    ).items()
    assert "summary" in job["result"] and "raw" not in job["result"]


def test_modkit_list_and_run_masks_secrets(client: TestClient, apk: Path, tmp_path: Path) -> None:
    kits = client.get("/api/modkits", headers=H).json()
    assert TEST_MODKIT_ID in {k["identity"]["modkit_id"] for k in kits}
    body = {
        "modkit": TEST_MODKIT_ID,
        "apk": str(apk),
        "output_dir": str(tmp_path / "out"),
        "operation": "transform",
        "parameters": {"scenario": "success", "api_token": SECRET},
    }
    r = client.post("/api/jobs/modkit-run", json=body, headers=H)
    assert r.status_code == 202 and SECRET not in r.text
    job = _wait(client, r.json())
    assert job["status"] == "DONE" and job["result"]["status"] == "SUCCESS"
    assert Path(job["result"]["published"]["path"]).is_file()
    assert SECRET not in client.get(f"/api/jobs/{job['id']}", headers=H).text
    assert SECRET not in client.get("/api/jobs", headers=H).text


def test_modkit_chain_job(client: TestClient, apk: Path, tmp_path: Path) -> None:
    step = {"modkit": TEST_MODKIT_ID, "operation": "transform"}
    steps = [{**step, "parameters": {"scenario": "success", "marker": m}} for m in ("a", "b")]
    job = _wait(client, client.post("/api/jobs/modkit-chain", headers=H, json={
        "apk": str(apk), "output_dir": str(tmp_path / "out"), "steps": steps,
    }).json())  # fmt: skip
    assert job["status"] == "DONE" and job["result"]["status"] == "SUCCESS"
    assert len(job["result"]["steps"]) == 2
    bad = client.post("/api/jobs/modkit-chain", headers=H, json={
        "apk": str(apk), "output_dir": str(tmp_path / "o2"), "steps": [{"modkit": "x"}],
    })  # fmt: skip
    assert bad.status_code == 422 and "invalid chain" in bad.text


def test_job_exception_becomes_error_status() -> None:
    jobs = JobManager(workers=1)

    def boom() -> None:
        raise RuntimeError("kaput")

    job = jobs.submit("x", {}, boom)
    deadline = time.monotonic() + 10
    while (got := jobs.get(job.id)) is not None and got.status in (JobStatus.QUEUED,
                                                                    JobStatus.RUNNING):  # fmt: skip
        assert time.monotonic() < deadline
        time.sleep(0.01)
    assert got is not None and got.status is JobStatus.ERROR and got.error == "RuntimeError: kaput"
    jobs.shutdown()
