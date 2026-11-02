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
def client(tmp_path: Path) -> TestClient:
    return TestClient(
        create_app(TOKEN, upload_dir=tmp_path / "up"), base_url="http://127.0.0.1:8765"
    )


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


def test_foreign_host_is_rejected_even_with_token(tmp_path: Path) -> None:
    """DNS rebinding: a page on evil.example resolving to 127.0.0.1 sends its own Host."""
    c = TestClient(create_app(TOKEN, upload_dir=tmp_path), base_url="http://evil.example")
    assert c.get("/api/health", headers=H).status_code == 403
    assert c.get("/").status_code == 403
    assert (
        TestClient(create_app(TOKEN, upload_dir=tmp_path), base_url="http://localhost:1")
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


# -- 9.1 follow-ups: cancel, upload, patch listing -------------------------------------


def test_cancel_kills_a_running_modkit(client: TestClient, apk: Path, tmp_path: Path) -> None:
    body = {"modkit": TEST_MODKIT_ID, "apk": str(apk), "output_dir": str(tmp_path / "out"),
            "operation": "transform", "parameters": {"scenario": "timeout"}}  # fmt: skip
    job = client.post("/api/jobs/modkit-run", json=body, headers=H).json()
    deadline = time.monotonic() + 30
    while job["status"] != "RUNNING":  # cancel only once the tool really runs
        assert time.monotonic() < deadline
        time.sleep(0.05)
        job = client.get(f"/api/jobs/{job['id']}", headers=H).json()
    time.sleep(1)
    assert client.post(f"/api/jobs/{job['id']}/cancel", headers=H).json()["cancel_requested"]
    t0 = time.monotonic()
    job = _wait(client, job, timeout=30)
    assert time.monotonic() - t0 < 15  # killed, not the 3600 s sleep or the ModKit timeout
    assert job["status"] == "CANCELLED" and job["result"]["status"] == "CANCELLED"
    assert not (tmp_path / "out").exists() or not any((tmp_path / "out").iterdir())
    assert client.post("/api/jobs/nope/cancel", headers=H).status_code == 404


def test_cancel_queued_job_never_runs() -> None:
    import threading

    jobs = JobManager(workers=1)
    gate, ran = threading.Event(), []
    first = jobs.submit("block", {}, gate.wait)
    second = jobs.submit("x", {}, lambda: ran.append(1))
    got = jobs.cancel(second.id)
    assert got is not None and got.status is JobStatus.CANCELLED
    gate.set()
    deadline = time.monotonic() + 10
    while (j := jobs.get(first.id)) is not None and j.status is not JobStatus.DONE:
        assert time.monotonic() < deadline
        time.sleep(0.01)
    time.sleep(0.1)
    assert ran == [] and jobs.get(second.id).status is JobStatus.CANCELLED  # type: ignore[union-attr]
    assert jobs.cancel(first.id).status is JobStatus.DONE  # type: ignore[union-attr]  # finished: unchanged
    jobs.shutdown()


def test_upload_stores_a_valid_apk_under_a_safe_name(tmp_path: Path, apk: Path) -> None:
    up = tmp_path / "uploads"
    c = TestClient(create_app(TOKEN, upload_dir=up), base_url="http://127.0.0.1:8765")
    r = c.post("/api/uploads", params={"name": "../../etc/evil name.apk"},
               content=apk.read_bytes(), headers=H)  # fmt: skip
    assert r.status_code == 201, r.text
    stored = Path(r.json()["path"])
    assert stored.parent.parent == up and stored.name == "evil_name.apk"
    assert stored.read_bytes() == apk.read_bytes()
    bad = c.post("/api/uploads", params={"name": "x.apk"}, content=b"not a zip", headers=H)
    assert bad.status_code == 422 and "not a valid APK" in bad.text
    assert len(list(up.iterdir())) == 1  # the rejected upload left nothing behind
    assert c.post("/api/uploads", content=b"x").status_code == 401


def test_patch_listing_needs_a_modkit_that_supports_it(client: TestClient) -> None:
    r = client.post("/api/jobs/modkit-patches", headers=H,
                    json={"modkit": TEST_MODKIT_ID, "patches": "/x.mpp"})  # fmt: skip
    assert r.status_code == 422 and "patch bundle listing" in r.text


# -- 9.2: preview, then apply ----------------------------------------------------------


def _post(client: TestClient, path: str, **body: Any) -> Any:
    return client.post(path, headers=H, json=body)


def _planned(apk: Path) -> Any:
    from apkforge.remediation.models import RemediationPlan

    return RemediationPlan(
        plan_id="p1",
        source_apk_path=str(apk),
        source_apk_sha256="x",
        finding_id="F-1",
        finding_category="persistence",
        finding_title="t",
        remediation_id="G-REM-001",
        remediation_name="n",
    )


def test_apply_runs_only_the_previewed_unchanged_plan(
    client: TestClient, apk: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from apkforge.remediation import RemediationService

    applied: list[tuple[str, Path]] = []

    def fake_apply(cls: object, plan: Any, approved: bool, output_path: Path) -> dict[str, str]:
        assert approved
        applied.append((plan.plan_id, output_path))
        return {"state": "verified"}

    monkeypatch.setattr(RemediationService, "plan", classmethod(lambda c, a, f, **k: _planned(a)))
    monkeypatch.setattr(RemediationService, "apply", classmethod(fake_apply))
    preview = _wait(client, _post(client, "/api/jobs/remediation-plan", apk=str(apk),
                                  finding_id="F-1").json())  # fmt: skip
    assert preview["status"] == "DONE", preview["error"]
    assert preview["result"]["state"] == "planned"

    def apply(output: str) -> Any:
        return _post(client, "/api/jobs/apply", preview_job=preview["id"], output=output)

    out = tmp_path / "out" / "fixed.apk"
    assert apply("fixed.apk").status_code == 422  # relative
    assert apply(str(tmp_path / "x.zip")).status_code == 422  # not .apk
    assert apply(str(apk)).status_code == 422  # exists (and is the input)
    original = apk.read_bytes()
    apk.write_bytes(original + b"\0")
    changed = apply(str(out))
    assert changed.status_code == 409 and "changed since the preview" in changed.text
    apk.write_bytes(original)
    job = _wait(client, apply(str(out)).json())
    assert job["status"] == "DONE" and applied == [("p1", out)]
    assert apply(str(tmp_path / "again.apk")).status_code == 409  # one apply per preview


def test_apply_refuses_unfinished_or_inapplicable_previews(
    client: TestClient, apk: Path, tmp_path: Path
) -> None:
    out = str(tmp_path / "o.apk")
    assert _post(client, "/api/jobs/apply", preview_job="nope", output=out).status_code == 409
    # a real plan for a finding that does not exist is never applicable
    preview = _wait(client, _post(client, "/api/jobs/remediation-plan", apk=str(apk),
                                  finding_id="NO-SUCH").json())  # fmt: skip
    assert preview["status"] == "DONE" and preview["result"]["state"] != "planned"
    r = _post(client, "/api/jobs/apply", preview_job=preview["id"], output=out)
    assert r.status_code == 409 and "cannot apply" in r.text
    analysis = _wait(client, _post(client, "/api/jobs/analyze", apk=str(apk)).json())
    r = _post(client, "/api/jobs/apply", preview_job=analysis["id"], output=out)
    assert r.status_code == 409  # an analysis is not a preview


def test_transform_plan_validates_ids(client: TestClient, apk: Path) -> None:
    def plan(**extra: str) -> Any:
        return _post(client, "/api/jobs/transform-plan", apk=str(apk), target="a.B", **extra)

    assert plan(transformation_id="H-TRANS-999").status_code == 422
    repl = plan(transformation_id="H-TRANS-001", replacement="x")
    assert repl.status_code == 422 and "H-TRANS-003" in repl.text


# -- 9.2b: plan, Phase D modifiers, verify ----------------------------------------------


@pytest.fixture()
def phase_d(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """The simulated toolchain the Phase D CLI tests use (no apktool/SDK); returns an APK
    whose package matches what the simulated decoder reports."""
    from apkforge.gui import changes
    from apkforge.modification import pipeline as pipeline_mod
    from tests.unit.phase_d_support import FakeDiff, ZipService, baseline_for, diff_adding
    from tests.unit.test_c5_boot_receiver import PKG
    from tests.unit.test_phase_d_cli import _marker

    class Service(ZipService):  # the GUI, like the CLI without --workspace, passes none
        def prepare_workspace(self, *, work_dir: Path | None = None, **kw: Any) -> Any:
            return super().prepare_workspace(work_dir=work_dir or tmp_path / "ws", **kw)

    service = Service()
    monkeypatch.setattr(changes, "default_build_service", lambda: service)
    monkeypatch.setattr(changes, "measure_noise_floor", lambda svc, a, work_dir: baseline_for(a))
    monkeypatch.setattr(
        pipeline_mod, "DiffEngine", lambda: FakeDiff(diff_adding(extra=[_marker()]))
    )
    return create_synthetic_apk(tmp_path / "pd" / "app.apk", package_name=PKG)


def test_modifiers_dry_run_then_apply(client: TestClient, tmp_path: Path, phase_d: Path) -> None:
    apk = phase_d
    ids = [m["id"] for m in client.get("/api/modifiers", headers=H).json()]
    assert "test.marker_asset" in ids
    bad = _post(client, "/api/jobs/modify-preview", apk=str(apk), modifiers=[{"id": "nope"}])
    assert bad.status_code == 422
    preview = _wait(client, _post(client, "/api/jobs/modify-preview", apk=str(apk),
                                  modifiers=[{"id": "test.marker_asset"}],
                                  measure_noise_floor=True).json())  # fmt: skip
    assert preview["status"] == "DONE", preview["error"]
    assert preview["result"]["status"] == "dry_run" and preview["result"]["dry_run"]
    out = tmp_path / "out" / "marked.apk"
    job = _wait(client, _post(client, "/api/jobs/apply", preview_job=preview["id"],
                              output=str(out)).json())  # fmt: skip
    assert job["status"] == "DONE", job["error"]
    assert job["result"]["status"] == "verified", job["result"]["failures"]
    assert out.is_file()
    assert job["result"]["dry_run"] is False


def test_modification_plan_and_verify_are_read_only(client: TestClient, apk: Path) -> None:
    before = apk.read_bytes()
    plan = _wait(client, _post(client, "/api/jobs/modification-plan", apk=str(apk)).json())
    assert plan["status"] == "DONE", plan["error"]
    assert "changes" in plan["result"]
    single = _wait(client, _post(client, "/api/jobs/verify", original=str(apk)).json())
    assert single["status"] == "DONE", single["error"]
    assert {"structural", "signature"} <= single["result"]["checks"].keys()
    pair = _wait(
        client, _post(client, "/api/jobs/verify", original=str(apk), modified=str(apk)).json()
    )
    assert pair["status"] == "DONE", pair["error"]
    assert "verification" in pair["result"] and "raw" not in pair["result"]
    assert apk.read_bytes() == before
    r = _post(client, "/api/jobs/apply", preview_job=plan["id"], output="/tmp/x.apk")
    assert r.status_code == 409  # a plan is not a preview


def test_h4_needs_a_verified_transformation_apply(client: TestClient, apk: Path) -> None:
    job = _wait(client, _post(client, "/api/jobs/analyze", apk=str(apk)).json())
    r = _post(client, "/api/jobs/verify-transformation", apply_job=job["id"])
    assert r.status_code == 409 and "transformation apply" in r.text


# -- 9.2c: references, declared expectations ---------------------------------------------


@pytest.fixture()
def h6_result(tmp_path: Path) -> Any:
    from apkforge.reference import ApkIdentity, ReferenceAnalysisService
    from tests.fixtures.h1_apks import write_project
    from tests.fixtures.h6_apks import H6_FIXTURES

    project = write_project(H6_FIXTURES[0], tmp_path / "h6")
    return ReferenceAnalysisService.analyze_decoded(
        project, identity=ApkIdentity(file_name="h6.apk", sha256="0" * 64)
    )


def test_reference_summary_counts_and_orders(h6_result: Any) -> None:
    from apkforge.gui.references import summarize
    from tests.fixtures.h6_apks import PKG

    s = summarize(h6_result)
    by_name = {c["name"]: c for c in s["classes"]}
    # Source is called from A; A is not referenced by any other class
    assert by_name[f"{PKG}.Source"]["references"] > 0
    totals = [c["references"] + c["indirect"] for c in s["classes"]]
    assert totals == sorted(totals)  # unreferenced first
    calls = {m["name"] + m["descriptor"]: m["calls"] for m in by_name[f"{PKG}.Source"]["methods"]}
    assert calls["getValue()Ljava/lang/String;"] >= 2  # twice() calls it twice
    for c in s["classes"]:  # each count agrees with the authoritative per-class assessment
        a = h6_result.index().assess_absence(c["name"])
        assert (c["references"] > 0) == bool(a.definitive_references)


def test_call_sites_use_the_h6_target_syntax(h6_result: Any) -> None:
    from apkforge.gui.references import call_sites
    from tests.fixtures.h6_apks import PKG, REPEATED_TARGET

    rows = call_sites(h6_result, f"{PKG}.A", "twice()Ljava/lang/String;")
    targets = [r["target"] for r in rows]
    assert REPEATED_TARGET in targets and REPEATED_TARGET.replace("#2", "#1") in targets


def test_references_job_and_call_sites(
    client: TestClient, apk: Path, h6_result: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from apkforge.gui import references
    from tests.fixtures.h6_apks import PKG, REPEATED_TARGET

    monkeypatch.setattr(references.ReferenceAnalysisService, "analyze", lambda self, a: h6_result)
    r = _post(client, "/api/jobs/references", apk=str(apk))
    assert r.status_code == 202, r.text
    job = _wait(client, r.json())
    assert job["status"] == "DONE", job["error"]
    assert job["result"]["apk_path"] == str(apk) and job["result"]["classes"]
    query = {"class_name": f"{PKG}.A", "method": "twice()Ljava/lang/String;"}
    url = f"/api/references/{job['result']['ref_id']}/call-sites"
    sites = client.get(url, headers=H, params=query)
    assert REPEATED_TARGET in [s["target"] for s in sites.json()]


def test_reference_call_sites_endpoint_expires(client: TestClient) -> None:
    r = client.get("/api/references/nope/call-sites", headers=H,
                   params={"class_name": "a.B", "method": "m()V"})  # fmt: skip
    assert r.status_code == 410
