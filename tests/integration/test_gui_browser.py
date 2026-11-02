"""Phase 9 GUI in a real browser (Playwright, headless Chromium).

The page is driven against an in-process server; the slow services are stubbed, so these
check the JavaScript: rendering, tab handoffs and what the page sends. Skipped unless
``playwright`` is installed with its Chromium (``playwright install chromium``) or a
Google Chrome is.
"""

from __future__ import annotations

import socket
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

pytest.importorskip("fastapi")
sync_api = pytest.importorskip("playwright.sync_api")

import uvicorn  # noqa: E402

from apkforge.gui.app import create_app  # noqa: E402
from apkforge.modkit.config import CONFIG_ENV_VAR  # noqa: E402
from apkforge.modkit.manager import TEST_MODKIT_ENV_VAR  # noqa: E402
from tests.fixtures import create_synthetic_apk  # noqa: E402

if TYPE_CHECKING:
    from collections.abc import Iterator

pytestmark = pytest.mark.integration

TOKEN = "ui-test-token"
#: The app the `server` fixture is serving, for tests that need its job manager.
SERVED: list[Any] = []


@pytest.fixture(scope="module")
def browser() -> Iterator[Any]:
    with sync_api.sync_playwright() as pw:
        b = None
        for kw in ({}, {"channel": "chrome"}):  # Playwright's Chromium, else installed Chrome
            try:
                b = pw.chromium.launch(**kw)
                break
            except Exception as e:
                reason = str(e).splitlines()[0]
        if b is None:
            pytest.skip(f"no browser for Playwright: {reason}")
        yield b
        b.close()


@pytest.fixture()
def server(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[str]:
    monkeypatch.delenv(CONFIG_ENV_VAR, raising=False)
    monkeypatch.setenv(TEST_MODKIT_ENV_VAR, "1")
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    app = create_app(TOKEN, upload_dir=tmp_path / "up")
    SERVED.append(app)
    srv = uvicorn.Server(uvicorn.Config(app, log_level="warning"))
    thread = threading.Thread(target=srv.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    while not srv.started:
        time.sleep(0.05)
    yield f"http://127.0.0.1:{sock.getsockname()[1]}"
    srv.should_exit = True
    thread.join(10)
    SERVED.clear()


@pytest.fixture()
def page(browser: Any, server: str) -> Iterator[Any]:
    p = browser.new_page()
    errors: list[str] = []
    p.on("pageerror", lambda e: errors.append(str(e)))
    p.goto(f"{server}/#token={TOKEN}")
    yield p
    p.close()
    assert not errors, errors


@pytest.fixture()
def apk(tmp_path: Path) -> Path:
    return create_synthetic_apk(tmp_path / "in" / "app.apk")


def test_modifier_parameters_render_as_fields(page: Any) -> None:
    page.click("nav button[data-tab=modify]")
    page.wait_for_selector("#modifier-list fieldset")
    assert "[object" not in page.inner_text("#modifier-list")
    for label in page.query_selector_all("#modifier-list label[for]"):
        assert page.query_selector(f'[id="{label.get_attribute("for")}"]') is not None


def test_references_hand_targets_to_transform(
    page: Any, apk: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from apkforge.gui import references
    from apkforge.reference import ApkIdentity, ReferenceAnalysisService
    from tests.fixtures.h1_apks import write_project
    from tests.fixtures.h6_apks import H6_FIXTURES, PKG, REPEATED_TARGET

    result = ReferenceAnalysisService.analyze_decoded(
        write_project(H6_FIXTURES[0], tmp_path / "h6"), identity=ApkIdentity(file_name="h6.apk")
    )
    monkeypatch.setattr(references.ReferenceAnalysisService, "analyze", lambda self, a: result)

    page.click("nav button[data-tab=references]")
    page.fill("#ref-apk", str(apk))
    page.click("#form-references button[type=submit]")
    page.wait_for_selector("#out-references summary")
    classes = "#out-references table > tbody > tr > td:first-child > details > summary"
    unreferenced = page.locator(classes).all_inner_texts()
    assert f"{PKG}.Source" not in unreferenced  # A calls it; the default view hides it
    page.uncheck("#out-references label.check input")
    page.fill("#out-references input.filter", "h1.a")
    assert page.locator(classes).all_inner_texts() == [f"{PKG}.A"]

    page.click(f"{classes} >> text={PKG}.A")
    row = page.locator("#out-references tr", has_text="twice()Ljava/lang/String;").last
    row.get_by_role("button", name="Call sites…").click()
    replace = page.get_by_role("button", name="Replace call (H-TRANS-003)…")
    replace.nth(1).click()  # the second getValue() call: the #2 target
    assert page.get_attribute("nav button[aria-selected=true]", "data-tab") == "transform"
    assert page.input_value("#tr-id") == "H-TRANS-003"
    assert page.input_value("#tr-target") == REPEATED_TARGET
    assert page.input_value("#tr-apk") == str(apk)
    assert page.evaluate("document.activeElement.id") == "tr-replacement"  # not submitted


def test_invalid_declared_changes_are_not_sent(page: Any, apk: Path) -> None:
    page.click("nav button[data-tab=verify]")
    page.fill("#verify-original", str(apk))
    page.click("#tab-verify details summary")
    page.fill("#verify-expected", "{not json")
    posts: list[str] = []
    page.on("request", lambda r: posts.append(r.url) if r.method == "POST" else None)
    page.click("#form-verify button[type=submit]")
    page.wait_for_selector("#out-verify .error")
    assert "not valid JSON" in page.inner_text("#out-verify")
    assert posts == []


def test_modify_result_verifies_its_declared_changes(
    page: Any, apk: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from apkforge.gui import changes

    calls: list[dict[str, Any]] = []

    class Report:
        def model_dump(self, **kw: Any) -> dict[str, Any]:
            return {"verification": {"overall": "VERIFIED", "checks": {}}, "unexpected": [],
                    "unknown": [], "expected": [], "limitations": []}  # fmt: skip

    def fake_verify_pair(original: Path, modified: Path, **kw: Any) -> tuple[Report, None]:
        calls.append({**kw, "original": original, "modified": modified})
        return Report(), None

    monkeypatch.setattr(changes, "verify_pair", fake_verify_pair)
    out = create_synthetic_apk(tmp_path / "out" / "app.apk")
    change = {
        "category": "uses_permission",
        "kind": "removed",
        "identifier": "android.permission.X",
    }
    job = {  # a finished Modify apply, as the Jobs tab would show it
        "id": "j1", "kind": "apply", "status": "DONE", "error": None, "cancel_requested": False,
        "created": "", "finished": "",
        "summary": {"preview_kind": "modify-preview", "apk": str(apk), "output": str(out)},
        "result": {"status": "verified", "output_apk": str(out), "modifiers": [{"plan": {
            "expected_changes": [change],
            "file_changes": [{"path": "AndroidManifest.xml", "action": "modified"}]}}]},
    }  # fmt: skip
    page.click("nav button[data-tab=modify]")
    page.evaluate("job => showJob(job, document.getElementById('out-modify'))", job)
    page.get_by_role("button", name="Verify output").click()
    page.wait_for_selector("#out-verify .badge:text('DONE')")
    (first,) = calls
    assert (str(first["original"]), str(first["modified"])) == (str(apk), str(out))
    assert [e.identifier for e in first["expected"]] == ["android.permission.X"]
    assert first["planned_entries"] == {"AndroidManifest.xml"}

    # the planned files belonged to that handoff: a manual re-run does not resend them
    page.click("#form-verify button[type=submit]")
    deadline = time.monotonic() + 10
    while len(calls) < 2 and time.monotonic() < deadline:
        time.sleep(0.05)
    assert calls[1]["planned_entries"] is None
    assert [e.identifier for e in calls[1]["expected"]] == ["android.permission.X"]


def test_download_apk_of_a_finished_apply(page: Any, apk: Path) -> None:
    jobs = SERVED[0].state.jobs
    job = jobs.submit("apply", {"output": str(apk)}, lambda: {"status": "verified"})
    deadline = time.monotonic() + 10
    while jobs.get(job.id).status != "DONE":
        assert time.monotonic() < deadline
        time.sleep(0.02)
    page.click("nav button[data-tab=jobs]")
    page.click("#job-list tr.clickable")  # newest first
    with page.expect_download() as info:
        page.get_by_role("button", name="Download APK").click()
    download = info.value
    assert download.suggested_filename == "app.apk"
    assert Path(download.path()).read_bytes() == apk.read_bytes()


# -- 9.4: the remaining tabs -----------------------------------------------------------------


def _param(page: Any, container: str, name: str) -> Any:
    """The input of parameter *name* in a ModKit parameter form (labels start with it)."""
    for label in page.query_selector_all(f"{container} label[for]"):
        if label.inner_text().split(" ")[0] == name:
            return page.locator(f'[id="{label.get_attribute("for")}"]')
    raise AssertionError(f"no parameter {name}")


def test_analyze_findings_then_remediate_and_apply(
    page: Any, apk: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import shutil
    from types import SimpleNamespace

    from apkforge.gui import changes
    from apkforge.remediation import RemediationService
    from apkforge.remediation.models import RemediationPlan

    finding = {"id": "PRIV-REC-BOOT", "title": "Starts at boot", "severity": "medium",
               "description": "d", "category": "persistence"}  # fmt: skip

    class Finding:
        def model_dump(self, **kw: Any) -> dict[str, Any]:
            return finding

    class Candidate:
        def model_dump(self, **kw: Any) -> dict[str, Any]:
            return {"remediation": {"id": "G-REM-001", "name": "Disable boot receiver"},
                    "is_supported": True}  # fmt: skip

    def plan(cls: object, a: Path, finding_id: str, **kw: Any) -> RemediationPlan:
        return RemediationPlan(plan_id="p1", source_apk_path=str(a), source_apk_sha256="x",
                               finding_id=finding_id, finding_category="persistence",
                               finding_title="Starts at boot", remediation_id="G-REM-001",
                               remediation_name="Disable boot receiver")  # fmt: skip

    def apply(cls: object, p: Any, approved: bool, output_path: Path) -> dict[str, Any]:
        shutil.copyfile(p.source_apk_path, output_path)
        return {"state": "verified", "output_apk_path": str(output_path)}

    monkeypatch.setattr(changes.PrivacyAnalysisService, "analyze",
                        lambda a: SimpleNamespace(findings=[Finding()]))  # fmt: skip
    monkeypatch.setattr(changes, "map_finding_to_remediations", lambda f: [Candidate()])
    monkeypatch.setattr(RemediationService, "plan", classmethod(plan))
    monkeypatch.setattr(RemediationService, "apply", classmethod(apply))

    page.fill("#analyze-apk", str(apk))  # Analyze is the first tab; real analysis
    page.click("#form-analyze button[type=submit]")
    page.wait_for_selector("#out-analyze h2")
    severities = page.locator("#out-analyze table tbody tr td:first-child").all_inner_texts()
    order = ["critical", "high", "medium", "low", "info"]
    ranks = [order.index(s.lower()) for s in severities if s.lower() in order]
    assert ranks == sorted(ranks)  # most severe first

    page.get_by_role("button", name="Open in Remediate").click()
    assert page.get_attribute("nav button[aria-selected=true]", "data-tab") == "remediate"
    assert page.input_value("#rem-apk") == str(apk)
    page.get_by_role("button", name="Plan G-REM-001").click()
    apply_form = page.locator("#out-remediate-plan form.apply")
    apply_form.wait_for()
    out = tmp_path / "out" / "fixed.apk"
    apply_form.locator("input").fill(str(out))
    apply_form.get_by_role("button", name="Apply remediation").click()
    page.wait_for_selector("#out-remediate-plan form.apply .badge:text('DONE')")
    assert out.read_bytes() == apk.read_bytes()
    assert apply_form.get_by_role("button", name="Download APK").is_visible()


def test_patch_options_form_fills_enable_and_options(page: Any) -> None:
    listing = {"patches": [
        {"index": 0, "name": "Clone", "enabled": False, "compatible": [], "options": [
            {"key": "packageName", "title": "Package name", "type": "String", "required": True},
            {"key": "darkMode", "type": "Boolean", "default": "false"}]},
        {"index": 1, "name": "Theme", "enabled": True, "compatible": [], "options": [
            {"key": "darkMode", "type": "Boolean", "default": "false"},
            {"key": "accent", "type": "String", "possible_values": [
                {"value": "#ff0000", "label": "Red"}, {"value": "#0000ff", "label": "Blue"}]}]},
        {"index": 2, "name": "Plain", "enabled": True, "compatible": [], "options": []},
    ]}  # fmt: skip
    page.evaluate(
        """listing => {
        const box = el("div", { id: "pt" });
        const options = el("input", { id: "pt-options", value: "manual=1, accent=#0000ff" });
        box.append(el("input", { id: "pt-enable" }), options);
        box.append(...renderPatches(listing, box.children[0], box.children[1]));
        document.getElementById("tab-modkits").append(box);
        document.querySelector("nav button[data-tab=modkits]").click();
    }""",
        listing,
    )
    boxes = page.locator("#pt table input[type=checkbox]")
    boxes.nth(0).check()
    boxes.nth(1).check()
    fields = page.locator("#pt label[for]")
    assert sorted(t.split(" ")[0] for t in fields.all_inner_texts()) == ["accent", "darkMode",
                                                                         "packageName"]  # fmt: skip
    accent = _param(page, "#pt", "accent")
    assert accent.input_value() == "#0000ff"  # prefilled from the options parameter
    presets = page.locator(f'[id="{accent.get_attribute("list")}"] option')
    assert presets.evaluate_all("os => os.map(o => o.value)") == ["#ff0000", "#0000ff"]
    accent.fill("#00ff00")  # presets are suggestions: any value is accepted
    use = page.get_by_role("button", name="Use selected as “enable” and “options”")
    use.click()
    assert "packageName is required" in page.inner_text("#pt")
    assert page.input_value("#pt-enable") == ""
    pkg = _param(page, "#pt", "packageName")
    pkg.fill("com.a,b")
    use.click()
    assert "cannot contain a comma" in page.inner_text("#pt")
    pkg.fill("com.example.clone")
    _param(page, "#pt", "darkMode").select_option("true")
    use.click()
    assert page.input_value("#pt-enable") == "Clone, Theme"
    assert page.input_value("#pt-options") == (
        "manual=1, packageName=com.example.clone, darkMode=true, accent=#00ff00"
    )
