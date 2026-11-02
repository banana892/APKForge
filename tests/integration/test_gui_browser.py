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
    from pathlib import Path

pytestmark = pytest.mark.integration

TOKEN = "ui-test-token"


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
    srv = uvicorn.Server(uvicorn.Config(create_app(TOKEN, upload_dir=tmp_path / "up"),
                                        log_level="warning"))  # fmt: skip
    thread = threading.Thread(target=srv.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    while not srv.started:
        time.sleep(0.05)
    yield f"http://127.0.0.1:{sock.getsockname()[1]}"
    srv.should_exit = True
    thread.join(10)


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
