"""Unit tests for Phase C.4 corpus validation (apkforge.builders.corpus).

Builds go through the real :class:`BuildService` with the simulated tools from
``test_build_service.FakeToolRunner``; no Java, Apktool or SDK is needed. The
authoritative real-toolchain corpus run is
``tests/integration/test_build_service_corpus.py`` (``APKFORGE_CORPUS_BUILD=1``)
and ``build-tests/run_corpus_validation.py``.
"""

from __future__ import annotations

import copy
import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any

import pytest

from apkforge.builders import BuildFailureCategory, BuildService, BuildStage, SigningConfig
from apkforge.builders import ToolchainConfig as TC
from apkforge.builders.corpus import (
    Comparison,
    CorpusManifest,
    CorpusManifestError,
    EntryIdentity,
    FinalStatus,
    Outcome,
    compare_outcome,
    compare_with_previous,
    render_report,
    resolve_entries,
    run_corpus,
    run_entry,
)
from tests.unit.test_build_service import PASSWORD, FakeToolRunner, _cr

C = BuildFailureCategory
S = BuildStage
SUCCESS = {"final_status": "SUCCESS", "failure_stage": None, "failure_category": "SUCCESS"}
RESOURCE_ERR = "error: attribute state_swiped (aka x.y:state_swiped) not found."


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_apk(path: Path, payload: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml", b"\x03\x00" + payload)
        z.writestr("lib/arm64-v8a/libx.so", b"\x7fELF" + payload)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _entry(entry_id: str, filename: str, digest: str, size: int, **kw: Any) -> dict[str, Any]:
    return {
        "id": entry_id,
        "filename": filename,
        "sha256": digest,
        "size_bytes": size,
        "package_name": f"pkg.{entry_id.split('@')[0]}",
        "expected": kw.pop("expected", {**SUCCESS, "evidence": "unit test"}),
        **kw,
    }


@pytest.fixture()
def corpus(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    """Two-APK corpus directory plus its manifest dict."""
    d = tmp_path / "corpus"
    entries = []
    for name in ("alpha", "beta"):
        apk = d / f"{name}.apk"
        digest = _make_apk(apk, name.encode())
        entries.append(_entry(f"{name}@1", apk.name, digest, apk.stat().st_size))
    manifest = {
        "schema_version": 1,
        "baseline_toolchain": {"java": "25.0.4.1", "apktool": "3.0.3"},
        "entries": entries,
    }
    return d, manifest


@pytest.fixture()
def toolchain(tmp_path: Path) -> TC:
    sdk = tmp_path / "sdk"
    bt = sdk / "build-tools" / "35.0.0"
    bt.mkdir(parents=True)
    for t in ("zipalign", "apksigner"):
        (bt / t).write_text("#!fake")
    plat = sdk / "platforms" / "android-35"
    plat.mkdir(parents=True)
    (plat / "android.jar").write_bytes(b"android-35")
    jdk = tmp_path / "jdk" / "bin"
    jdk.mkdir(parents=True)
    for t in ("java", "keytool"):
        (jdk / t).write_text("#!fake")
    (tmp_path / "apktool_3.0.3.jar").write_bytes(b"jar")
    return TC.discover(
        java=jdk / "java",
        apktool=tmp_path / "apktool_3.0.3.jar",
        android_sdk=sdk,
        framework_dir=tmp_path / "framework",
        environ={"PATH": ""},
    )


@pytest.fixture()
def runner(toolchain: TC) -> FakeToolRunner:
    return FakeToolRunner(toolchain)


@pytest.fixture()
def service(toolchain: TC, runner: FakeToolRunner, tmp_path: Path) -> BuildService:
    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "dev.p12").write_bytes(b"p12")
    (keys / "dev.password").write_text(PASSWORD + "\n")
    signing = SigningConfig(
        keystore=keys / "dev.p12",
        alias="apkforge-dev",
        password_file=keys / "dev.password",
        development_key=True,
    )
    return BuildService(toolchain, signing, runner=runner, work_dir=tmp_path / "default")  # type: ignore[arg-type]


def _fail_build_for(runner: FakeToolRunner, marker: str, err: str = RESOURCE_ERR) -> None:
    """Make ``apktool b`` fail for builds whose workspace path contains *marker*."""

    def handler(argv: list[str], _env: dict[str, str]) -> Any:
        if any(marker in a for a in argv):
            return _cr(argv, rc=1, err=err)
        return None

    runner.overrides["apktool:b"] = handler


def _run(service: BuildService, corpus: tuple[Path, dict[str, Any]], tmp_path: Path, **kw: Any):
    d, m = corpus
    return run_corpus(service, CorpusManifest.from_dict(m), d, tmp_path / "runs", **kw)


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


class TestManifest:
    def test_valid_manifest(self, corpus: tuple[Path, dict[str, Any]], tmp_path: Path) -> None:
        path = tmp_path / "manifest.json"
        path.write_text(json.dumps(corpus[1]))
        m = CorpusManifest.load(path)
        assert [e.id for e in m.entries] == ["alpha@1", "beta@1"]
        assert m.entries[0].expected.outcome == Outcome(FinalStatus.SUCCESS)
        assert m.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
        assert CorpusManifest.from_dict(m.to_dict()).to_dict() == m.to_dict()

    def test_repository_manifest_is_valid(self) -> None:
        path = Path(__file__).resolve().parents[1] / "corpus" / "manifest.json"
        m = CorpusManifest.load(path)
        assert len(m.entries) >= 1
        assert len({e.sha256 for e in m.entries}) == len(m.entries)

    @pytest.mark.parametrize(
        ("mutate", "message"),
        [
            (lambda m: m["entries"][0].update(sha256="ABC"), "sha256 must be 64"),
            (lambda m: m["entries"][0].update(sha256="g" * 64), "sha256 must be 64"),
            (lambda m: m["entries"][1].update(id="alpha@1"), "duplicate id"),
            (
                lambda m: m["entries"][1].update(sha256=m["entries"][0]["sha256"]),
                "duplicate sha256",
            ),
            (lambda m: m["entries"][0].update(filename="../x.apk"), "plain *.apk"),
            (lambda m: m["entries"][0].update(id="../evil"), "invalid id"),
            (lambda m: m["entries"][0].update(size_bytes=-1), "size_bytes"),
            (lambda m: m.update(schema_version=99), "schema_version"),
            (lambda m: m.update(entries=[]), "non-empty"),
            (
                lambda m: m["entries"][0].update(
                    expected={
                        "final_status": "FAILURE",
                        "failure_stage": "build",
                        "failure_category": "RESOURCE_FAILURE",
                    }
                ),
                "must document its reason",
            ),
            (
                lambda m: m["entries"][0].update(
                    expected={"final_status": "FAILURE", "reason": "x"}
                ),
                "needs failure_stage",
            ),
            (
                lambda m: m["entries"][0].update(
                    expected={**SUCCESS, "failure_category": "BUILD_FAILURE"}
                ),
                "cannot name a failure",
            ),
            (
                lambda m: m["entries"][0].update(
                    expected={**SUCCESS, "failure_category": "NOT_A_CATEGORY"}
                ),
                "invalid expected outcome",
            ),
        ],
    )
    def test_invalid_manifest(
        self, corpus: tuple[Path, dict[str, Any]], mutate: Any, message: str
    ) -> None:
        m = copy.deepcopy(corpus[1])
        mutate(m)
        with pytest.raises(CorpusManifestError) as exc:
            CorpusManifest.from_dict(m)
        assert any(message in e for e in exc.value.errors), exc.value.errors

    def test_known_failure_with_reason_is_valid(self, corpus: tuple[Path, dict[str, Any]]) -> None:
        m = copy.deepcopy(corpus[1])
        m["entries"][0]["expected"] = {
            "final_status": "FAILURE",
            "failure_stage": "build",
            "failure_category": "RESOURCE_FAILURE",
            "reason": "Unsupported resource structure",
        }
        e = CorpusManifest.from_dict(m).entries[0]
        assert e.expected.outcome == Outcome(FinalStatus.FAILURE, S.BUILD, C.RESOURCE_FAILURE)


class TestResolution:
    def test_all_present(self, corpus: tuple[Path, dict[str, Any]]) -> None:
        resolved, unlisted = resolve_entries(CorpusManifest.from_dict(corpus[1]), corpus[0])
        assert [r.identity for r in resolved] == [EntryIdentity.OK, EntryIdentity.OK]
        assert unlisted == []

    def test_missing_apk(self, corpus: tuple[Path, dict[str, Any]]) -> None:
        (corpus[0] / "beta.apk").unlink()
        resolved, _ = resolve_entries(CorpusManifest.from_dict(corpus[1]), corpus[0])
        assert resolved[1].identity == EntryIdentity.MISSING
        assert resolved[1].path is None and "No corpus APK" in (resolved[1].problem or "")

    def test_replaced_apk_is_hash_mismatch(self, corpus: tuple[Path, dict[str, Any]]) -> None:
        _make_apk(corpus[0] / "beta.apk", b"something else")
        resolved, _ = resolve_entries(CorpusManifest.from_dict(corpus[1]), corpus[0])
        assert resolved[1].identity == EntryIdentity.HASH_MISMATCH
        assert resolved[1].path is None and "replaced" in (resolved[1].problem or "")

    def test_renamed_apk_found_by_hash(self, corpus: tuple[Path, dict[str, Any]]) -> None:
        (corpus[0] / "beta.apk").rename(corpus[0] / "beta-renamed.apk")
        resolved, unlisted = resolve_entries(CorpusManifest.from_dict(corpus[1]), corpus[0])
        assert resolved[1].identity == EntryIdentity.RENAMED
        assert resolved[1].path == (corpus[0] / "beta-renamed.apk").resolve()
        assert unlisted == []

    def test_unlisted_apk_reported(self, corpus: tuple[Path, dict[str, Any]]) -> None:
        _make_apk(corpus[0] / "extra.apk", b"extra")
        _, unlisted = resolve_entries(CorpusManifest.from_dict(corpus[1]), corpus[0])
        assert unlisted == ["extra.apk"]


# ---------------------------------------------------------------------------
# Baseline comparison
# ---------------------------------------------------------------------------

OK = Outcome(FinalStatus.SUCCESS)
RES_FAIL = Outcome(FinalStatus.FAILURE, S.BUILD, C.RESOURCE_FAILURE)
ALIGN_FAIL = Outcome(FinalStatus.FAILURE, S.ALIGN, C.ALIGNMENT_FAILURE)
NOT_RUN = Outcome(FinalStatus.NOT_RUN)


@pytest.mark.parametrize(
    ("baseline", "actual", "expected"),
    [
        (OK, OK, Comparison.UNCHANGED_SUCCESS),
        (OK, RES_FAIL, Comparison.REGRESSION),
        (RES_FAIL, OK, Comparison.IMPROVEMENT),
        (RES_FAIL, RES_FAIL, Comparison.UNCHANGED_KNOWN_FAILURE),
        (RES_FAIL, ALIGN_FAIL, Comparison.NEW_FAILURE),
        (None, RES_FAIL, Comparison.NEW_FAILURE),
        (None, OK, Comparison.NEW_SUCCESS),
        (OK, NOT_RUN, Comparison.CORPUS_ERROR),
    ],
)
def test_compare_outcome(baseline: Outcome | None, actual: Outcome, expected: Comparison) -> None:
    assert compare_outcome(baseline, actual) == expected


def test_unexpected_flags() -> None:
    assert {c for c in Comparison if c.unexpected} == {
        Comparison.REGRESSION,
        Comparison.NEW_FAILURE,
        Comparison.CORPUS_ERROR,
    }


# ---------------------------------------------------------------------------
# Result recording (real BuildService, simulated tools)
# ---------------------------------------------------------------------------


class TestRecording:
    def test_successful_apk(
        self, service: BuildService, corpus: tuple[Path, dict[str, Any]], tmp_path: Path
    ) -> None:
        run = _run(service, corpus, tmp_path)
        r = run.results[0]
        assert r.outcome == OK and r.comparison == Comparison.UNCHANGED_SUCCESS
        assert list(r.stages) == [str(s) for s in S]
        assert all(st["status"] == "PASS" for st in r.stages.values())
        assert r.apk_sha256 == corpus[1]["entries"][0]["sha256"] and r.input_unchanged
        assert r.signing_mode == "development" and r.certificate_sha256
        # The simulated build output omits lib/, so only presence is asserted here.
        assert r.integrity is not None and r.integrity["native_lib_count"] == 1
        assert run.summary()["passed"] and run.summary()["successful"] == 2
        assert not (Path(r.workspace or "") / "signed" / "signed.apk").exists()  # output removed

    def test_known_failure(
        self,
        service: BuildService,
        runner: FakeToolRunner,
        corpus: tuple[Path, dict[str, Any]],
        tmp_path: Path,
    ) -> None:
        corpus[1]["entries"][0]["expected"] = {
            "final_status": "FAILURE",
            "failure_stage": "build",
            "failure_category": "RESOURCE_FAILURE",
            "reason": "AAPT2 cannot link a private attribute",
        }
        _fail_build_for(runner, "alpha@1")
        run = _run(service, corpus, tmp_path)
        r = run.results[0]
        assert r.comparison == Comparison.UNCHANGED_KNOWN_FAILURE and not r.unexpected
        assert r.outcome == RES_FAIL
        assert [r.stages[s]["status"] for s in ("align", "sign", "verify")] == ["SKIPPED"] * 3
        build = r.stages["build"]
        assert build["failure_category"] == "RESOURCE_FAILURE"
        assert build["evidence"] == RESOURCE_ERR and RESOURCE_ERR in build["stderr_tail"]
        assert build["failed_command"] and r.log_file and Path(r.log_file).is_file()
        assert any("AAPT2 cannot link" in n for n in r.notes)
        s = run.summary()
        assert s["known_failures"] == 1 and s["unexpected_failures"] == 0 and s["passed"]

    def test_unexpected_failure_is_regression(
        self,
        service: BuildService,
        runner: FakeToolRunner,
        corpus: tuple[Path, dict[str, Any]],
        tmp_path: Path,
    ) -> None:
        _fail_build_for(runner, "alpha@1")
        run = _run(service, corpus, tmp_path)
        assert run.results[0].comparison == Comparison.REGRESSION
        s = run.summary()
        assert s["regressions"] == 1 and s["unexpected_failures"] == 1 and not s["passed"]
        assert Path(run.results[0].workspace or "").is_dir()  # failure workspace retained

    def test_improvement(
        self, service: BuildService, corpus: tuple[Path, dict[str, Any]], tmp_path: Path
    ) -> None:
        corpus[1]["entries"][0]["expected"] = {
            "final_status": "FAILURE",
            "failure_stage": "build",
            "failure_category": "RESOURCE_FAILURE",
            "reason": "was broken",
        }
        run = _run(service, corpus, tmp_path)
        assert run.results[0].comparison == Comparison.IMPROVEMENT
        assert run.summary()["improvements"] == 1 and run.summary()["passed"]

    def test_different_failure_mode_is_new_failure(
        self,
        service: BuildService,
        runner: FakeToolRunner,
        corpus: tuple[Path, dict[str, Any]],
        tmp_path: Path,
    ) -> None:
        corpus[1]["entries"][0]["expected"] = {
            "final_status": "FAILURE",
            "failure_stage": "decode",
            "failure_category": "DECODE_FAILURE",
            "reason": "known decode issue",
        }
        _fail_build_for(runner, "alpha@1")
        run = _run(service, corpus, tmp_path)
        assert run.results[0].comparison == Comparison.NEW_FAILURE
        assert not run.summary()["passed"]

    def test_missing_and_replaced_apks_are_not_built(
        self,
        service: BuildService,
        runner: FakeToolRunner,
        corpus: tuple[Path, dict[str, Any]],
        tmp_path: Path,
    ) -> None:
        (corpus[0] / "alpha.apk").unlink()
        _make_apk(corpus[0] / "beta.apk", b"tampered")
        run = _run(service, corpus, tmp_path)
        for r in run.results:
            assert r.outcome.final_status == FinalStatus.NOT_RUN
            assert r.comparison == Comparison.CORPUS_ERROR and r.stages == {}
        assert run.results[1].identity == EntryIdentity.HASH_MISMATCH
        assert not any(a[0][0] == str(service.toolchain.java) and "d" in a[0] for a in runner.calls)
        assert run.summary()["corpus_errors"] == 2 and not run.summary()["passed"]

    def test_signing_secret_never_recorded(
        self, service: BuildService, corpus: tuple[Path, dict[str, Any]], tmp_path: Path
    ) -> None:
        # Tool-output masking is CommandRunner's job (tested in test_build_service);
        # this checks the corpus layer adds no secret of its own (signing, env, config).
        run = _run(service, corpus, tmp_path)
        assert run.results[0].stages["sign"]["status"] == "PASS"
        assert PASSWORD not in json.dumps(run.to_dict())
        assert PASSWORD not in render_report(run)


# ---------------------------------------------------------------------------
# Isolation
# ---------------------------------------------------------------------------


def test_failure_does_not_stop_or_contaminate_next_entry(
    service: BuildService,
    runner: FakeToolRunner,
    corpus: tuple[Path, dict[str, Any]],
    tmp_path: Path,
) -> None:
    _fail_build_for(runner, "alpha@1")
    run = _run(service, corpus, tmp_path)
    alpha, beta = run.results
    assert alpha.outcome.final_status == FinalStatus.FAILURE
    assert beta.outcome == OK and beta.comparison == Comparison.UNCHANGED_SUCCESS
    wa, wb = Path(alpha.workspace or ""), Path(beta.workspace or "")
    assert wa != wb and not wa.is_relative_to(wb.parent) and not wb.is_relative_to(wa.parent)
    assert "alpha@1" in str(wa) and "beta@1" in str(wb)
    assert (wa / "decoded").is_dir()  # failed entry keeps its evidence


def test_original_apks_untouched(
    service: BuildService, corpus: tuple[Path, dict[str, Any]], tmp_path: Path
) -> None:
    before = {p.name: p.read_bytes() for p in corpus[0].glob("*.apk")}
    _run(service, corpus, tmp_path)
    assert {p.name: p.read_bytes() for p in corpus[0].glob("*.apk")} == before


def test_attempt_directory_is_never_reused(
    service: BuildService, corpus: tuple[Path, dict[str, Any]], tmp_path: Path
) -> None:
    d, m = corpus
    resolved, _ = resolve_entries(CorpusManifest.from_dict(m), d)
    run_entry(service, resolved[0], tmp_path / "w")
    with pytest.raises(FileExistsError):
        run_entry(service, resolved[0], tmp_path / "w")


# ---------------------------------------------------------------------------
# Reproducibility / repeated runs
# ---------------------------------------------------------------------------


class TestReproducibility:
    def test_repeated_runs_consistent(
        self, service: BuildService, corpus: tuple[Path, dict[str, Any]], tmp_path: Path
    ) -> None:
        run = _run(service, corpus, tmp_path, repeat=3)
        for r in run.results:
            assert len(r.attempts) == 3 and r.consistent
            assert r.attempts[0]["apk_sha256"] == r.expected_sha256
        assert run.summary()["inconsistent"] == 0 and run.summary()["passed"]

    def test_flaky_result_detected(
        self,
        service: BuildService,
        runner: FakeToolRunner,
        corpus: tuple[Path, dict[str, Any]],
        tmp_path: Path,
    ) -> None:
        _fail_build_for(runner, "attempt-2")
        run = _run(service, corpus, tmp_path, repeat=2)
        assert all(not r.consistent for r in run.results)
        assert run.results[0].comparison == Comparison.UNCHANGED_SUCCESS  # first attempt rules
        assert run.summary()["inconsistent"] == 2 and not run.summary()["passed"]
        assert "Inconsistent repeated runs" in render_report(run)

    def test_run_records_reproducibility_metadata(
        self, service: BuildService, corpus: tuple[Path, dict[str, Any]], tmp_path: Path
    ) -> None:
        d = _run(service, corpus, tmp_path, repo_dir=tmp_path).to_dict()
        assert d["toolchain"]["versions"]["java"] == "25.0.4.1"
        assert d["toolchain"]["versions"]["apktool"] == "3.0.3"
        assert d["toolchain"]["versions"]["zipalign"] == "35.0.0"
        assert d["toolchain"]["versions"]["apksigner"] == "0.9"
        assert d["toolchain_differences"] == {}
        assert d["signing"]["mode"] == "development" and d["apkforge"]["version"]
        assert d["configuration"]["repeat"] == 1
        assert all(r["expected_sha256"] == r["apk_sha256"] for r in d["results"])


# ---------------------------------------------------------------------------
# Previous-run comparison and report
# ---------------------------------------------------------------------------


def test_compare_with_previous_run(
    service: BuildService,
    runner: FakeToolRunner,
    corpus: tuple[Path, dict[str, Any]],
    tmp_path: Path,
) -> None:
    previous = _run(service, corpus, tmp_path / "a").to_dict()
    previous["results"][1].update(
        final_status="FAILURE", failure_stage="align", failure_category="ALIGNMENT_FAILURE"
    )
    _fail_build_for(runner, "alpha@1")
    current = _run(service, corpus, tmp_path / "b")
    compare_with_previous(current, previous)
    assert current.results[0].previous == {
        "outcome": SUCCESS,
        "comparison": "REGRESSION",
    }
    assert (current.results[1].previous or {})["comparison"] == "IMPROVEMENT"
    assert current.summary()["vs_previous"]["REGRESSION"] == 1


def test_report_generated_from_results(
    service: BuildService,
    runner: FakeToolRunner,
    corpus: tuple[Path, dict[str, Any]],
    tmp_path: Path,
) -> None:
    corpus[1]["baseline_toolchain"]["apktool"] = "2.10.0"
    _fail_build_for(runner, "alpha@1")
    run = _run(service, corpus, tmp_path)
    text = render_report(run)
    assert "| alpha@1 | PASS | PASS | FAIL | skip | skip | skip |" in text
    assert "RESOURCE_FAILURE at build" in text and "REGRESSION" in text
    assert "- Total: 2" in text and "- Successful: 1" in text and "- Regressions: 1" in text
    assert "apktool: baseline 2.10.0 -> current 3.0.3" in text
    assert "Baseline check: FAILED" in text
