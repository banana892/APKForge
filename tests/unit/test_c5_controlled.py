"""C.5 controlled pipeline with a simulated BuildService and DiffEngine.

The real-toolchain run is tests/integration/test_c5_openlink.py; these tests cover the
orchestration decisions: refusal, stage failures, unexpected diffs, a missing noise
floor, original preservation and workspace cleanup.
"""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from apkforge.builders.models import (
    BuildFailureCategory,
    BuildStage,
    BuildVerificationResult,
    StageResult,
    StageStatus,
)
from apkforge.builders.semantic_baseline import (
    NoopSemanticBaseline,
    NoopSemanticEntry,
    SemanticResult,
)
from apkforge.builders.workspace import BuildWorkspace
from apkforge.diff.models import ComponentDiff, DiffResult, PermissionDiff
from apkforge.modification.controlled import ModificationStatus, run_disable_boot_receiver
from tests.fixtures import create_synthetic_apk
from tests.unit.test_c5_boot_receiver import BOOT_RX, OTHER_RX, PKG, manifest
from tests.unit.test_c5_expectations import _diff, _receiver

BOOT = "android.permission.RECEIVE_BOOT_COMPLETED"
NOISE = [
    "signature_replaced",
    "certificate_replaced",
    "manifest_reencoded",
    "dex_reencoded",
    "resource_table_reencoded",
    "resource_path_canonicalized",
]


def _ok(stage: BuildStage, **kw: Any) -> StageResult:
    return StageResult(stage=stage, status=StageStatus.PASS, **kw)


def _fail(stage: BuildStage, cat: BuildFailureCategory) -> StageResult:
    return StageResult(
        stage=stage,
        status=StageStatus.FAIL,
        failure_category=cat,
        failure_cause=f"simulated {stage} failure",
    )


class FakeService:
    """Stage methods with BuildService's signatures; no tools are run."""

    def __init__(
        self,
        decoded_manifest: str,
        *,
        fail: str | None = None,
        raise_in: str | None = None,
        tamper: Path | None = None,
    ) -> None:
        self.decoded_manifest = decoded_manifest
        self.fail, self.raise_in, self.tamper = fail, raise_in, tamper
        self.toolchain = SimpleNamespace(to_dict=lambda: {"apktool": "simulated"})
        self.signing = SimpleNamespace(mode="development")
        self.calls: list[str] = []
        self.workspaces: list[BuildWorkspace] = []

    def _step(self, name: str) -> None:
        self.calls.append(name)
        if self.raise_in == name:
            raise RuntimeError(f"simulated crash in {name}")

    def prepare_workspace(self, *, work_dir: Path | None = None, build_id: str | None = None):
        self._step("prepare")
        assert work_dir is not None
        ws = BuildWorkspace.create(work_dir, build_id)
        self.workspaces.append(ws)
        return ws, _ok(BuildStage.PREPARE)

    def decode(self, apk: Path, ws: BuildWorkspace, **_: Any) -> StageResult:
        self._step("decode")
        ws.decoded_dir.mkdir()
        (ws.decoded_dir / "AndroidManifest.xml").write_text(self.decoded_manifest)
        return _ok(BuildStage.DECODE)

    def build(self, project: Path, out: Path, **_: Any) -> StageResult:
        self._step("build")
        if self.tamper is not None:
            self.tamper.write_bytes(self.tamper.read_bytes() + b"x")
        if self.fail == "build":
            return _fail(BuildStage.BUILD, BuildFailureCategory.BUILD_FAILURE)
        out.write_bytes(b"PK unaligned")
        return _ok(BuildStage.BUILD)

    def align(self, src: Path, out: Path, **_: Any) -> StageResult:
        self._step("align")
        shutil.copyfile(src, out)
        return _ok(BuildStage.ALIGN)

    def sign(self, src: Path, out: Path, **_: Any) -> StageResult:
        self._step("sign")
        shutil.copyfile(src, out)
        return _ok(BuildStage.SIGN, certificate_sha256="ab" * 32)

    def verify(self, apk: Path, **_: Any) -> StageResult:
        self._step("verify")
        if self.fail == "verify":
            sr = _fail(BuildStage.VERIFY, BuildFailureCategory.VERIFICATION_FAILURE)
            sr.verification = BuildVerificationResult(valid=False)
            return sr
        return _ok(
            BuildStage.VERIFY,
            verification=BuildVerificationResult(
                valid=True,
                zipalign_verified=True,
                signature_verified=True,
                expected_signer_matched=True,
                zip_integrity_verified=True,
            ),
        )


class FakeDiff:
    def __init__(self, result: DiffResult) -> None:
        self.result = result
        self.calls: list[tuple[Path, Path]] = []

    def diff(self, a: Path, b: Path) -> DiffResult:
        self.calls.append((Path(a), Path(b)))
        return self.result


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


@pytest.fixture()
def apk(tmp_path: Path) -> Path:
    return create_synthetic_apk(tmp_path / "in" / "app.apk", package_name=PKG)


def _baseline(apk: Path) -> NoopSemanticBaseline:
    entry = NoopSemanticEntry(
        id="app",
        filename=apk.name,
        sha256=_sha(apk),
        build_success=True,
        result=SemanticResult.EQUIVALENT,
        noise_rule_counts=dict.fromkeys(NOISE, 1),
    )
    return NoopSemanticBaseline(entries=[entry])


def _planned() -> DiffResult:
    return _diff(
        permissions=PermissionDiff(removed=[BOOT]),
        components=ComponentDiff(receivers=[_receiver(BOOT_RX)]),
    )


def _run(
    apk: Path, tmp_path: Path, service: FakeService, diff: DiffResult | None = None, **kw: Any
):
    kw.setdefault("noop_baseline", _baseline(apk))
    return run_disable_boot_receiver(
        service,  # type: ignore[arg-type]
        apk,
        work_dir=tmp_path / "work",
        diff_engine=FakeDiff(diff or _planned()),  # type: ignore[arg-type]
        **kw,
    )


def _workspaces(tmp_path: Path) -> list[Path]:
    work = tmp_path / "work"
    return sorted(work.iterdir()) if work.exists() else []


class TestControlledPipeline:
    def test_verified_run(self, apk: Path, tmp_path: Path) -> None:
        before = _sha(apk)
        out = tmp_path / "out" / "modified.apk"
        svc = FakeService(manifest())
        res = _run(apk, tmp_path, svc, output_apk=out)
        assert res.status == ModificationStatus.VERIFIED, res.failures
        assert svc.calls == ["prepare", "decode", "build", "align", "sign", "verify"]
        assert res.plan is not None and res.plan.receiver == BOOT_RX
        assert res.apply is not None and res.apply.matches_plan
        assert res.verdict is not None and res.verdict.passed
        assert res.original_preserved and res.original_sha256_after == before == _sha(apk)
        assert res.output_apk == str(out.resolve()) and out.is_file()
        assert _workspaces(tmp_path) == []  # removed (keep_workspace=False)

    def test_decoded_manifest_edited_exactly(self, apk: Path, tmp_path: Path) -> None:
        svc = FakeService(manifest())
        res = _run(apk, tmp_path, svc, keep_workspace=True)
        assert res.status == ModificationStatus.VERIFIED
        (ws,) = svc.workspaces
        after = (ws.decoded_dir / "AndroidManifest.xml").read_text()
        assert BOOT not in after
        assert f'android:enabled="true" android:exported="true" android:name="{OTHER_RX}"' in after
        assert res.workspace_kept and Path(res.workspace or "").is_dir()

    def test_refused_when_target_missing(self, apk: Path, tmp_path: Path) -> None:
        svc = FakeService(manifest(permission=False))
        res = _run(apk, tmp_path, svc, keep_workspace=True)
        assert res.status == ModificationStatus.REFUSED
        assert "build" not in svc.calls and res.verdict is None
        (ws,) = svc.workspaces
        assert (ws.decoded_dir / "AndroidManifest.xml").read_text() == manifest(permission=False)
        assert res.original_preserved

    def test_refused_when_ambiguous(self, apk: Path, tmp_path: Path) -> None:
        res = _run(apk, tmp_path, FakeService(manifest(second_boot=True)))
        assert res.status == ModificationStatus.REFUSED
        assert "ambiguous_target" in res.failures[0]

    def test_build_failure_is_not_success(self, apk: Path, tmp_path: Path) -> None:
        svc = FakeService(manifest(), fail="build")
        res = _run(apk, tmp_path, svc)
        assert res.status == ModificationStatus.FAILED
        assert "align" not in svc.calls and res.output_apk is None
        assert any(f.startswith("build:") for f in res.failures)
        assert _workspaces(tmp_path) == []

    def test_verification_failure_fails_pipeline(self, apk: Path, tmp_path: Path) -> None:
        res = _run(apk, tmp_path, FakeService(manifest(), fail="verify"))
        assert res.status == ModificationStatus.FAILED and res.verdict is None
        assert any(f.startswith("verify:") for f in res.failures)

    def test_unexpected_diff_fails(self, apk: Path, tmp_path: Path) -> None:
        extra = _diff(
            permissions=PermissionDiff(removed=[BOOT, "android.permission.INTERNET"]),
            components=ComponentDiff(receivers=[_receiver(BOOT_RX)]),
        )
        res = _run(apk, tmp_path, FakeService(manifest()), diff=extra)
        assert res.status == ModificationStatus.FAILED
        assert any("unexpected" in f for f in res.failures)

    def test_missing_expected_change_fails(self, apk: Path, tmp_path: Path) -> None:
        only_perm = _diff(permissions=PermissionDiff(removed=[BOOT]))
        res = _run(apk, tmp_path, FakeService(manifest()), diff=only_perm)
        assert res.status == ModificationStatus.FAILED
        assert any("expected change not observed" in f for f in res.failures)

    def test_no_noise_baseline_fails(self, apk: Path, tmp_path: Path) -> None:
        res = _run(apk, tmp_path, FakeService(manifest()), noop_baseline=None)
        assert res.status == ModificationStatus.FAILED
        assert "noise floor is not established" in res.failures[0]

    def test_original_changed_fails(self, apk: Path, tmp_path: Path) -> None:
        res = _run(apk, tmp_path, FakeService(manifest(), tamper=apk))
        assert res.status == ModificationStatus.FAILED and not res.original_preserved
        assert "Original APK changed during the run." in res.failures

    def test_workspace_removed_on_exception(self, apk: Path, tmp_path: Path) -> None:
        with pytest.raises(RuntimeError, match="simulated crash"):
            _run(apk, tmp_path, FakeService(manifest(), raise_in="build"))
        assert _workspaces(tmp_path) == []
