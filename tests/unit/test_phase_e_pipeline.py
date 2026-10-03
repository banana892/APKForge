"""Phase E inside the modification lifecycle: baseline compatibility, planned entries,
verification matrix and report on every executed pipeline run."""

from __future__ import annotations

from pathlib import Path

import pytest

from apkforge.builders.semantic_baseline import (
    BaselineStatus,
    NoopSemanticBaseline,
    NoopSemanticEntry,
    SemanticResult,
)
from apkforge.diff.models import ChangeType, FileEntryDiff
from apkforge.modification.catalog import ModifierCatalog
from apkforge.modification.pipeline import ModificationPipeline, ModifierRequest, PipelineStatus
from apkforge.verification import OverallStatus
from tests.fixtures import create_synthetic_apk
from tests.unit.phase_d_support import (
    FakeDiff,
    Scripted,
    ZipService,
    diff_adding,
    scripted_path,
    sha,
)
from tests.unit.test_c5_boot_receiver import PKG
from tests.unit.test_c5_expectations import SIM_TOOLCHAIN, noise_baseline


@pytest.fixture()
def apk(tmp_path: Path) -> Path:
    return create_synthetic_apk(tmp_path / "in" / "app.apk", package_name=PKG)


def _run(apk: Path, tmp_path: Path, baseline: NoopSemanticBaseline | None, diff=None):  # type: ignore[no-untyped-def]
    pipeline = ModificationPipeline(
        ZipService(),  # type: ignore[arg-type]
        ModifierCatalog([Scripted("a")]),
        diff_engine=FakeDiff(diff or diff_adding(scripted_path("a"))),  # type: ignore[arg-type]
    )
    return pipeline.run(
        apk, [ModifierRequest(modifier_id="a")], noop_baseline=baseline, work_dir=tmp_path / "work"
    )


def test_compatible_baseline_verified_with_matrix_and_report(apk: Path, tmp_path: Path) -> None:
    res = _run(apk, tmp_path, noise_baseline(sha(apk)))
    assert res.status == PipelineStatus.VERIFIED, res.failures
    assert res.baseline_check is not None and res.baseline_check.status == BaselineStatus.COMPATIBLE
    assert res.toolchain_identity == SIM_TOOLCHAIN
    assert res.verification_matrix is not None
    assert res.verification_matrix.overall == OverallStatus.VERIFIED
    assert res.report is not None and res.report.verification.overall == OverallStatus.VERIFIED
    assert res.report.requested == ["a: add assets/scripted/a.txt"]
    assert res.noise_floor["content_aware"] is True


def test_incompatible_toolchain_baseline_is_rejected(apk: Path, tmp_path: Path) -> None:
    other = SIM_TOOLCHAIN.model_copy(update={"apktool": "2.10.0"})
    res = _run(apk, tmp_path, noise_baseline(sha(apk), toolchain=other))
    assert res.status == PipelineStatus.FAILED
    assert "BASELINE_INCOMPATIBLE" in res.failures[0]
    assert "noise floor is not established" in res.failures[0]
    assert res.verification_matrix is not None
    assert res.verification_matrix.overall != OverallStatus.VERIFIED


def test_legacy_baseline_is_not_verified(apk: Path, tmp_path: Path) -> None:
    v2 = noise_baseline(sha(apk))
    e = v2.entries[0]
    legacy = NoopSemanticBaseline(
        schema_version=1,
        entries=[
            NoopSemanticEntry(
                id=e.id,
                filename=e.filename,
                sha256=e.sha256,
                build_success=True,
                result=SemanticResult.EQUIVALENT,
                noise_rule_counts=e.noise_rule_counts,
            )
        ],
    )
    res = _run(apk, tmp_path, legacy)
    assert res.status == PipelineStatus.UNVERIFIED
    assert res.verification_matrix is not None
    assert res.verification_matrix.overall == OverallStatus.UNDETERMINED
    assert any("legacy" in w for w in res.warnings)


def test_undeclared_change_fails_with_unexpected_row(apk: Path, tmp_path: Path) -> None:
    extra = FileEntryDiff(
        path="assets/other.txt",
        change_type=ChangeType.ADDED,
        category="asset",
        size_after=1,
        sha256_after="1" * 64,
    )
    res = _run(
        apk, tmp_path, noise_baseline(sha(apk)), diff=diff_adding(scripted_path("a"), extra=[extra])
    )
    assert res.status == PipelineStatus.FAILED
    m = res.verification_matrix
    assert m is not None and m.status("unexpected_changes") == "failed"
    assert res.report is not None
    assert [u["identifier"] for u in res.report.unexpected] == ["assets/other.txt"]
