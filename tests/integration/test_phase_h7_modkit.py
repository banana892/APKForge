"""Phase H.7 - ModKit output through the existing pipeline (diff, Phase F, BuildService, H.4).

The reference ``test-modkit`` adds ``assets/test-modkit/marker.txt``. Its output is
consumed, unchanged, by the existing engines: nothing here is a second diff engine,
privacy rule set or verifier.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from apkforge.builders import BuildService, ToolchainConfig, ensure_dev_keystore
from apkforge.builders.semantic_baseline import current_toolchain_identity, run_semantic_noop
from apkforge.diff.expectations import ExpectedChange
from apkforge.modkit import (
    ExecutionRequest,
    ModKitExecutionResult,
    ModKitManager,
    ModKitPostAnalysis,
    ModKitResultStatus,
)
from apkforge.modkit.analysis import output_path
from apkforge.modkit.testing import MARKER_ENTRY, TEST_MODKIT_ID, TestModKitAdapter
from apkforge.transformation import TransformationVerifier
from apkforge.transformation.verification import (
    DifferenceClass,
    TransformationVerificationStatus,
)
from tests.fixtures import create_synthetic_apk
from tests.fixtures.h3_apks import H3_FIXTURES, publish_fixture, publisher_key

if TYPE_CHECKING:
    from apkforge.modkit import ModKitAnalysisReport

V = TransformationVerificationStatus


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _execute(apk: Path, out: Path, ws: Path, scenario: str = "success") -> ModKitExecutionResult:
    m = ModKitManager()
    m.register(TEST_MODKIT_ID, TestModKitAdapter)
    before = _sha(apk)
    res = m.execute(
        TEST_MODKIT_ID,
        ExecutionRequest(input_apk=apk, output_dir=out, operation="transform",
                         parameters={"scenario": scenario}, workspace_base=ws),
    )  # fmt: skip
    assert _sha(apk) == before
    return res


# ---------------------------------------------------------------------------
# Synthetic APK: diff + Phase F/B before/after (no build toolchain needed)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def synthetic(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, ModKitExecutionResult]:
    base = tmp_path_factory.mktemp("h7-synthetic")
    apk = create_synthetic_apk(base / "app.apk")
    res = _execute(apk, base / "out", base / "ws")
    assert res.status is ModKitResultStatus.SUCCESS, res.reason
    return apk, res


@pytest.fixture(scope="module")
def report(synthetic: tuple[Path, ModKitExecutionResult]) -> ModKitAnalysisReport:
    logging.disable(logging.INFO)
    try:
        return ModKitPostAnalysis().run(synthetic[1])
    finally:
        logging.disable(logging.NOTSET)


def test_existing_diff_engine_consumes_output(
    synthetic: tuple[Path, ModKitExecutionResult],
) -> None:
    apk, res = synthetic
    diff = ModKitPostAnalysis().diff(res)
    assert diff.summary.files_added == 1 and diff.summary.files_removed == 0
    assert [e.path for e in diff.files.entries if e.change_type == "added"] == [MARKER_ENTRY]
    assert diff.apk_a.sha256 == _sha(apk)


def test_post_analysis_report(
    synthetic: tuple[Path, ModKitExecutionResult], report: ModKitAnalysisReport
) -> None:
    apk, res = synthetic
    assert report.original_sha256 == _sha(apk) == res.original.sha256  # type: ignore[union-attr]
    assert report.output_sha256 == _sha(output_path(res))
    assert report.diff_summary is not None and report.diff_summary["files_added"] == 1
    for delta in (report.privacy, report.security):
        assert delta is not None
        # a marker asset introduces and removes no finding
        assert delta.introduced == () and delta.removed == ()
        assert delta.retained == delta.findings_before == delta.findings_after
        assert delta.status_before and delta.status_after
    assert report.limitations


def test_post_analysis_refuses_unpublished_result(tmp_path: Path) -> None:
    apk = create_synthetic_apk(tmp_path / "app.apk")
    res = _execute(apk, tmp_path / "out", tmp_path / "ws", scenario="invalid-apk")
    assert res.status is ModKitResultStatus.OUTPUT_INVALID
    with pytest.raises(ValueError, match="published no output"):
        ModKitPostAnalysis().run(res)


# ---------------------------------------------------------------------------
# Real APK: BuildService hand-off and the H.4 verification hook
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def base(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("h7")


@pytest.fixture(scope="module")
def service(base: Path) -> BuildService:
    toolchain = ToolchainConfig.discover(framework_dir=base / "framework")
    if toolchain.keytool is None:
        pytest.skip("keytool not available")
    svc = BuildService(toolchain, ensure_dev_keystore(toolchain.keytool, base / "dev-key"),
                       work_dir=base / "ws")  # fmt: skip
    if not svc.check_toolchain().valid:
        pytest.skip("Build toolchain unavailable")
    return svc


@pytest.fixture(scope="module")
def legs(service: BuildService, base: Path) -> dict[str, Path]:
    """A = published fixture, B = control rebuild of A, C = rebuild of the ModKit output."""
    assert service.toolchain.keytool is not None
    pub = publisher_key(service.toolchain.keytool, base / "publisher-key")
    fx = {f.name: f for f in H3_FIXTURES}
    a = publish_fixture(service, fx["h3_isolated"], base / "fixtures", pub)
    res = _execute(a, base / "modkit-out", base / "modkit-ws")
    assert res.status is ModKitResultStatus.SUCCESS, res.reason
    mk = output_path(res)
    # The ModKit output is an ordinary APK for BuildService (no ModKit-specific signing).
    ctl = run_semantic_noop(service, a, entry_id="control", work_dir=base / "control")
    cand = run_semantic_noop(service, mk, entry_id="modkit", work_dir=base / "candidate")
    assert ctl.build_success and cand.build_success
    assert cand.input_unchanged
    return {
        "A": a,
        "MK": mk,
        "B": base / "control" / f"{a.stem}.noop.apk",
        "C": base / "candidate" / f"{mk.stem}.noop.apk",
    }


def test_h4_flags_undeclared_modkit_change(service: BuildService, legs: dict[str, Path]) -> None:
    before = _sha(legs["A"])
    res = TransformationVerifier(service).verify_external(
        legs["A"], legs["B"], legs["C"], toolchain=current_toolchain_identity(service)
    )
    assert res.mode == "external" and res.original_unchanged
    assert res.status is V.FAILED
    (u,) = res.unexpected_changes
    assert u.observation.identifier == MARKER_ENTRY
    assert u.classification is DifferenceClass.UNEXPECTED_CHANGE
    assert _sha(legs["A"]) == before


def test_h4_verifies_declared_modkit_change(service: BuildService, legs: dict[str, Path]) -> None:
    probe = TransformationVerifier(service).verify_external(
        legs["A"], legs["B"], legs["C"], toolchain=current_toolchain_identity(service)
    )
    obs = probe.unexpected_changes[0].observation
    declared = [
        ExpectedChange(
            category=obs.category,
            kind=obs.kind,
            identifier=obs.identifier,
            detail=obs.detail,
            description="test-modkit marker asset",
        )
    ]
    res = TransformationVerifier(service).verify_external(
        legs["A"], legs["B"], legs["C"], expected=declared,
        toolchain=current_toolchain_identity(service),
    )  # fmt: skip
    assert res.status in (V.VERIFIED, V.VERIFIED_WITH_LIMITATIONS), res.status_reason
    assert not res.unexpected_changes and not res.unknown_changes
    assert [d.observation.identifier for d in res.expected_changes] == [MARKER_ENTRY]


def test_post_analysis_verify_hook(
    service: BuildService, legs: dict[str, Path], base: Path
) -> None:
    """ModKitPostAnalysis.verify routes to H.4 (unsigned ModKit output, unknown toolchain)."""
    res = _execute(legs["A"], base / "hook-out", base / "hook-ws")
    v = ModKitPostAnalysis(verifier=TransformationVerifier(service)).verify(res, legs["B"])
    assert v.mode == "external" and v.original_unchanged
    assert v.status is not V.VERIFIED  # an undeclared change is never verified
