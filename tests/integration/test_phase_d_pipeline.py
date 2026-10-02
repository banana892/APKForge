"""Phase D integration: the generalized pipeline on the real OpenLink APK.

Real toolchain, real BuildService, real DiffEngine. Skipped when the toolchain, the
OpenLink corpus APK or the committed semantic no-op baseline is missing.

A  C.5 OpenLink modification through the generalized pipeline
B  the test-only marker-asset modifier
C  both modifiers in one run (one build)
D  a failing modifier: the earlier one is rolled back, the later one not attempted
E  dry run: a plan, no modified APK, original unchanged
F  an undeclared (unexpected) change makes the run fail
"""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from apkforge.builders import BuildService, ToolchainConfig, ensure_dev_keystore
from apkforge.builders.semantic_baseline import NoopSemanticBaseline
from apkforge.diff.expectations import ObservationClass
from apkforge.modification.builtin import BootReceiverModifier, MarkerAssetModifier
from apkforge.modification.builtin.marker_asset import MARKER_CONTENT
from apkforge.modification.catalog import ModifierCatalog
from apkforge.modification.modifiers.base import StepStatus
from apkforge.modification.pipeline import (
    ModificationPipeline,
    ModifierRequest,
    PipelineResult,
    PipelineStatus,
)
from tests.integration.phase_d_modifiers import FailingModifier, UndeclaredChangeModifier
from tests.integration.test_c5_openlink import (
    ANDROID,
    BOOT,
    NOOP_BASELINE,
    OPENLINK,
    OTHER_RECEIVER,
    RECEIVER,
    _binary_manifest,
)

if TYPE_CHECKING:
    from apkforge.modification.contract import APKModifier

pytestmark = pytest.mark.integration

C5 = "c5.disable_boot_receiver"
MARKER = "test.marker_asset"
MARKER_PATH = "assets/apkforge-test/marker.txt"
STAGES = ["prepare", "decode", "build", "align", "sign", "verify"]


@pytest.fixture(scope="module")
def real_service(tmp_path_factory: pytest.TempPathFactory) -> BuildService:
    base = tmp_path_factory.mktemp("phase-d")
    toolchain = ToolchainConfig.discover(framework_dir=base / "framework")
    if toolchain.keytool is None:
        pytest.skip("keytool not available")
    signing = ensure_dev_keystore(toolchain.keytool, base / "dev-key")
    service = BuildService(toolchain, signing, work_dir=base / "work")
    check = service.check_toolchain()
    if not check.valid:
        pytest.skip(f"Build toolchain unavailable: {check.errors}")
    return service


@pytest.fixture(scope="module")
def noop_baseline() -> NoopSemanticBaseline:
    if not OPENLINK.is_file():
        pytest.skip(f"Corpus sample missing: {OPENLINK}")
    if not NOOP_BASELINE.is_file():
        pytest.skip("C.5 semantic no-op baseline not generated")
    return NoopSemanticBaseline.model_validate_json(NOOP_BASELINE.read_text())


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _run(
    service: BuildService,
    baseline: NoopSemanticBaseline,
    tmp_path: Path,
    ids: list[str],
    *,
    extra: list[APKModifier] | None = None,
    **kw: Any,
) -> PipelineResult:
    catalog = ModifierCatalog([BootReceiverModifier(), MarkerAssetModifier(), *(extra or [])])
    pipeline = ModificationPipeline(service, catalog)
    return pipeline.run(
        OPENLINK,
        [ModifierRequest(modifier_id=i) for i in ids],
        noop_baseline=baseline,
        work_dir=tmp_path / "work",
        **kw,
    )


def _expected(res: PipelineResult) -> list[tuple[str, str, str]]:
    assert res.verdict is not None
    return sorted(
        (c.observation.category, c.observation.kind, c.observation.identifier)
        for c in res.verdict.of(ObservationClass.EXPECTED_MODIFICATION)
    )


def _assert_clean_success(res: PipelineResult, sha_before: str) -> None:
    assert res.status == PipelineStatus.VERIFIED, res.failures
    assert [s.stage for s in res.stages] == STAGES
    assert all(s.status == "PASS" for s in res.stages)
    assert res.build_passed and res.apk_verified and res.modification_verified
    v = res.verification or {}
    assert v.get("valid") and v.get("zipalign_verified") and v.get("signature_verified")
    assert v.get("expected_signer_matched") and v.get("zip_integrity_verified")
    verdict = res.verdict
    assert verdict is not None and verdict.passed
    assert not verdict.of(ObservationClass.UNEXPECTED) and not verdict.of(ObservationClass.UNKNOWN)
    assert set(verdict.noise_rule_counts) <= set(res.noise_floor["allowed_noise_rules"] or [])
    assert res.original_preserved and _sha(OPENLINK) == sha_before == res.original_sha256_after
    assert res.workspace is not None and not Path(res.workspace).exists()


def test_a_openlink_c5_through_pipeline(
    real_service: BuildService, noop_baseline: NoopSemanticBaseline, tmp_path: Path
) -> None:
    sha_before = _sha(OPENLINK)
    out = tmp_path / "a.apk"
    res = _run(real_service, noop_baseline, tmp_path, [C5], output_apk=out)
    _assert_clean_success(res, sha_before)
    assert _expected(res) == [
        ("component", "modified", RECEIVER),
        ("uses_permission", "removed", BOOT),
    ]
    (run,) = res.modifiers
    assert run.step.status == StepStatus.SUCCESS and run.step.verified is True
    assert run.source_check is not None and run.source_check.modified == ["AndroidManifest.xml"]
    assert run.source_check.manifest_matches_plan
    assert run.verification is not None and all(c.satisfied for c in run.verification.checks)

    root = _binary_manifest(out)
    perms = {e.get(f"{ANDROID}name") for e in root.iter("uses-permission")}
    assert BOOT not in perms and perms
    receivers = {e.get(f"{ANDROID}name"): e for e in root.iter("receiver")}
    assert receivers[RECEIVER].get(f"{ANDROID}enabled") == "false"
    assert receivers[OTHER_RECEIVER].get(f"{ANDROID}enabled") == "true"


def test_b_marker_asset(
    real_service: BuildService, noop_baseline: NoopSemanticBaseline, tmp_path: Path
) -> None:
    sha_before = _sha(OPENLINK)
    out = tmp_path / "b.apk"
    res = _run(real_service, noop_baseline, tmp_path, [MARKER], output_apk=out)
    _assert_clean_success(res, sha_before)
    assert _expected(res) == [("file", "added", MARKER_PATH)]
    with zipfile.ZipFile(out) as z:
        assert z.read(MARKER_PATH) == MARKER_CONTENT
    root = _binary_manifest(out)
    assert BOOT in {e.get(f"{ANDROID}name") for e in root.iter("uses-permission")}


def test_c_two_modifiers_one_build(
    real_service: BuildService, noop_baseline: NoopSemanticBaseline, tmp_path: Path
) -> None:
    sha_before = _sha(OPENLINK)
    out = tmp_path / "c.apk"
    res = _run(real_service, noop_baseline, tmp_path, [C5, MARKER], output_apk=out)
    _assert_clean_success(res, sha_before)
    assert res.order == [C5, MARKER] and not res.conflicts
    assert [s.stage for s in res.stages].count("build") == 1
    assert _expected(res) == [
        ("component", "modified", RECEIVER),
        ("file", "added", MARKER_PATH),
        ("uses_permission", "removed", BOOT),
    ]
    assert [len(r.expected_observed) for r in res.modifiers] == [2, 1]
    assert res.counts()["verified"] == 2
    with zipfile.ZipFile(out) as z:
        assert z.read(MARKER_PATH) == MARKER_CONTENT
    receivers = {e.get(f"{ANDROID}name"): e for e in _binary_manifest(out).iter("receiver")}
    assert receivers[RECEIVER].get(f"{ANDROID}enabled") == "false"


def test_d_failure_rolls_back_and_stops(
    real_service: BuildService, noop_baseline: NoopSemanticBaseline, tmp_path: Path
) -> None:
    sha_before = _sha(OPENLINK)
    res = _run(
        real_service,
        noop_baseline,
        tmp_path,
        [MARKER, "test.failing", C5],
        extra=[FailingModifier()],
        keep_workspace=True,
    )
    assert res.status == PipelineStatus.FAILED
    marker, failing, c5 = res.modifiers
    assert marker.step.status == StepStatus.SUCCESS and marker.step.rolled_back
    assert failing.step.status == StepStatus.FAILED and "RuntimeError" in failing.step.message
    assert c5.step.status == StepStatus.PENDING
    assert c5.step.message == "Not attempted: execution stopped at test.failing"
    assert res.rollback is not None and res.rollback["restored"] is True
    assert [s.stage for s in res.stages] == ["prepare", "decode"]  # nothing built
    assert res.output_apk is None and res.build_passed is None
    decoded = Path(res.workspace or "") / "decoded"
    assert not (decoded / MARKER_PATH).exists()
    assert BOOT in (decoded / "AndroidManifest.xml").read_text()
    assert res.original_preserved and _sha(OPENLINK) == sha_before


def test_e_dry_run(
    real_service: BuildService, noop_baseline: NoopSemanticBaseline, tmp_path: Path
) -> None:
    sha_before = _sha(OPENLINK)
    out = tmp_path / "e.apk"
    res = _run(real_service, noop_baseline, tmp_path, [C5, MARKER], dry_run=True, output_apk=out)
    assert res.status == PipelineStatus.DRY_RUN and not res.failures
    assert [r.step.status for r in res.modifiers] == [StepStatus.DRY_RUN] * 2
    assert all(r.plan is not None and r.plan.ready for r in res.modifiers)
    c5_plan = res.modifiers[0].plan
    assert c5_plan is not None and [e.identifier for e in c5_plan.expected_changes] == [
        BOOT,
        RECEIVER,
    ]
    assert [s.stage for s in res.stages] == ["prepare", "decode"]
    assert res.output_apk is None and not out.exists() and res.verdict is None
    assert res.original_preserved and _sha(OPENLINK) == sha_before
    assert res.workspace is not None and not Path(res.workspace).exists()


def test_f_unexpected_change_fails(
    real_service: BuildService, noop_baseline: NoopSemanticBaseline, tmp_path: Path
) -> None:
    sha_before = _sha(OPENLINK)
    out = tmp_path / "f.apk"
    res = _run(
        real_service,
        noop_baseline,
        tmp_path,
        ["test.undeclared"],
        extra=[UndeclaredChangeModifier()],
        output_apk=out,
    )
    assert res.status == PipelineStatus.FAILED
    assert res.build_passed and res.apk_verified  # the APK itself is fine...
    v = res.verdict
    assert v is not None and not v.passed  # ...but the change was not planned
    (unexpected,) = v.of(ObservationClass.UNEXPECTED)
    assert (unexpected.observation.category, unexpected.observation.identifier) == (
        "file",
        UndeclaredChangeModifier.path,
    )
    assert "semantic: 1 unexpected change(s)" in res.failures
    (run,) = res.modifiers
    assert run.step.verified is None and run.verification_state == "not_verified"
    assert res.output_apk is None and not out.exists()
    assert res.original_preserved and _sha(OPENLINK) == sha_before
