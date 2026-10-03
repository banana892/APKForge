"""Phase H.4 integration: control experiment on real synthetic APKs (H-TRANS-001 only).

Real APKs (tests/fixtures/h3_apks.py, published like real apps) go through H.1 -> H.2 ->
H.3 and are verified by H.4 against an unmodified control rebuild. Skipped when the build
toolchain is unavailable.

1  clean transformation (ELIGIBLE -> H.3 VERIFIED -> H.4 VERIFIED)
2  repeated transformation (identical plan, signal and classification)
3  natural build noise (two unmodified rebuilds)
4  unexpected mutation (H.3 pre-build detection; a late faulty mutation H.4 rejects)
5  unexpected resource modification          6  unexpected manifest modification
7  unexpected native change (added library; modified library without a plan)
8  incomplete analysis (truncated strings, failed native comparator, H.1 insufficient)
+  resource table re-encoded by the toolchain -> VERIFIED_WITH_LIMITATIONS; CLI
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from typer.testing import CliRunner

import apkforge.diff.strings as strings_mod
from apkforge.builders import BuildService, ToolchainConfig, ensure_dev_keystore
from apkforge.cli.main import app
from apkforge.diff.native import NativeDiffer
from apkforge.reference import ReferenceAnalysisService
from apkforge.transformation import (
    ApplicationReason,
    ApplicationStatus,
    Completeness,
    ControlExperiment,
    ControlPresence,
    DifferenceClass,
    EligibilityState,
    ExperimentResult,
    PlanningResult,
    RemoveIsolatedClassModifier,
    TransformationPlanningService,
    TransformationRequest,
    TransformationVerificationStatus,
    TransformationVerifier,
)
from apkforge.verification.models import CheckStatus
from tests.fixtures.h3_apks import H3_FIXTURES, PKG, TARGET, publish_fixture, publisher_key
from tests.fixtures.h4_apks import FAULTS, inject_at_build, unpublished_fixture

if TYPE_CHECKING:
    from apkforge.builders import SigningConfig

pytestmark = pytest.mark.integration

S = TransformationVerificationStatus
K = DifferenceClass
AS = ApplicationStatus
C1 = "H-TRANS-001"


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


@pytest.fixture(scope="module")
def base(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("h4")


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
def publisher(service: BuildService, base: Path) -> SigningConfig:
    assert service.toolchain.keytool is not None
    return publisher_key(service.toolchain.keytool, base / "publisher-key")


@pytest.fixture(scope="module")
def apks(service: BuildService, base: Path, publisher: SigningConfig) -> dict[str, Path]:
    fx = {f.name: f for f in H3_FIXTURES}
    out = {n: publish_fixture(service, fx[n], base / "fixtures", publisher)
           for n in ("h3_isolated", "h3_native")}  # fmt: skip
    out["unpublished"] = unpublished_fixture(
        service, fx["h3_isolated"], base / "fixtures-unpublished", publisher
    )
    return out


@pytest.fixture(scope="module")
def reference(service: BuildService, base: Path) -> ReferenceAnalysisService:
    return ReferenceAnalysisService(service, work_dir=base / "analysis")


@pytest.fixture(scope="module")
def experiment(service: BuildService, reference: ReferenceAnalysisService) -> ControlExperiment:
    return ControlExperiment(service, reference_service=reference)


def _plan(reference: ReferenceAnalysisService, apk: Path, path: Path) -> Path:
    res = TransformationPlanningService(reference).plan(
        apk, [TransformationRequest(transformation_id=C1, target=TARGET)]
    )
    (d,) = res.decisions
    assert d.eligibility is EligibilityState.ELIGIBLE and d.plan is not None, d.reasons
    path.write_text(res.to_json())
    return path


@pytest.fixture(scope="module")
def plan(reference: ReferenceAnalysisService, apks: dict[str, Path], base: Path) -> Path:
    return _plan(reference, apks["h3_isolated"], base / "plan.json")


@pytest.fixture(scope="module")
def clean(experiment: ControlExperiment, apks: dict[str, Path], plan: Path, base: Path) -> Any:
    return _run(experiment, apks["h3_isolated"], plan, base / "clean")


def _run(
    experiment: ControlExperiment, apk: Path, plan: Path, work: Path, **kw: Any
) -> ExperimentResult:
    before = _sha(apk)
    res = experiment.run(apk, plan, work, **kw)
    # mandatory invariant for every run: the original is byte-identical
    assert _sha(apk) == before == res.original_sha256 == res.original_sha256_after
    assert res.verification.original_unchanged is True
    paths = {res.control, res.transformed}
    assert str(apk) not in paths and (res.control is None or res.control != res.transformed)
    return res


def _unexpected(res: ExperimentResult) -> set[tuple[str, str, str, str]]:
    return {
        (str(d.domain), d.observation.category, d.observation.kind, d.observation.identifier)
        for d in res.verification.unexpected_changes
    }


# ---------------------------------------------------------------------------
# 1 / 2 / 3
# ---------------------------------------------------------------------------


def test_case1_clean_transformation(clean: ExperimentResult) -> None:
    v = clean.verification
    assert clean.application is not None and clean.application.status is AS.VERIFIED
    assert clean.transformed_source == "published"
    assert v.status is S.VERIFIED, (v.status_reason, v.unknown_changes)
    assert v.completeness is Completeness.COMPLETE
    assert all(d.completeness is Completeness.COMPLETE for d in v.domains.values())
    assert all(i.status == CheckStatus.PASSED for i in v.invariants), v.invariants
    assert v.domains["dex"].facts["classes_removed"] == [TARGET]
    assert v.domains["dex"].facts["classes"] == {"original": 3, "control": 3, "transformed": 2}
    exp = {(d.observation.category, d.observation.identifier) for d in v.expected_changes}
    assert ("dex_class", TARGET) in exp and ("file", "classes.dex") in exp
    assert {d.domain for d in v.expected_changes} == {"dex"}
    # the only noise is re-signing: certificate + v1 signature files, reproduced by B
    assert {d.domain for d in v.noise_changes} == {"signing"}
    assert {d.rule for d in v.noise_changes} == {"certificate_replaced", "signature_replaced"}
    assert v.domains["signing"].facts["resigned_by_apkforge"] is True
    assert not v.unexpected_changes and not v.unknown_changes and not v.declared_missing
    # declared changes equal H.3's (same derivation, independently re-run)
    assert clean.application is not None
    assert v.declared_changes == clean.application.expected_changes


def test_case2_repeated_transformation(
    experiment: ControlExperiment,
    reference: ReferenceAnalysisService,
    apks: dict[str, Path],
    clean: ExperimentResult,
    base: Path,
) -> None:
    apk = apks["h3_isolated"]
    plan2 = _plan(reference, apk, base / "plan-repeat.json")
    p1 = PlanningResult.model_validate_json((base / "plan.json").read_text())
    p2 = PlanningResult.model_validate_json(plan2.read_text())
    assert p1.decisions[0].plan == p2.decisions[0].plan  # plan identity
    again = _run(experiment, apk, plan2, base / "repeat")
    a, b = clean.verification, again.verification
    assert b.status is S.VERIFIED
    assert a.comparable() == b.comparable()  # semantic verification result identical
    assert a.transformed_rebuild.content_sha256 == b.transformed_rebuild.content_sha256
    assert [d.observation for d in a.noise_changes] == [d.observation for d in b.noise_changes] or (
        sorted(d.observation.identifier for d in a.noise_changes)
        == sorted(d.observation.identifier for d in b.noise_changes)
    )
    for v in (a, b):
        assert v.domains["dex"].facts["classes_removed"] == [TARGET]


def test_case3_natural_build_noise(experiment: ControlExperiment, apks: dict[str, Path],
                                   base: Path) -> None:  # fmt: skip
    apk = apks["h3_isolated"]
    before = _sha(apk)
    nf = experiment.noise_floor(apk, base / "noise")
    assert _sha(apk) == before == nf.original_sha256_after
    assert nf.noop_results == ["EQUIVALENT", "EQUIVALENT"]
    # measured, not assumed: entry contents and accepted noise are identical; the outer
    # bytes are recorded (ZIP metadata may or may not differ) but never relied on
    assert nf.entry_content_identical is True and nf.fingerprints_identical is True
    assert nf.apk_bytes_identical in (True, False)
    v = nf.verification
    assert v is not None and v.status is S.VERIFIED and v.mode == "noop"
    assert not v.expected_changes and not v.unexpected_changes and not v.unknown_changes
    assert v.legs["control->transformed"].observations == 0
    assert all(d.in_control is ControlPresence.SAME_CONTENT or d.rule == "signature_replaced"
               for d in v.noise_changes)  # fmt: skip


# ---------------------------------------------------------------------------
# 4-7: unexpected changes
# ---------------------------------------------------------------------------


def test_case4a_h3_faulty_mutation_is_never_built(
    experiment: ControlExperiment, apks: dict[str, Path], plan: Path, base: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    def remove_two(self: Any, path: Path) -> None:
        path.unlink()
        (path.parent / "C.smali").unlink()

    monkeypatch.setattr(RemoveIsolatedClassModifier, "_remove", remove_two)
    res = _run(experiment, apks["h3_isolated"], plan, base / "fault-h3",
               verify_unpublished=True)  # fmt: skip
    assert res.application is not None and res.application.status is AS.FAILED
    assert res.application.failure is not None
    assert res.application.failure.code is ApplicationReason.UNEXPECTED_MUTATION
    assert res.transformed is None  # nothing was built
    assert res.verification.status is S.UNVERIFIED


@pytest.mark.parametrize("fault", sorted(FAULTS))
def test_cases4_to_7_unexpected_changes_fail(
    experiment: ControlExperiment, service: BuildService, apks: dict[str, Path], plan: Path,
    base: Path, fault: str,
) -> None:  # fmt: skip
    """Build, align, sign succeed, but an unplanned change is in the output."""
    edit, domain = FAULTS[fault]
    with inject_at_build(service, edit):
        res = _run(experiment, apks["h3_isolated"], plan, base / f"fault-{fault}",
                   verify_unpublished=True)  # fmt: skip
    app_res = res.application
    assert app_res is not None and app_res.status is AS.FAILED  # H.3 refuses to publish
    assert AS.BUILT in app_res.status_history and app_res.output_apk is None
    assert res.transformed_source == "unpublished"
    v = res.verification
    assert v.status is S.FAILED, v.status_reason
    assert v.control_rebuild.noop_result == "EQUIVALENT"  # the control was not affected
    assert {u[0] for u in _unexpected(res)} == {domain}, _unexpected(res)
    assert v.domains[domain].status == CheckStatus.FAILED
    # not absorbed into the noise floor: none of it occurs in the control rebuild
    assert all(d.in_control is not ControlPresence.SAME_CONTENT for d in v.unexpected_changes)
    assert all(d.classification is K.UNEXPECTED_CHANGE for d in v.unexpected_changes)
    if fault == "other_class_removed":
        assert (domain, "dex_class", "removed", f"{PKG}.C") in _unexpected(res)
    if fault == "resource_modified":
        assert ("resources", "file", "modified", "resources.arsc") in _unexpected(res)
    if fault == "manifest_modified":
        assert ("manifest", "uses_permission", "added",
                "android.permission.INTERNET") in _unexpected(res)  # fmt: skip
    if fault == "native_added":
        assert ("native", "native_library", "added", "lib/arm64-v8a/libinjected.so") in (
            _unexpected(res)
        )


def test_case7_native_library_modification_without_plan(
    experiment: ControlExperiment, service: BuildService, apks: dict[str, Path], base: Path
) -> None:
    """No eligible plan exists for an APK with native code (H.2: NATIVE_DEPENDENCY_UNKNOWN),
    so a modified library is shown with the plan-less control experiment: B is an
    unmodified rebuild, C a rebuild whose .so changed. Detected by content hash only."""
    apk = apks["h3_native"]
    control, entry = experiment.rebuild_control(apk, base / "native" / "control")
    assert control is not None and entry.result == "EQUIVALENT"
    real = service.build

    def build(project: Path, out: Path, **kw: Any) -> Any:
        (project / "lib/arm64-v8a/libh3native.so").write_bytes(
            b"\x7fELF\x02\x01\x01\x00synthetic-modified"
        )
        return real(project, out, **kw)

    service.build = build  # type: ignore[method-assign]
    try:
        changed, _ = experiment.rebuild_control(apk, base / "native" / "changed")
    finally:
        service.build = real  # type: ignore[method-assign]
    assert changed is not None
    v = TransformationVerifier(service).verify_noop(apk, control, changed)
    assert v.status is S.FAILED
    lib = "lib/arm64-v8a/libh3native.so"
    assert {(d.observation.category, d.observation.identifier) for d in v.unexpected_changes} == {
        ("native_library", lib), ("file", lib),
    }  # fmt: skip
    native = v.domains["native"]
    assert native.status == CheckStatus.FAILED and native.completeness is Completeness.COMPLETE
    assert native.facts["analysis"].endswith("native code not analysed")


# ---------------------------------------------------------------------------
# 8: incomplete analysis
# ---------------------------------------------------------------------------


def _reverify(service: BuildService, reference: ReferenceAnalysisService,
              res: ExperimentResult, plan: Path) -> Any:  # fmt: skip
    assert res.control and res.transformed
    v = TransformationVerifier(service, reference_service=reference)
    return v.verify(res.original, res.control, res.transformed, plan)


def test_case8_truncated_string_comparison(
    service: BuildService, reference: ReferenceAnalysisService, clean: ExperimentResult,
    plan: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    monkeypatch.setattr(strings_mod, "_SAMPLE_LIMIT", 2)
    v = _reverify(service, reference, clean, plan)
    assert v.status is S.UNKNOWN, v.status_reason
    assert v.domains["dex"].completeness is not Completeness.COMPLETE
    assert any(d.observation.kind == "incomplete" for d in v.unknown_changes)


def test_case8_failed_native_comparator(
    service: BuildService, reference: ReferenceAnalysisService, clean: ExperimentResult,
    plan: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    def boom(self: Any, *a: Any, **k: Any) -> Any:
        raise RuntimeError("simulated native differ failure")

    monkeypatch.setattr(NativeDiffer, "diff", boom)
    v = _reverify(service, reference, clean, plan)
    assert v.status is S.UNKNOWN, v.status_reason
    assert v.domains["native"].completeness is Completeness.UNKNOWN
    assert v.completeness is Completeness.UNKNOWN


def test_case8_insufficient_h1_reanalysis(
    service: BuildService, reference: ReferenceAnalysisService, clean: ExperimentResult,
    plan: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    real = reference.analyze

    def analyze(apk: Path, *a: Any, **k: Any) -> Any:
        result = real(apk, *a, **k)
        if Path(apk) == Path(clean.transformed or ""):
            result.errors.append("simulated: DEX analysis aborted")
        return result

    monkeypatch.setattr(reference, "analyze", analyze)
    v = _reverify(service, reference, clean, plan)
    assert v.status is S.UNKNOWN, v.status_reason
    assert v.domains["dex"].completeness is Completeness.UNKNOWN


# ---------------------------------------------------------------------------
# limitations, CLI
# ---------------------------------------------------------------------------


def test_reencoded_resource_table_is_verified_with_limitations(
    experiment: ControlExperiment, reference: ReferenceAnalysisService,
    apks: dict[str, Path], base: Path,
) -> None:  # fmt: skip
    apk = apks["unpublished"]
    res = _run(experiment, apk, _plan(reference, apk, base / "plan-unpub.json"), base / "unpub")
    assert res.application is not None and res.application.status is AS.VERIFIED
    v = res.verification
    assert "resource_table_reencoded" in v.noise_floor["accepted_rule_counts"]
    assert v.status is S.VERIFIED_WITH_LIMITATIONS, v.status_reason
    assert v.domains["resources"].completeness is Completeness.PARTIAL
    assert v.completeness is Completeness.PARTIAL
    assert [x for x in v.limitations if x.startswith("[resources] PARTIAL")]
    arsc = [d for d in v.noise_changes if d.observation.identifier == "resources.arsc"]
    assert arsc and arsc[0].in_control is ControlPresence.SAME_CONTENT
    assert all(i.status == CheckStatus.PASSED for i in v.invariants)


def _cli(args: list[str], base: Path) -> Any:
    env = {"FORCE_COLOR": "3", "APKFORGE_DEV_KEY_DIR": str(base / "dev-key")}
    return CliRunner().invoke(app, args, env=env)


def test_cli_verify_with_control(clean: ExperimentResult, plan: Path, base: Path,
                                 tmp_path: Path) -> None:  # fmt: skip
    assert clean.control and clean.transformed
    before = _sha(Path(clean.original))
    report = tmp_path / "h4.md"
    work = ["--work-dir", str(tmp_path / "ws")]
    res = _cli(["verify", clean.original, clean.transformed, "--plan", str(plan),
                "--control", clean.control, "--built-locally", "--json", "--report",
                str(report), *work], base)  # fmt: skip
    assert res.exit_code == 0, res.output
    data = json.loads(res.stdout)
    assert data["status"] == "VERIFIED" and data["phase"] == "H.4"
    assert "Phase H.4" in report.read_text() and "\x1b" not in report.read_text()
    # build the control locally instead
    res = _cli(["verify", clean.original, clean.transformed, "--plan", str(plan),
                "--build-control", "--json", *work], base)  # fmt: skip
    assert res.exit_code == 0, res.output
    assert json.loads(res.stdout)["status"] == "VERIFIED"
    # the control given as the transformed APK: nothing to attribute -> FAILED (exit 1)
    res = _cli(["verify", clean.original, clean.control, "--plan", str(plan),
                "--build-control", "--json", *work], base)  # fmt: skip
    assert res.exit_code == 1, res.output
    assert _sha(Path(clean.original)) == before
