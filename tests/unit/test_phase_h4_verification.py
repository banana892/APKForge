"""Phase H.4 unit tests: three-leg attribution, completeness, status semantics, CLI usage.

No toolchain is needed: the three DiffEngine comparisons (original->control,
original->transformed, control->transformed) are simulated with the Phase E test
helpers, apksigner is a test double, plans come from H.2 over ``analyze_decoded``
fixture projects and the H.1 re-analysis uses ``analyze_decoded`` too. The real-APK path
is covered by tests/integration/test_phase_h4_verification.py.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

import apkforge.transformation.verifier as verifier_mod
from apkforge.cli.main import app
from apkforge.diff.expectations import ExpectedChange, Observation
from apkforge.diff.models import (
    CertificateDiff,
    ChangeType,
    ComparatorResult,
    ComparisonStatus,
    DEXDiff,
    FileDiff,
    NativeDiff,
    NativeLibraryDiff,
    PermissionDiff,
    StringDiff,
)
from apkforge.reference import ApkIdentity, ReferenceAnalysisService
from apkforge.transformation import (
    MANDATORY_DOMAINS,
    VERIFICATION_RESULT_SCHEMA_VERSION,
    Completeness,
    ControlPresence,
    DifferenceClass,
    TransformationPlanningService,
    TransformationRequest,
    TransformationVerificationResult,
    TransformationVerificationStatus,
    TransformationVerifier,
    VerificationDomain,
    format_verification_report,
)
from apkforge.transformation.modifier import removal_expectations
from apkforge.transformation.verification import weakest
from apkforge.transformation.verifier import domain_of
from apkforge.verification.models import CheckStatus, VerificationCheck
from tests.fixtures.h1_apks import FIXTURES, PKG, write_project
from tests.fixtures.h2_apks import H2_FIXTURES
from tests.fixtures.h3_apks import H3_FIXTURES, TARGET
from tests.unit.test_c5_expectations import (
    SIGNER_AFTER,
    SIM_TOOLCHAIN,
    _complete_comparisons,
    _diff,
    _f,
    _h,
)

S = TransformationVerificationStatus
K = DifferenceClass
D = VerificationDomain
ALL = {fx.name: fx for fx in (*FIXTURES, *H2_FIXTURES, *H3_FIXTURES)}
INTERNET = "android.permission.INTERNET"


# ---------------------------------------------------------------------------
# doubles
# ---------------------------------------------------------------------------


class FakeEngine:
    """DiffEngine stand-in: the diff for (before stem, after stem)."""

    def __init__(self, legs: dict[tuple[str, str], Any], on_diff: Any = None) -> None:
        self.legs, self.on_diff, self.calls = legs, on_diff, []

    def diff(self, a: Path, b: Path) -> Any:
        self.calls.append((Path(a).stem, Path(b).stem))
        if self.on_diff:
            self.on_diff(a, b)
        return self.legs[(Path(a).stem, Path(b).stem)]


class SigService:
    """apksigner stand-in: every APK verifies, signed by SIGNER_AFTER (APKForge)."""

    def __init__(self, work_dir: Path, *, valid: bool = True) -> None:
        self.work_dir, self.valid = work_dir, valid

    def check_toolchain(self) -> Any:
        return SimpleNamespace(valid=True, errors=[])

    def verify(self, apk: Path, *, expected_certificate_sha256: str | None = None) -> Any:
        d = {
            "signature_verified": self.valid,
            "zipalign_verified": True,
            "zip_integrity_verified": True,
            "expected_certificate_sha256": expected_certificate_sha256,
            "expected_signer_matched": (
                None if expected_certificate_sha256 is None
                else expected_certificate_sha256 == SIGNER_AFTER
            ),
            "certificate": {"sha256_digest": SIGNER_AFTER, "v2_scheme": True},
            "errors": [] if self.valid else ["apksigner: DOES NOT VERIFY"],
        }  # fmt: skip
        ver = SimpleNamespace(to_dict=lambda: d, errors=d["errors"])
        return SimpleNamespace(verification=ver, failure_cause=None)


class FakeReference:
    """H.1 stand-in returning real analyze_decoded results per APK."""

    def __init__(self, results: dict[str, Any]) -> None:
        self.results = results

    def analyze(self, apk: Path, **_: Any) -> Any:
        return self.results[Path(apk).stem]


@pytest.fixture(autouse=True)
def _structural_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    def ok(p: Path) -> VerificationCheck:
        if not Path(p).is_file():
            return VerificationCheck(name="structural", status=CheckStatus.FAILED, summary="x")
        return VerificationCheck(name="structural", status=CheckStatus.PASSED, summary="ok")

    monkeypatch.setattr(verifier_mod, "structural_check", ok)


def _zip(path: Path, tag: str) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("classes.dex", tag)
        z.writestr("AndroidManifest.xml", "m")
    return path


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


@pytest.fixture
def apks(tmp_path: Path) -> dict[str, Path]:
    return {n: _zip(tmp_path / f"{n}.apk", n) for n in ("orig", "ctrl", "cand")}


def _same(**kw: Any) -> Any:
    """Two APKs built by the same toolchain and key with identical entry content."""
    cert = [{"sha256_fingerprint": SIGNER_AFTER}]
    parts: dict[str, Any] = {
        "files": FileDiff(entries=[]),
        "certificates": CertificateDiff(status="SAME", count_before=1, count_after=1,
                                        certificates_before=cert, certificates_after=cert),
    }  # fmt: skip
    parts.update(kw)
    return _diff(**parts)


def _comparisons(**status: tuple[ComparisonStatus, bool]) -> dict[str, ComparatorResult]:
    out = _complete_comparisons()
    for name, (st, complete) in status.items():
        out[name] = ComparatorResult(comparator=name, status=st, complete=complete, reason="sim")
    return out


def _noop(
    apks: dict[str, Path],
    tmp_path: Path,
    ab: Any,
    ac: Any,
    bc: Any,
    *,
    service: Any = "sig",
    on_diff: Any = None,
) -> TransformationVerificationResult:
    engine = FakeEngine({("orig", "ctrl"): ab, ("orig", "cand"): ac, ("ctrl", "cand"): bc},
                        on_diff)  # fmt: skip
    svc = SigService(tmp_path / "ws") if service == "sig" else service
    v = TransformationVerifier(svc, diff_engine=engine)  # type: ignore[arg-type]
    before = _sha(apks["orig"])
    res = v.verify_noop(apks["orig"], apks["ctrl"], apks["cand"], toolchain=SIM_TOOLCHAIN)
    assert res.source_apk_sha256 == before
    return res


# ---------------------------------------------------------------------------
# noise floor: control rebuild vs a second unmodified rebuild
# ---------------------------------------------------------------------------


def test_noise_only_candidate_is_verified(apks: dict[str, Path], tmp_path: Path) -> None:
    res = _noop(apks, tmp_path, _diff(), _diff(), _same())
    assert res.status is S.VERIFIED, res.status_reason
    assert res.completeness is Completeness.COMPLETE
    assert res.schema_version == VERIFICATION_RESULT_SCHEMA_VERSION and res.phase == "H.4"
    assert not res.unexpected_changes and not res.unknown_changes and not res.expected_changes
    assert res.noise_changes and all(d.classification is K.NOISE for d in res.noise_changes)
    # every noise difference is reproduced by the control with the same content
    assert {d.in_control for d in res.noise_changes} == {ControlPresence.SAME_CONTENT}
    assert all(d.in_signal is False for d in res.noise_changes)
    assert set(res.domains) == {str(d) for d in MANDATORY_DOMAINS}
    assert all(d.status == CheckStatus.PASSED for d in res.domains.values())
    assert res.noise_floor["noop_result"] == "EQUIVALENT"
    assert res.noise_floor["baseline_status"] == "COMPATIBLE"
    assert res.control_rebuild.available and res.transformed_rebuild.available
    assert res.original_unchanged is True
    signing = res.domains["signing"].facts
    assert signing["resigned_by_apkforge"] is True
    assert (
        "also occurs in the unmodified control rebuild" in signing["certificate_change_explained"]
    )


def test_unexpected_permission_is_not_absorbed(apks: dict[str, Path], tmp_path: Path) -> None:
    perm = PermissionDiff(added=[INTERNET])
    res = _noop(apks, tmp_path, _diff(), _diff(permissions=perm), _same(permissions=perm))
    assert res.status is S.FAILED
    (u,) = res.unexpected_changes
    assert (u.domain, u.observation.category, u.observation.identifier) == (
        D.MANIFEST, "uses_permission", INTERNET,
    )  # fmt: skip
    assert u.in_control is ControlPresence.ABSENT and u.in_signal is True
    assert res.domains["manifest"].status == CheckStatus.FAILED
    assert res.domains["dex"].status == CheckStatus.PASSED  # other domains stay as they are


def test_noise_path_with_new_content_is_unexpected(apks: dict[str, Path], tmp_path: Path) -> None:
    """A resource-table change at a noise path is noise only with the control's content."""
    ac = _diff()
    for f in ac.files.entries:
        if f.path == "resources.arsc":
            f.sha256_after = _h("resources.arsc", "tampered")
    arsc = _f("resources.arsc", ChangeType.MODIFIED, "resource_table",
              sha256_after=_h("resources.arsc", "tampered"))  # fmt: skip
    bc = _same(files=FileDiff(entries=[arsc]))
    res = _noop(apks, tmp_path, _diff(), ac, bc)
    assert res.status is S.FAILED
    (u,) = res.unexpected_changes
    assert u.domain is D.RESOURCES and u.observation.identifier == "resources.arsc"
    assert u.in_control is ControlPresence.DIFFERENT_CONTENT
    assert u.rule == "resource_table_reencoded"  # path rule matched, content did not


def test_not_comparable_resource_table_gives_bounded_limitation(
    apks: dict[str, Path], tmp_path: Path
) -> None:
    nc = _comparisons(resource_table=(ComparisonStatus.NOT_COMPARABLE, False))
    res = _noop(apks, tmp_path, _diff(comparisons=nc), _diff(comparisons=nc), _same())
    assert res.status is S.VERIFIED_WITH_LIMITATIONS, res.status_reason
    assert res.completeness is Completeness.PARTIAL
    assert res.domains["resources"].completeness is Completeness.PARTIAL
    assert res.domains["resources"].status == CheckStatus.PARTIAL
    assert any(x.startswith("[resources] PARTIAL") for x in res.limitations)
    assert "resources" in res.status_reason


def test_undetermined_comparator_is_never_verified(apks: dict[str, Path], tmp_path: Path) -> None:
    und = _comparisons(native=(ComparisonStatus.UNDETERMINED, False))
    res = _noop(apks, tmp_path, _diff(), _diff(comparisons=und), _same())
    assert res.status is S.UNKNOWN
    assert res.domains["native"].completeness is Completeness.UNKNOWN
    assert res.domains["native"].status == CheckStatus.UNDETERMINED
    assert res.completeness is Completeness.UNKNOWN  # the weakest mandatory domain


def test_truncated_string_comparison_is_unknown(apks: dict[str, Path], tmp_path: Path) -> None:
    partial = _comparisons(strings=(ComparisonStatus.PARTIAL, False))
    ac = _diff(strings=StringDiff(total_added=51), comparisons=partial)
    res = _noop(apks, tmp_path, _diff(), ac, _same(strings=StringDiff(total_added=51)))
    assert res.status is S.UNKNOWN
    assert any(d.observation.kind == "incomplete" for d in res.unknown_changes)
    assert res.domains["dex"].status == CheckStatus.UNDETERMINED


def test_native_library_change_is_detected(apks: dict[str, Path], tmp_path: Path) -> None:
    lib = "lib/arm64-v8a/libx.so"
    nat = NativeDiff(libraries_modified=[NativeLibraryDiff(
        path=lib, abi="arm64-v8a", change_type=ChangeType.MODIFIED,
        sha256_before=_h(lib, "before"), sha256_after=_h(lib, "evil"))])  # fmt: skip
    files = FileDiff(entries=[*_diff().files.entries,
                              _f(lib, ChangeType.MODIFIED, "native_lib")])  # fmt: skip
    res = _noop(apks, tmp_path, _diff(), _diff(native=nat, files=files),
                _same(native=nat, files=FileDiff(entries=[_f(lib, ChangeType.MODIFIED,
                                                             "native_lib")])))  # fmt: skip
    assert res.status is S.FAILED
    assert {d.domain for d in res.unexpected_changes} == {D.NATIVE}
    assert {d.observation.category for d in res.unexpected_changes} == {"native_library", "file"}
    native = res.domains["native"]
    assert native.status == CheckStatus.FAILED
    assert any("native code is not analysed" in x for x in native.limitations)


def test_unusable_control_is_unverified(apks: dict[str, Path], tmp_path: Path) -> None:
    """A change every rebuild makes is not noise: the control is NOT_EQUIVALENT."""
    perm = PermissionDiff(added=[INTERNET])
    res = _noop(apks, tmp_path, _diff(permissions=perm), _diff(permissions=perm), _same())
    assert res.status is S.UNVERIFIED
    assert res.control_rebuild.noop_result == "NOT_EQUIVALENT"
    assert "noise floor" in res.status_reason
    assert not res.differences()  # nothing is classified against an unusable floor
    assert res.noise_floor["unexpected_in_control"] == [f"uses_permission added {INTERNET}"]
    assert res.completeness is Completeness.NOT_ANALYZED


@pytest.mark.parametrize("missing", ["ctrl", "cand"])
def test_missing_rebuild_is_unverified(apks: dict[str, Path], tmp_path: Path, missing: str) -> None:
    apks[missing].unlink()
    res = _noop(apks, tmp_path, _diff(), _diff(), _same())
    assert res.status is S.UNVERIFIED
    rec = res.control_rebuild if missing == "ctrl" else res.transformed_rebuild
    assert not rec.available and "file not found" in rec.reasons


def test_original_as_its_own_control_is_rejected(apks: dict[str, Path], tmp_path: Path) -> None:
    engine = FakeEngine({})
    v = TransformationVerifier(SigService(tmp_path), diff_engine=engine)  # type: ignore[arg-type]
    res = v.verify_noop(apks["orig"], apks["orig"], apks["cand"], toolchain=SIM_TOOLCHAIN)
    assert res.status is S.UNVERIFIED and not engine.calls


def test_signal_only_difference_is_unknown(apks: dict[str, Path], tmp_path: Path) -> None:
    """The control re-encodes a resource the candidate does not: not reproducible."""
    extra = _f("res/values/x.xml", ChangeType.MODIFIED, "resource")
    ab = _diff(files=FileDiff(entries=[*_diff().files.entries, extra]))
    bc = _same(files=FileDiff(entries=[_f("res/values/x.xml", ChangeType.MODIFIED, "resource")]))
    res = _noop(apks, tmp_path, ab, _diff(), bc)
    assert res.status is S.UNKNOWN
    (u,) = res.unknown_changes
    assert u.leg == "control->transformed" and "not reproduced" in u.reason


def test_signature_unverifiable_without_toolchain(apks: dict[str, Path], tmp_path: Path) -> None:
    res = _noop(apks, tmp_path, _diff(), _diff(), _same(), service=None)
    assert res.status is S.UNKNOWN
    assert res.domains["signing"].completeness is Completeness.UNKNOWN


def test_bad_signature_fails(apks: dict[str, Path], tmp_path: Path) -> None:
    res = _noop(apks, tmp_path, _diff(), _diff(), _same(),
                service=SigService(tmp_path, valid=False))  # fmt: skip
    assert res.status is S.FAILED
    assert res.domains["signing"].status == CheckStatus.FAILED


def test_original_changed_fails(apks: dict[str, Path], tmp_path: Path) -> None:
    def tamper(a: Path, b: Path) -> None:
        if Path(a).stem == "orig" and Path(b).stem == "cand":
            with zipfile.ZipFile(a, "a") as z:
                z.writestr("x", "y")

    res = _noop(apks, tmp_path, _diff(), _diff(), _same(), on_diff=tamper)
    assert res.original_unchanged is False and res.status is S.FAILED


def test_comparable_ignores_paths_and_archive_bytes(apks: dict[str, Path], tmp_path: Path) -> None:
    a = _noop(apks, tmp_path, _diff(), _diff(), _same())
    other = tmp_path / "copy"
    other.mkdir()
    for n, p in apks.items():
        shutil.copyfile(p, other / p.name)
        _zip(other / p.name, n) if n != "orig" else None
    copies = {n: other / p.name for n, p in apks.items()}
    b = _noop(copies, tmp_path, _diff(), _diff(), _same())
    assert a.source_apk != b.source_apk
    assert a.comparable() == b.comparable()


def test_report_renders(apks: dict[str, Path], tmp_path: Path) -> None:
    perm = PermissionDiff(added=[INTERNET])
    res = _noop(apks, tmp_path, _diff(), _diff(permissions=perm), _same(permissions=perm))
    md = format_verification_report(res)
    assert "Phase H.4" in md and "**FAILED**" in md and INTERNET in md
    assert "does not establish that the transformed application is safe" in md
    assert json.loads(res.to_json())["status"] == "FAILED"


# ---------------------------------------------------------------------------
# transformation mode (H-TRANS-001 plan)
# ---------------------------------------------------------------------------


def _planning(tmp_path: Path, fixture: str, sha: str, tid: str, target: str) -> Any:
    project = write_project(ALL[fixture], tmp_path / "projects" / fixture)
    result = ReferenceAnalysisService.analyze_decoded(
        project, identity=ApkIdentity(file_name=f"{fixture}.apk", sha256=sha)
    )
    req = TransformationRequest(transformation_id=tid, target=target)
    return TransformationPlanningService.plan_from_result(result, [req]), project


STRING = "h3-only-in-b"
EXPECTED = removal_expectations(TARGET, {STRING}, set())


def _dex(removed: list[str], strings: list[str]) -> dict[str, Any]:
    return {"dex": DEXDiff(classes_removed=removed),
            "strings": StringDiff(total_removed=len(strings), removed_sample=strings)}  # fmt: skip


def _transformed(**kw: Any) -> tuple[Any, Any]:
    """(A -> C, B -> C) of a correct removal of TARGET: DEX changes + regenerated sigs."""
    dex_c = _f("classes.dex", ChangeType.MODIFIED, "dex", sha256_after=_h("classes.dex", "C"))
    mf_c = _f("META-INF/MANIFEST.MF", ChangeType.MODIFIED, "signature",
              sha256_after=_h("MANIFEST.MF", "C"))  # fmt: skip
    noise = [
        f for f in _diff().files.entries if f.path not in ("classes.dex", "META-INF/MANIFEST.MF")
    ]
    ac = _diff(files=FileDiff(entries=[*noise, dex_c, mf_c]), **_dex([TARGET], [STRING]))
    bc = _same(files=FileDiff(entries=[
        _f("classes.dex", ChangeType.MODIFIED, "dex", sha256_before=_h("classes.dex", "after"),
           sha256_after=_h("classes.dex", "C")),
        _f("META-INF/MANIFEST.MF", ChangeType.MODIFIED, "signature"),
        _f("META-INF/APKFORGE.RSA", ChangeType.MODIFIED, "certificate"),
    ]), **_dex([TARGET], [STRING]))  # fmt: skip
    for k, v in kw.items():
        setattr(ac, k, v)
        setattr(bc, k, v)
    return ac, bc


@pytest.fixture
def plan_env(apks: dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    sha = _sha(apks["orig"])
    planning, project = _planning(tmp_path, "h3_isolated", sha, "H-TRANS-001", TARGET)
    assert planning.decisions[0].plan is not None
    plan = tmp_path / "plan.json"
    plan.write_text(planning.to_json())
    pre = ReferenceAnalysisService.analyze_decoded(
        project, identity=ApkIdentity(file_name="orig.apk", sha256=sha)
    )
    post_project = tmp_path / "post"
    shutil.copytree(project, post_project)
    (post_project / "smali/com/example/h1/B.smali").unlink()
    post = ReferenceAnalysisService.analyze_decoded(
        post_project, identity=ApkIdentity(file_name="cand.apk", sha256="0" * 64))  # fmt: skip
    classes = {"orig": {f"{PKG}.{c}" for c in "ABC"}, "ctrl": {f"{PKG}.{c}" for c in "ABC"},
               "cand": {f"{PKG}.A", f"{PKG}.C"}}  # fmt: skip
    monkeypatch.setattr(verifier_mod, "_classes", lambda p: classes[Path(p).stem])
    return SimpleNamespace(plan=plan, reference=FakeReference({"orig": pre, "cand": post}),
                           classes=classes)  # fmt: skip


def _verify(
    apks: dict[str, Path],
    tmp_path: Path,
    env: Any,
    ac: Any,
    bc: Any,
    *,
    expected: list[ExpectedChange] | None = None,
) -> TransformationVerificationResult:
    engine = FakeEngine({("orig", "ctrl"): _diff(), ("orig", "cand"): ac, ("ctrl", "cand"): bc})
    v = TransformationVerifier(SigService(tmp_path / "ws"), reference_service=env.reference,  # type: ignore[arg-type]
                               diff_engine=engine)  # fmt: skip
    return v.verify(apks["orig"], apks["ctrl"], apks["cand"], env.plan, toolchain=SIM_TOOLCHAIN,
                    expected=EXPECTED if expected is None else expected)  # fmt: skip


def test_transformation_verified(apks: dict[str, Path], tmp_path: Path, plan_env: Any) -> None:
    res = _verify(apks, tmp_path, plan_env, *_transformed())
    assert res.status is S.VERIFIED, (res.status_reason, res.unknown_changes)
    assert res.mode == "transformation" and res.transformation_id == "H-TRANS-001"
    assert res.target["class"] == TARGET
    exp = {(d.observation.category, d.observation.identifier) for d in res.expected_changes}
    assert exp == {("dex_class", TARGET), ("dex_string", STRING), ("file", "classes.dex")}
    assert all(d.attributable and d.in_signal for d in res.expected_changes)
    assert all(d.in_control is ControlPresence.ABSENT for d in res.expected_changes
               if d.observation.category != "file")  # fmt: skip
    inv = {i.name: i.status for i in res.invariants}
    assert set(inv.values()) == {CheckStatus.PASSED}, inv
    assert inv.keys() >= {
        "plan_integrity", "control_rebuild_equivalent", "target_defined_before",
        "target_absent_after", "exactly_one_class_removed[original->transformed]",
        "exactly_one_class_removed[control->transformed]", "class_count",
        "h1_reference_state", "declared_changes_observed", "no_unexpected_change",
        "signature_verified", "original_unchanged",
    }  # fmt: skip
    # the regenerated v1 signature files are noise on both legs, never expected
    sig = [d for d in res.noise_changes if d.domain is D.SIGNING]
    assert {d.leg for d in sig} == {"original->transformed", "control->transformed"}
    assert res.post_analysis is not None and not res.post_analysis.target_defined


def test_unrelated_class_removed_fails(
    apks: dict[str, Path], tmp_path: Path, plan_env: Any
) -> None:
    ac, bc = _transformed(dex=DEXDiff(classes_removed=[TARGET, f"{PKG}.C"]))
    plan_env.classes["cand"] = {f"{PKG}.A"}
    res = _verify(apks, tmp_path, plan_env, ac, bc)
    assert res.status is S.FAILED
    assert any(d.observation.identifier == f"{PKG}.C" for d in res.unexpected_changes)
    inv = {i.name: i.status for i in res.invariants}
    assert inv["exactly_one_class_removed[original->transformed]"] == CheckStatus.FAILED
    assert inv["class_count"] == CheckStatus.FAILED
    assert res.domains["dex"].status == CheckStatus.FAILED


def test_target_not_removed_fails(apks: dict[str, Path], tmp_path: Path, plan_env: Any) -> None:
    """Build succeeded, nothing changed: target removal cannot be established -> FAILED."""
    plan_env.classes["cand"] = plan_env.classes["orig"]
    res = _verify(apks, tmp_path, plan_env, _diff(), _same())
    assert res.status is S.FAILED
    assert len(res.declared_missing) == 4  # 2 declared changes x 2 legs
    inv = {i.name: i.status for i in res.invariants}
    assert inv["target_absent_after"] == CheckStatus.FAILED
    assert inv["declared_changes_observed"] == CheckStatus.FAILED


def test_expected_change_also_in_control_is_not_attributed(
    apks: dict[str, Path], tmp_path: Path, plan_env: Any
) -> None:
    """A declared change the control already shows is not the transformation's signal."""
    ac, _ = _transformed()
    _, bc_without_class = _transformed(dex=DEXDiff())
    res = _verify(apks, tmp_path, plan_env, ac, bc_without_class)
    assert res.status in (S.FAILED, S.UNKNOWN)
    assert res.status is not S.VERIFIED
    assert any(d.observation.category == "dex_class" for d in res.unknown_changes)


def test_unsupported_transformation_is_unverified(apks: dict[str, Path], tmp_path: Path) -> None:
    # H-TRANS-002 is now verifiable (H.5); a transformation outside the supported set is not.
    sha = _sha(apks["orig"])
    planning, _ = _planning(tmp_path, "g01_methods", sha, "H-TRANS-002", f"{PKG}.D->helper()V")
    decision = planning.decisions[0]
    assert decision.plan is not None
    forged = decision.plan.model_copy(update={"transformation_id": "H-TRANS-404"})
    plan = tmp_path / "p2.json"
    plan.write_text(forged.model_dump_json())
    v = TransformationVerifier(SigService(tmp_path), diff_engine=FakeEngine({}))  # type: ignore[arg-type]
    res = v.verify(apks["orig"], apks["ctrl"], apks["cand"], plan, toolchain=SIM_TOOLCHAIN)
    assert res.status is S.UNVERIFIED and "planning-only" in res.status_reason
    assert not res.legs


def test_plan_for_other_apk_is_unverified(
    apks: dict[str, Path], tmp_path: Path, plan_env: Any
) -> None:
    v = TransformationVerifier(SigService(tmp_path), diff_engine=FakeEngine({}))  # type: ignore[arg-type]
    res = v.verify(apks["ctrl"], apks["orig"], apks["cand"], plan_env.plan, toolchain=SIM_TOOLCHAIN,
                   expected=EXPECTED)  # fmt: skip
    assert res.status is S.UNVERIFIED and "not this original" in res.status_reason


def test_invalid_plan_is_unverified(apks: dict[str, Path], tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    v = TransformationVerifier(SigService(tmp_path), diff_engine=FakeEngine({}))  # type: ignore[arg-type]
    res = v.verify(apks["orig"], apks["ctrl"], apks["cand"], bad, toolchain=SIM_TOOLCHAIN)
    assert res.status is S.UNVERIFIED and "PLAN_INVALID" in res.status_reason


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("obs", "domain"),
    [
        (("dex_class", "removed", "a.B", {}), D.DEX),
        (("dex_string", "removed", "x", {}), D.DEX),
        (("file", "modified", "classes2.dex", {"file_category": "dex"}), D.DEX),
        (("uses_permission", "added", INTERNET, {}), D.MANIFEST),
        (("manifest_element", "modified", "x", {}), D.MANIFEST),
        (("file", "modified", "AndroidManifest.xml", {"file_category": "manifest"}), D.MANIFEST),
        (("file", "modified", "resources.arsc", {"file_category": "resource_table"}), D.RESOURCES),
        (("file", "added", "res/raw/x", {"file_category": "resource"}), D.RESOURCES),
        (("file", "added", "assets/x", {"file_category": "asset"}), D.ASSETS),
        (("native_library", "added", "lib/x86/a.so", {}), D.NATIVE),
        (("file", "added", "lib/x86/a.so", {"file_category": "native_lib"}), D.NATIVE),
        (("certificate", "modified", "signing_certificate", {}), D.SIGNING),
        (("file", "modified", "META-INF/CERT.SF", {"file_category": "signature"}), D.SIGNING),
        (("file", "added", "META-INF/services/x", {"file_category": "signature"}), D.ARCHIVE),
        (("file", "added", "kotlin/x.kotlin_builtins", {"file_category": "other"}), D.ARCHIVE),
        (("embedded", "added", "assets/x.apk", {}), D.ARCHIVE),
        (("network_url", "added", "https://x", {}), D.ENDPOINTS),
    ],
)
def test_domain_of(obs: tuple[str, str, str, dict[str, Any]], domain: VerificationDomain) -> None:
    cat, kind, ident, detail = obs
    assert (
        domain_of(Observation(category=cat, kind=kind, identifier=ident, detail=detail)) is domain
    )


def test_weakest() -> None:
    C = Completeness
    assert weakest([C.COMPLETE, C.PARTIAL]) is C.PARTIAL
    assert weakest([C.COMPLETE, C.UNKNOWN, C.PARTIAL]) is C.UNKNOWN
    assert weakest([C.COMPLETE, C.NOT_ANALYZED]) is C.NOT_ANALYZED
    assert weakest([C.COMPLETE]) is C.COMPLETE and weakest([]) is C.NOT_ANALYZED


def _cli(args: list[str]) -> Any:
    return CliRunner().invoke(app, args, env={"FORCE_COLOR": "3"})


def test_cli_usage_errors(apks: dict[str, Path], tmp_path: Path) -> None:
    a, c, t = (str(apks[n]) for n in ("orig", "ctrl", "cand"))
    plan = tmp_path / "plan.json"
    plan.write_text("{}")
    cases = [
        ["verify", a, t, "--control", c],  # --control without --plan
        ["verify", a, "--plan", str(plan), "--control", c],  # no MODIFIED
        ["verify", a, t, "--plan", str(plan)],  # no control
        ["verify", a, t, "--plan", str(plan), "--control", c, "--build-control"],
        ["verify", a, t, "--plan", str(plan), "--control", c, "--measure-noise-floor"],
    ]
    for args in cases:
        res = _cli(args)
        assert res.exit_code == 2, (args, res.output)
