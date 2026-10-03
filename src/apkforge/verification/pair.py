"""Classification against a baseline, and original-vs-modified verification (Phase E).

:func:`classify` is the single place that decides how a diff is normalised for a given
baseline state; the modification pipeline and ``apkforge verify`` both use it:

======================  ==============================================================
baseline status         classification
======================  ==============================================================
COMPATIBLE              content fingerprint; content mismatch -> UNEXPECTED
BASELINE_PARTIAL        as COMPATIBLE (the matrix reports the baseline as partial)
TOOLCHAIN_UNKNOWN       content fingerprint; content mismatch -> UNKNOWN
LEGACY_PATH_RULES       Phase C.5 path rules (content not compared)
anything else           no noise accepted: rule-shaped differences -> UNKNOWN,
                        everything else -> UNEXPECTED
======================  ==============================================================
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from apkforge.builders.semantic_baseline import BaselineCheck, BaselineStatus
from apkforge.diff.expectations import ObservationClass, verify_expectations
from apkforge.diff.normalization import NoiseFingerprint
from apkforge.diff.security import build_security_diff
from apkforge.verification.checks import signature_check_with_service, structural_check
from apkforge.verification.matrix import build_matrix
from apkforge.verification.report import VerificationReport, build_report

if TYPE_CHECKING:
    from apkforge.builders.semantic_baseline import NoopSemanticBaseline
    from apkforge.diff.engine import DiffEngine
    from apkforge.diff.expectations import ExpectationVerdict, ExpectedChange
    from apkforge.diff.models import DiffResult
    from apkforge.diff.normalization import ToolchainIdentity

__all__ = ["check_baseline", "classify", "verify_pair"]


def check_baseline(
    baseline: NoopSemanticBaseline | None, sha256: str, toolchain: ToolchainIdentity | None
) -> BaselineCheck:
    if baseline is None:
        return BaselineCheck(
            status=BaselineStatus.MISSING,
            usable=False,
            reasons=["no semantic no-op baseline was given"],
            current_toolchain=toolchain,
        )
    return baseline.check(sha256, toolchain)


def classify(
    diff: DiffResult,
    expected: list[ExpectedChange],
    baseline: NoopSemanticBaseline | None,
    check: BaselineCheck,
    *,
    planned_entries: set[str] | None = None,
    expected_signer: str | None = None,
    sha256: str | None = None,
) -> ExpectationVerdict:
    """Classify *diff* according to the baseline state (see the module table).

    *sha256* identifies the original APK's baseline entry (default: the diff's side A).
    """
    sha256 = sha256 or diff.apk_a.sha256 or ""
    entry = baseline.entry_for(sha256) if baseline is not None else None
    if check.usable and check.content_aware and entry is not None and entry.fingerprint:
        return verify_expectations(
            diff,
            expected,
            fingerprint=entry.fingerprint,
            planned_entries=planned_entries,
            expected_signer=expected_signer,
            content_mismatch=(
                ObservationClass.UNEXPECTED
                if check.status in (BaselineStatus.COMPATIBLE, BaselineStatus.PARTIAL)
                else ObservationClass.UNKNOWN
            ),
        )
    if check.usable and baseline is not None:
        allowances = baseline.allowances(sha256)
        if allowances is not None:
            rules, residue = allowances
            return verify_expectations(
                diff, expected, allowed_noise_rules=rules, allowed_residue=residue
            )
    # No usable noise floor: nothing is accepted as noise.
    verdict = verify_expectations(
        diff,
        expected,
        fingerprint=NoiseFingerprint(),
        planned_entries=planned_entries,
        expected_signer=expected_signer,
        content_mismatch=ObservationClass.UNKNOWN,
    )
    verdict.failures.append(f"noise floor not established: {check.status}")
    verdict.passed = False
    return verdict


def verify_pair(
    original: Path,
    modified: Path,
    *,
    baseline: NoopSemanticBaseline | None = None,
    expected: list[ExpectedChange] | None = None,
    service: Any = None,  # noqa: ANN401 - BuildService (optional: signature check)
    expected_signer: str | None = None,
    build_toolchain: ToolchainIdentity | None = None,
    diff_engine: DiffEngine | None = None,
) -> tuple[VerificationReport, DiffResult | None]:
    """Verify *modified* against *original*: structure, signature, diff, matrix.

    *build_toolchain* is the toolchain that built *modified*, if known; when ``None``
    a content-aware baseline is applied with ``TOOLCHAIN_UNKNOWN`` semantics.
    """
    from apkforge.diff.engine import DiffEngine

    expected = list(expected or [])
    original, modified = Path(original), Path(modified)
    structural = structural_check(modified)
    original_ok = structural_check(original)
    if original_ok.status == "failed":
        structural.evidence.append(f"original APK: {original_ok.summary}")
    signature = signature_check_with_service(service, modified, expected_signer)

    diff: DiffResult | None = None
    verdict: ExpectationVerdict | None = None
    check: BaselineCheck | None = None
    security = None
    if structural.status == "passed" and original_ok.status == "passed":
        diff = (diff_engine or DiffEngine()).diff(original, modified)
        check = check_baseline(baseline, diff.apk_a.sha256 or "", build_toolchain)
        verdict = classify(diff, expected, baseline, check, expected_signer=expected_signer)
        security = build_security_diff(diff, verdict)
    matrix = build_matrix(
        structural=structural,
        signature=signature,
        baseline=check,
        diff=diff,
        verdict=verdict,
        security=security,
        expected=expected,
    )
    report = build_report(
        diff=diff,
        verdict=verdict,
        security=security,
        matrix=matrix,
        baseline=check,
        toolchain=build_toolchain,
        expected=expected,
        original=original,
        modified=modified,
    )
    return report, diff
