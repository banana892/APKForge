"""Assemble the verification matrix from independent evidence (Phase E6)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from apkforge.diff.expectations import ObservationClass
from apkforge.diff.models import ComparisonStatus
from apkforge.verification.models import (
    CheckStatus,
    VerificationCheck,
    VerificationMatrix,
)

if TYPE_CHECKING:
    from apkforge.builders.semantic_baseline import BaselineCheck
    from apkforge.diff.expectations import ExpectationVerdict, ExpectedChange
    from apkforge.diff.models import DiffResult
    from apkforge.diff.security import SecurityDiff

__all__ = ["baseline_check_row", "build_matrix", "semantic_check"]

#: comparator -> file observation category it covers when not semantically comparable
_CONTENT_COVERED = {"resource_table": "resource_table", "resources": "resource"}


def baseline_check_row(check: BaselineCheck | None) -> VerificationCheck:
    from apkforge.builders.semantic_baseline import BaselineStatus

    if check is None:
        return VerificationCheck(
            name="noise_baseline",
            status=CheckStatus.UNDETERMINED,
            summary="no no-op baseline: rebuild noise cannot be separated from changes",
        )
    status = {
        BaselineStatus.COMPATIBLE: CheckStatus.PASSED,
        BaselineStatus.TOOLCHAIN_UNKNOWN: CheckStatus.PASSED,
        BaselineStatus.LEGACY_PATH_RULES: CheckStatus.PARTIAL,
        BaselineStatus.PARTIAL: CheckStatus.PARTIAL,
    }.get(check.status, CheckStatus.UNDETERMINED)
    summary = {
        BaselineStatus.COMPATIBLE: "content-aware baseline for this APK and toolchain",
        BaselineStatus.TOOLCHAIN_UNKNOWN: (
            "content-aware baseline; build toolchain not declared, so only exact content "
            "identity is accepted as noise"
        ),
        BaselineStatus.LEGACY_PATH_RULES: (
            "legacy baseline: noise accepted by path rule, content not compared"
        ),
    }.get(check.status, f"{check.status}: " + "; ".join(check.reasons))
    return VerificationCheck(
        name="noise_baseline",
        status=status,
        summary=summary,
        evidence=[f"baseline status {check.status}", *check.reasons],
        details=check.model_dump(mode="json"),
    )


def semantic_check(
    diff: DiffResult | None, verdict: ExpectationVerdict | None
) -> VerificationCheck:
    """Could the semantic comparison establish what changed?

    A comparator that is not comparable by design (resources.arsc entries, res/ binary
    XML) does not block verification when every difference in its area is byte-
    identical to the no-op rebuild (content-assured noise): byte identity establishes
    more than a semantic comparison would.
    """
    if diff is None:
        return VerificationCheck(
            name="semantic_diff", status=CheckStatus.UNDETERMINED, summary="no diff available"
        )
    content_noise: dict[str, list[bool]] = {}
    if verdict is not None:
        for c in verdict.observations:
            o = c.observation
            if o.category == "file":
                cat = o.detail.get("file_category")
                ok = c.classification == ObservationClass.REBUILD_NOISE and c.assurance == "content"
                content_noise.setdefault(str(cat), []).append(ok)
    undetermined, partial, covered = [], [], []
    for name, res in diff.comparisons.items():
        if res.complete:
            continue
        if res.status == ComparisonStatus.NOT_COMPARABLE and name in _CONTENT_COVERED:
            states = content_noise.get(_CONTENT_COVERED[name], [])
            if states and all(states):
                covered.append(name)
                continue
        if res.status == ComparisonStatus.UNDETERMINED:
            undetermined.append(f"{name} ({res.reason})")
        else:
            partial.append(f"{name}: {res.status} ({res.reason})")
    evidence = [f"{k}: {v.status}" for k, v in diff.comparisons.items()]
    if covered:
        evidence.append(
            "established by byte identity with the no-op rebuild: " + ", ".join(covered)
        )
    if str(diff.status) != "complete":
        partial.append(f"diff status {diff.status}")
    if not diff.comparisons:
        undetermined.append("no comparator statuses recorded")
    if undetermined:
        status, summary = CheckStatus.UNDETERMINED, "undetermined: " + "; ".join(undetermined)
    elif partial:
        status, summary = CheckStatus.PARTIAL, "partial: " + "; ".join(partial)
    else:
        status, summary = CheckStatus.PASSED, "every comparator completed"
    return VerificationCheck(
        name="semantic_diff",
        status=status,
        summary=summary,
        evidence=evidence,
        details={"covered_by_content_identity": covered},
    )


def _expected_row(
    verdict: ExpectationVerdict | None, expected: list[ExpectedChange]
) -> VerificationCheck:
    if not expected:
        return VerificationCheck(
            name="expected_changes",
            status=CheckStatus.NOT_APPLICABLE,
            summary="no expected changes declared",
        )
    if verdict is None:
        return VerificationCheck(
            name="expected_changes",
            status=CheckStatus.UNDETERMINED,
            summary="the diff was not classified",
        )
    missing = verdict.expected_missing
    return VerificationCheck(
        name="expected_changes",
        status=CheckStatus.FAILED if missing else CheckStatus.PASSED,
        summary=(
            f"{len(missing)} requested change(s) not observed"
            if missing
            else f"all {len(expected)} expected change(s) observed"
        ),
        evidence=[
            f"observed: {e.category} {e.kind} {e.identifier}" for e in verdict.expected_observed
        ]
        + [f"NOT observed: {e.category} {e.kind} {e.identifier}" for e in missing],
    )


def _unexpected_row(verdict: ExpectationVerdict | None) -> VerificationCheck:
    if verdict is None:
        return VerificationCheck(
            name="unexpected_changes",
            status=CheckStatus.UNDETERMINED,
            summary="the diff was not classified",
        )
    unexpected = verdict.of(ObservationClass.UNEXPECTED)
    unknown = verdict.of(ObservationClass.UNKNOWN)
    path_rule = [
        c for c in verdict.of(ObservationClass.REBUILD_NOISE) if c.assurance == "path_rule"
    ]
    ev = [
        f"unexpected: {c.observation.category} {c.observation.kind} {c.observation.identifier}"
        f" — {c.reason}"
        for c in unexpected
    ] + [
        f"unknown: {c.observation.category} {c.observation.kind} {c.observation.identifier}"
        f" — {c.reason}"
        for c in unknown
    ]
    if unexpected:
        status = CheckStatus.FAILED
        summary = f"{len(unexpected)} unexpected change(s) detected"
    elif unknown:
        status = CheckStatus.UNDETERMINED
        summary = f"{len(unknown)} change(s) could not be classified"
    elif path_rule:
        status = CheckStatus.PARTIAL
        summary = (
            f"{len(path_rule)} difference(s) accepted as noise by path rule only "
            "(content not compared)"
        )
    else:
        status = CheckStatus.PASSED
        summary = "no unexpected or unclassified change"
    return VerificationCheck(
        name="unexpected_changes",
        status=status,
        summary=summary,
        evidence=ev[:200],
        details={"counts": verdict.counts, "mode": verdict.mode},
    )


def _security_row(security: SecurityDiff | None) -> VerificationCheck:
    if security is None:
        return VerificationCheck(
            name="security_diff", status=CheckStatus.UNDETERMINED, summary="not computed"
        )
    items = security.items()
    bad = [i for i in items if i.classification == str(ObservationClass.UNEXPECTED)]
    unknown = [i for i in items if i.classification == str(ObservationClass.UNKNOWN)]
    ev = [f"{i.category}: {i.change} {i.subject} [{i.classification}]" for i in items][:200]
    if bad:
        status = CheckStatus.FAILED
        summary = f"{len(bad)} unexpected security-relevant change(s)"
    elif unknown:
        status = CheckStatus.UNDETERMINED
        summary = f"{len(unknown)} security-relevant change(s) could not be classified"
    elif security.status != "complete":
        status = CheckStatus.PARTIAL
        summary = "not every category could be compared: " + ", ".join(
            security.incomplete_categories
        )
    else:
        status = CheckStatus.PASSED
        summary = f"{len(items)} security-relevant change(s), none unexpected"
    return VerificationCheck(
        name="security_diff",
        status=status,
        summary=summary,
        evidence=ev,
        details={"counts": security.counts()},
    )


def build_matrix(
    *,
    structural: VerificationCheck,
    signature: VerificationCheck,
    baseline: BaselineCheck | None,
    diff: DiffResult | None,
    verdict: ExpectationVerdict | None,
    security: SecurityDiff | None,
    expected: list[ExpectedChange],
    modification: VerificationCheck | None = None,
) -> VerificationMatrix:
    """Combine the evidence into a :class:`VerificationMatrix` (finalised)."""
    m = VerificationMatrix()
    m.checks["structural"] = structural
    m.checks["signature"] = signature
    m.checks["noise_baseline"] = baseline_check_row(baseline)
    m.checks["modification"] = modification or VerificationCheck(
        name="modification",
        status=CheckStatus.NOT_APPLICABLE,
        summary="no modifier was run (pair verification)",
    )
    m.checks["expected_changes"] = _expected_row(verdict, expected)
    m.checks["unexpected_changes"] = _unexpected_row(verdict)
    m.checks["semantic_diff"] = semantic_check(diff, verdict)
    m.checks["security_diff"] = _security_row(security)

    lim: list[str] = []
    if diff is not None:
        for res in diff.comparisons.values():
            lim.extend(f"{res.comparator}: {x}" for x in res.limitations)
            if not res.complete and res.reason:
                lim.append(f"{res.comparator}: {res.status}: {res.reason}")
    if baseline is not None and baseline.status != "COMPATIBLE":
        lim.extend(f"noise baseline: {r}" for r in baseline.reasons)
    lim.append(
        "signature files (META-INF/MANIFEST.MF, *.SF, *.RSA...) are accepted by path; their "
        "validity is established by apksigner, not by the diff"
    )
    m.limitations = list(dict.fromkeys(lim))
    return m.finalize()
