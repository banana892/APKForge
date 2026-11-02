"""``apkforge scan``: the actionable security findings of many APKs, gated for CI.

Each APK gets the full security analysis (:class:`SecurityEngine`); the scan only filters
and judges it. A verdict is relative to a threshold, never a safety claim:

- ``pass``: analysis complete and no finding at or above the ``fail_on`` severity
- ``fail``: at least one finding at or above ``fail_on``
- ``incomplete``: no failing finding, but the analysis was PARTIAL, so the absence of
  findings proves nothing
- ``error``: the APK could not be analysed (the engine raised or reported FAILED)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, Field

from apkforge.core.models import AnalysisStatus, Severity

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable
    from pathlib import Path

    from apkforge.security.models import SecurityResult

__all__ = ["APK_SUFFIXES", "ScanFinding", "ScanRecord", "collect_apks", "exit_code",
           "judge", "scan_apk"]  # fmt: skip

Verdict = Literal["pass", "fail", "incomplete", "error"]
APK_SUFFIXES = (".apk", ".apks", ".xapk", ".apkm")
#: Most severe first.
RANK = {s: i for i, s in enumerate((Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                                    Severity.LOW, Severity.INFORMATIONAL))}  # fmt: skip


class ScanFinding(BaseModel):
    id: str
    title: str
    severity: Severity
    confidence: str
    category: str


class ScanRecord(BaseModel):
    path: str
    verdict: Verdict
    package_name: str | None = None
    version_name: str | None = None
    status: str | None = None
    worst_severity: Severity | None = None
    #: All findings by severity, including those below ``min_severity``.
    counts: dict[str, int] = Field(default_factory=dict)
    #: Findings at or above ``min_severity``, most severe first.
    findings: list[ScanFinding] = Field(default_factory=list)
    error: str | None = None


def at_least(severity: Severity, threshold: Severity) -> bool:
    return RANK[severity] <= RANK[threshold]


def collect_apks(paths: Iterable[Path]) -> list[Path]:
    """Files as given; directories searched recursively for APK containers. Sorted, unique."""
    found: set[Path] = set()
    for p in paths:
        if p.is_dir():
            found.update(f for f in p.rglob("*") if f.is_file()
                         and f.suffix.lower() in APK_SUFFIXES)  # fmt: skip
        else:
            found.add(p)
    return sorted(found)


def judge(
    path: Path, result: SecurityResult, *, min_severity: Severity, fail_on: Severity | None
) -> ScanRecord:
    findings = sorted(result.findings, key=lambda f: (RANK[f.severity], f.id))
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    worst = findings[0].severity if findings else None
    if fail_on is not None and worst is not None and at_least(worst, fail_on):
        verdict: Verdict = "fail"
    elif result.status == AnalysisStatus.FAILED:
        verdict = "error"
    elif result.status != AnalysisStatus.COMPLETE:
        verdict = "incomplete"
    else:
        verdict = "pass"
    shown = [f for f in findings if at_least(f.severity, min_severity)]
    return ScanRecord(
        path=str(path),
        verdict=verdict,
        package_name=result.package_name,
        version_name=result.version_name,
        status=result.status.value,
        worst_severity=worst,
        counts=counts,
        findings=[
            ScanFinding(
                id=f.id,
                title=f.title,
                severity=f.severity,
                confidence=str(f.confidence),
                category=str(f.category),
            )
            for f in shown
        ],
        error="; ".join(result.errors) or None,
    )


def scan_apk(
    path: Path,
    analyze: Callable[[Path], SecurityResult],
    *,
    min_severity: Severity,
    fail_on: Severity | None,
) -> ScanRecord:
    """Analyse one APK; any failure becomes an ``error`` record so a batch keeps going."""
    try:
        result = analyze(path)
    except Exception as exc:  # one bad APK must not stop the batch
        return ScanRecord(path=str(path), verdict="error", error=f"{type(exc).__name__}: {exc}")
    return judge(path, result, min_severity=min_severity, fail_on=fail_on)


def exit_code(records: Iterable[ScanRecord]) -> int:
    """2 if any APK could not be (fully) analysed, else 1 if any failed, else 0.

    An unscannable APK outranks a failure: CI must not read "only one finding" into a
    batch it could not check.
    """
    verdicts = {r.verdict for r in records}
    if verdicts & {"error", "incomplete"}:
        return 2
    return 1 if "fail" in verdicts else 0
