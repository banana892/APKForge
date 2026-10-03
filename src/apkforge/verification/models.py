"""Verification result models (Phase E6).

A verification is a *matrix* of independent checks, never one boolean. Each check has
its own status and evidence; the overall status is derived conservatively:

- ``FAILED`` if any check failed
- ``UNDETERMINED`` if no check failed but any check could not be completed
  (``undetermined`` / ``partial``) — "not verified" is preferred to "verified"
- ``VERIFIED`` only if every applicable check passed

What verification proves: the APK is structurally valid, its signature verifies, the
requested changes were observed and nothing else changed beyond the measured rebuild
noise, *within what the comparators can see*. It does not prove the APK is safe or
free of malware.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

__all__ = [
    "MATRIX_CHECKS",
    "VERIFICATION_SCHEMA_VERSION",
    "CheckStatus",
    "OverallStatus",
    "VerificationCheck",
    "VerificationMatrix",
]

VERIFICATION_SCHEMA_VERSION = 1


class CheckStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    PARTIAL = "partial"  # some of the check could be performed, not all
    UNDETERMINED = "undetermined"  # the check could not be performed
    NOT_APPLICABLE = "not_applicable"


class OverallStatus(StrEnum):
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    UNDETERMINED = "UNDETERMINED"


class VerificationCheck(BaseModel):
    name: str
    status: CheckStatus
    summary: str = ""
    evidence: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)


#: check name -> question it answers (also the matrix row order)
MATRIX_CHECKS: dict[str, str] = {
    "structural": "Is the APK a readable, well-formed archive with a decodable manifest?",
    "signature": "Does the APK signature verify (apksigner), with the expected signer?",
    "noise_baseline": "Is a compatible, content-aware no-op baseline available?",
    "modification": "Did every requested modifier execute and pass its own verification?",
    "expected_changes": "Was every declared expected change observed?",
    "unexpected_changes": "Is every observed difference expected, planned or baseline noise?",
    "semantic_diff": "Could every semantic comparator complete?",
    "security_diff": "Could every security-relevant category be compared?",
}


class VerificationMatrix(BaseModel):
    schema_version: int = VERIFICATION_SCHEMA_VERSION
    checks: dict[str, VerificationCheck] = Field(default_factory=dict)
    overall: OverallStatus = OverallStatus.UNDETERMINED
    overall_reason: str = ""
    limitations: list[str] = Field(default_factory=list)
    statement: str = (
        "Verification establishes structural/signing validity and that observed "
        "differences match the plan and the measured rebuild noise, within the stated "
        "comparator coverage. It does not establish that the application is safe."
    )

    def status(self, name: str) -> CheckStatus | None:
        c = self.checks.get(name)
        return c.status if c else None

    def finalize(self) -> VerificationMatrix:
        failed = [n for n, c in self.checks.items() if c.status == CheckStatus.FAILED]
        open_ = [
            n
            for n, c in self.checks.items()
            if c.status in (CheckStatus.UNDETERMINED, CheckStatus.PARTIAL)
        ]
        if failed:
            self.overall = OverallStatus.FAILED
            self.overall_reason = "failed: " + ", ".join(failed)
        elif open_:
            self.overall = OverallStatus.UNDETERMINED
            self.overall_reason = "not established: " + ", ".join(open_)
        elif not self.checks:
            self.overall = OverallStatus.UNDETERMINED
            self.overall_reason = "no checks were performed"
        else:
            self.overall = OverallStatus.VERIFIED
            self.overall_reason = "every applicable check passed"
        return self

    def table(self) -> list[dict[str, str]]:
        return [
            {"check": n, "status": str(c.status), "summary": c.summary}
            for n, c in self.checks.items()
        ]
