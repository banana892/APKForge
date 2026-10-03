"""APKForge verification (Phase E6).

Verification is a matrix of independent checks — structural validity, signature
validity, noise baseline, modification, expected changes, unexpected changes, semantic
diff and security diff — with a conservative overall status (VERIFIED / FAILED /
UNDETERMINED). See :mod:`apkforge.verification.models`.

A verified APK is structurally valid, correctly signed and differs from its original
only as planned plus the measured rebuild noise, within the stated comparator coverage.
That is not a statement about application safety.
"""

from apkforge.verification.checks import (
    signature_check,
    signature_check_with_service,
    structural_check,
)
from apkforge.verification.matrix import build_matrix
from apkforge.verification.models import (
    CheckStatus,
    OverallStatus,
    VerificationCheck,
    VerificationMatrix,
)
from apkforge.verification.pair import check_baseline, classify, verify_pair
from apkforge.verification.report import VerificationReport, build_report, render_markdown

__all__ = [
    "CheckStatus",
    "OverallStatus",
    "VerificationCheck",
    "VerificationMatrix",
    "VerificationReport",
    "build_matrix",
    "build_report",
    "check_baseline",
    "classify",
    "render_markdown",
    "signature_check",
    "signature_check_with_service",
    "structural_check",
    "verify_pair",
]
