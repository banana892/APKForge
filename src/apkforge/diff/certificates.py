"""Certificate differ — compares signing certificates and fingerprints."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from apkforge.diff.models import CertificateDiff, ChangeType, DiffChange

if TYPE_CHECKING:
    from apkforge.inspection.models import InspectionResult
    from apkforge.intake import SigningCertificate

__all__ = ["CertificateDiffer"]


class CertificateDiffer:
    """Compares X.509 signing certificates and signature fingerprints."""

    def diff(self, insp_a: InspectionResult, insp_b: InspectionResult) -> CertificateDiff:
        """Execute certificate comparison between Inspection A and Inspection B."""
        certs_a: list[SigningCertificate] = insp_a.package.certificates if insp_a.package else []
        certs_b: list[SigningCertificate] = insp_b.package.certificates if insp_b.package else []

        serialized_a = [self._cert_to_dict(c) for c in certs_a]
        serialized_b = [self._cert_to_dict(c) for c in certs_b]

        fps_a = {c.sha256_fingerprint for c in certs_a if c.sha256_fingerprint}
        fps_b = {c.sha256_fingerprint for c in certs_b if c.sha256_fingerprint}

        status = "UNCHANGED"
        if not fps_a and not fps_b:
            status = "UNCHANGED"
        elif not fps_a and fps_b:
            status = "ADDED"
        elif fps_a and not fps_b:
            status = "REMOVED"
        elif fps_a == fps_b:
            status = "SAME"
        else:
            status = "CHANGED"

        fp_changes: list[DiffChange] = []
        # Added cert fingerprints
        for fp in sorted(fps_b - fps_a):
            fp_changes.append(
                DiffChange(
                    change_type=ChangeType.ADDED,
                    category="certificate.fingerprint",
                    identifier="sha256_fingerprint",
                    before=None,
                    after=fp,
                )
            )
        # Removed cert fingerprints
        for fp in sorted(fps_a - fps_b):
            fp_changes.append(
                DiffChange(
                    change_type=ChangeType.REMOVED,
                    category="certificate.fingerprint",
                    identifier="sha256_fingerprint",
                    before=fp,
                    after=None,
                )
            )

        return CertificateDiff(
            status=status,
            count_before=len(certs_a),
            count_after=len(certs_b),
            certificates_before=serialized_a,
            certificates_after=serialized_b,
            fingerprint_changes=fp_changes,
        )

    @staticmethod
    def _cert_to_dict(cert: SigningCertificate) -> dict[str, Any]:
        """Convert certificate to a clean dictionary representation."""
        return {
            "subject": cert.subject,
            "issuer": cert.issuer,
            "serial_number": cert.serial_number,
            "sha256_fingerprint": cert.sha256_fingerprint,
            "sha1_fingerprint": cert.sha1_fingerprint,
            "signature_version": cert.signature_version,
        }
