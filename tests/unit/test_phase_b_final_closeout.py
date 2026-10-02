"""Phase B final close-out regression tests.

1. Certificate fallback status: a recoverable Androguard failure that the
   PKCS#7 fallback fully recovers from must not degrade intake or anything
   downstream of it.
2. Nested archive safety: nested APKs inspected in memory must obey the same
   ExtractionLimits as top-level intake, without changing PRC-05 detection of
   legitimate nested APKs.
"""

from __future__ import annotations

import io
import zipfile
from typing import TYPE_CHECKING

import pytest

from apkforge.core.config import ExtractionLimits
from apkforge.core.models import AnalysisStatus
from apkforge.inspection.embedded import EmbeddedFileInspector
from apkforge.inspection.engine import InspectionEngine
from apkforge.inspection.models import InspectionResult, ManifestInspection
from apkforge.intake import APKIntakeService
from apkforge.intake import certificates as certs_mod
from apkforge.privacy.engine import PrivacyEngine
from apkforge.security.engine import SecurityEngine
from tests.fixtures.factory import create_synthetic_apk

if TYPE_CHECKING:
    from pathlib import Path

# The exact message observed in the post-PRC corpus run.
SHA1_BACKEND_FAILURE = (
    "Androguard certificate extraction failed: "
    "sha1 is not supported by this backend for RSA signing."
)


def _androguard_fails(_apk_path: Path) -> tuple[list, list[str]]:
    return [], [SHA1_BACKEND_FAILURE]


def _androguard_yields_nothing(_apk_path: Path) -> tuple[list, list[str]]:
    return [], []


# ---------------------------------------------------------------------------
# 1. Certificate fallback status propagation
# ---------------------------------------------------------------------------


class TestCertificateFallbackStatus:
    def test_recovered_failure_keeps_intake_complete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        apk = create_synthetic_apk(tmp_path / "signed.apk")
        monkeypatch.setattr(certs_mod, "_extract_via_androguard", _androguard_fails)

        pkg = APKIntakeService().process(apk)

        assert pkg.status == AnalysisStatus.COMPLETE
        assert pkg.warnings == []
        assert pkg.errors == []

    def test_recovered_failure_retains_certificate_and_records_note(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        apk = create_synthetic_apk(tmp_path / "signed.apk")
        monkeypatch.setattr(certs_mod, "_extract_via_androguard", _androguard_fails)

        pkg = APKIntakeService().process(apk)

        assert len(pkg.certificates) == 1
        cert = pkg.certificates[0]
        # Full certificate identity is retained.
        assert cert.subject == "O=APKForge,CN=APKForge Test"
        assert cert.issuer == cert.subject
        assert cert.serial_number == format(123456789, "x")
        assert cert.not_before is not None and cert.not_after is not None
        assert cert.sha256_fingerprint and len(cert.sha256_fingerprint) == 64
        assert cert.sha1_fingerprint and len(cert.sha1_fingerprint) == 40
        # The fallback is explicit and the backend failure is informational.
        assert cert.extraction_backend == "pkcs7_fallback"
        assert len(cert.extraction_notes) == 1
        assert SHA1_BACKEND_FAILURE in cert.extraction_notes[0]
        assert "recovered by the PKCS#7 fallback" in cert.extraction_notes[0]

    def test_no_downstream_degradation_from_recovered_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Inspection, privacy and security are identical with and without the failure."""
        apk = create_synthetic_apk(tmp_path / "signed.apk")

        def run() -> tuple:
            insp = InspectionEngine().inspect(apk)
            priv = PrivacyEngine().analyze(insp, keep_workspace=False)
            sec = SecurityEngine().analyze(target=insp, privacy=priv, apk_path=apk)
            return (
                insp.package.status,
                insp.package.warnings,
                insp.status,
                insp.warnings,
                priv.status,
                priv.warnings,
                sec.status,
                sorted(f.id for f in sec.findings),
            )

        monkeypatch.setattr(certs_mod, "_extract_via_androguard", _androguard_yields_nothing)
        baseline = run()
        monkeypatch.setattr(certs_mod, "_extract_via_androguard", _androguard_fails)
        recovered = run()

        assert recovered == baseline
        assert recovered[0] == AnalysisStatus.COMPLETE
        assert not any(SHA1_BACKEND_FAILURE in w for w in recovered[3])

    def test_unrecovered_failure_still_warns(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No fallback certificate: the backend failure stays a warning (unchanged)."""
        apk = create_synthetic_apk(tmp_path / "unsigned.apk", include_cert=False)
        monkeypatch.setattr(certs_mod, "_extract_via_androguard", _androguard_fails)

        pkg = APKIntakeService().process(apk)

        assert pkg.status == AnalysisStatus.PARTIAL
        assert SHA1_BACKEND_FAILURE in pkg.warnings
        assert "No signing certificates could be extracted." in pkg.warnings
        assert pkg.certificates == []

    def test_incomplete_fallback_still_warns(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A fallback record missing identity fields is not a full recovery."""
        apk = create_synthetic_apk(tmp_path / "signed.apk")
        monkeypatch.setattr(certs_mod, "_extract_via_androguard", _androguard_fails)
        real_fallback = certs_mod.extract_certificates_from_zip

        def incomplete(path: Path) -> tuple[list, list[str]]:
            found, warns = real_fallback(path)
            return [c.model_copy(update={"subject": None}) for c in found], warns

        monkeypatch.setattr(certs_mod, "extract_certificates_from_zip", incomplete)

        found, warns = certs_mod.extract_certificates(apk)

        assert len(found) == 1
        assert warns == [SHA1_BACKEND_FAILURE]
        assert found[0].extraction_notes == []

    def test_androguard_success_path_is_labelled(self, tmp_path: Path) -> None:
        """Fallback-only APKs (no androguard result) are labelled and carry no notes."""
        apk = create_synthetic_apk(tmp_path / "signed.apk")

        found, warns = certs_mod.extract_certificates(apk)

        assert warns == []
        assert [c.extraction_backend for c in found] == ["pkcs7_fallback"]
        assert found[0].extraction_notes == []


# ---------------------------------------------------------------------------
# 2. Nested archive safety
# ---------------------------------------------------------------------------


def _zip_bytes(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _outer_apk(tmp_path: Path, nested_name: str, nested: bytes) -> Path:
    outer = tmp_path / "outer.apk"
    with zipfile.ZipFile(outer, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest package='com.example.app'/>")
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 32)
        zf.writestr(nested_name, nested)
    return outer


def _payload_findings(inspection: object) -> list:
    result = SecurityEngine().analyze(
        InspectionResult(
            manifest=ManifestInspection(package_name="com.example.app"),
            embedded=inspection,
        )
    )
    return [f for f in result.findings if "SEC-MAL-PAYLOAD-APK" in f.id]


CODE_FREE = {"AndroidManifest.xml": b"<manifest/>", "resources.arsc": b"\x02\x00\x0c\x00"}


class TestNestedArchiveSafety:
    def test_entry_count_over_limit_is_rejected_and_bounded(self, tmp_path: Path) -> None:
        limits = ExtractionLimits(max_file_count=20)
        # Code-free by content, but 25 entries > 20: must not be trusted as code-free.
        hostile = _zip_bytes({**CODE_FREE, **{f"res/raw/f{i}.bin": b"x" for i in range(23)}})
        outer = _outer_apk(tmp_path, "frameworks/android/android-23.apk", hostile)

        inspection, warnings = EmbeddedFileInspector(limits=limits).inspect(outer)

        assert len(inspection.embedded_apks) == 1
        assert inspection.embedded_apks[0].has_code is True
        assert any(
            "rejected by extraction limits" in w and "25 entries" in w and "limit of 20" in w
            for w in warnings
        )
        # PRC-05 suppression is not granted to an archive that could not be verified.
        assert len(_payload_findings(inspection)) == 1

    def test_path_traversal_entry_is_rejected(self, tmp_path: Path) -> None:
        hostile = _zip_bytes({**CODE_FREE, "../../../data/local/tmp/evil": b"x"})
        outer = _outer_apk(tmp_path, "assets/update.apk", hostile)

        inspection, warnings = EmbeddedFileInspector().inspect(outer)

        assert inspection.embedded_apks[0].has_code is True
        assert any(
            "rejected by extraction limits" in w and "Path traversal" in w for w in warnings
        )
        assert len(_payload_findings(inspection)) == 1

    @pytest.mark.parametrize("name", ["/system/bin/evil", "C:/evil"])
    def test_absolute_and_drive_paths_are_rejected(self, tmp_path: Path, name: str) -> None:
        outer = _outer_apk(tmp_path, "assets/update.apk", _zip_bytes({**CODE_FREE, name: b"x"}))

        inspection, warnings = EmbeddedFileInspector().inspect(outer)

        assert inspection.embedded_apks[0].has_code is True
        assert any("rejected by extraction limits" in w for w in warnings)

    def test_recursion_depth_limit_is_enforced(self, tmp_path: Path) -> None:
        outer = _outer_apk(tmp_path, "assets/framework.apk", _zip_bytes(CODE_FREE))

        inspection, warnings = EmbeddedFileInspector(
            limits=ExtractionLimits(max_recursion_depth=0)
        ).inspect(outer)

        assert inspection.embedded_apks[0].has_code is True
        assert any("depth 1 exceeds limit 0" in w for w in warnings)

    def test_unsafe_archive_found_by_content_sniffing_is_not_classified(
        self, tmp_path: Path
    ) -> None:
        """A ZIP without .apk/.jar extension is only sniffed after passing the limits."""
        hostile = _zip_bytes({"AndroidManifest.xml": b"<m/>", "../escape": b"x"})
        outer = _outer_apk(tmp_path, "assets/blob.bin", hostile)

        inspection, warnings = EmbeddedFileInspector().inspect(outer)

        assert inspection.embedded_apks == []
        assert any("assets/blob.bin" in w and "Path traversal" in w for w in warnings)

    def test_valid_code_free_nested_apk_unchanged(self, tmp_path: Path) -> None:
        """PRC-05: a legitimate code-free framework APK is still recognised as code-free."""
        outer = _outer_apk(tmp_path, "frameworks/android/android-23.apk", _zip_bytes(CODE_FREE))

        inspection, warnings = EmbeddedFileInspector().inspect(outer)

        assert warnings == []
        assert inspection.embedded_apks[0].has_code is False
        assert inspection.executable_files == []
        assert _payload_findings(inspection) == []

    def test_valid_nested_apk_with_code_still_detected(self, tmp_path: Path) -> None:
        nested = _zip_bytes({**CODE_FREE, "classes.dex": b"dex\n035\x00" + b"\x00" * 32})
        outer = _outer_apk(tmp_path, "assets/dropped_payload.apk", nested)

        inspection, warnings = EmbeddedFileInspector().inspect(outer)

        assert warnings == []
        assert inspection.embedded_apks[0].has_code is True
        assert [e.path for e in inspection.executable_files] == ["assets/dropped_payload.apk"]
        assert len(_payload_findings(inspection)) == 1

    def test_valid_nested_apk_at_exact_entry_limit_is_accepted(self, tmp_path: Path) -> None:
        nested = _zip_bytes({**CODE_FREE, **{f"res/raw/f{i}.bin": b"x" for i in range(18)}})
        outer = _outer_apk(tmp_path, "frameworks/android/android-24.apk", nested)

        inspection, warnings = EmbeddedFileInspector(
            limits=ExtractionLimits(max_file_count=20)
        ).inspect(outer)

        assert warnings == []
        assert inspection.embedded_apks[0].has_code is False

    def test_inspection_engine_passes_configured_limits(self) -> None:
        from apkforge.core.config import load_default_config

        config = load_default_config()
        engine = InspectionEngine(config=config)

        assert engine._embedded_inspector._limits is config.extraction
