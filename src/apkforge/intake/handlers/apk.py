"""Single APK package handler."""

from __future__ import annotations

from typing import TYPE_CHECKING

from apkforge.core.logging import get_logger
from apkforge.core.models import AnalysisStatus
from apkforge.intake import (
    AndroidPackage,
    InputFormat,
    PackageIdentity,
    PackageType,
)
from apkforge.intake.archive import SafeZipExtractor, validate_zip
from apkforge.intake.handlers.base import BasePackageHandler, inspect_single_apk
from apkforge.intake.hashing import compute_file_hashes

if TYPE_CHECKING:
    from pathlib import Path

    from apkforge.core.config import ExtractionLimits
    from apkforge.core.workspace import Workspace
    from apkforge.intake.detector import DetectionResult

__all__ = ["SingleAPKHandler"]

_log = get_logger(__name__)


class SingleAPKHandler(BasePackageHandler):
    """Handler for standalone .apk packages."""

    @classmethod
    def can_handle(cls, detection: DetectionResult) -> bool:
        return detection.format == InputFormat.SINGLE_APK

    def process(
        self,
        input_path: Path,
        workspace: Workspace,
        limits: ExtractionLimits,
    ) -> AndroidPackage:
        warnings: list[str] = []
        errors: list[str] = []

        # 1. Safe zip validation on the original archive and enforce safety limits
        try:
            zip_warnings = validate_zip(input_path)
            warnings.extend(zip_warnings)
            extractor = SafeZipExtractor(input_path, limits)
            extractor.list_entries()
        except Exception as exc:
            errors.append(f"Archive validation failed: {exc}")
            return AndroidPackage(
                input_path=input_path,
                package_type=PackageType.APK,
                input_format=InputFormat.SINGLE_APK,
                status=AnalysisStatus.FAILED,
                errors=errors,
            )

        # 2. Hash computation of the original file bytes
        try:
            file_hashes = compute_file_hashes(input_path)
        except Exception as exc:
            errors.append(f"Hash calculation failed: {exc}")
            file_hashes = None

        # 3. Stage the APK into the isolated workspace
        staged_apk = workspace.subpath("input", input_path.name)
        try:
            self._stage_file(input_path, staged_apk)
        except Exception as exc:
            errors.append(f"Staging to workspace failed: {exc}")
            return AndroidPackage(
                input_path=input_path,
                package_type=PackageType.APK,
                input_format=InputFormat.SINGLE_APK,
                hashes=file_hashes,
                status=AnalysisStatus.FAILED,
                errors=errors,
                warnings=warnings,
            )

        # 4. Extract metadata, certificates, and inventory from the staged file
        metadata, certs, files, dex_files, native_libs, inspect_warnings = inspect_single_apk(
            staged_apk
        )
        warnings.extend(inspect_warnings)

        # 5. Build stable package identity
        identity = None
        if metadata.package_name:
            identity = PackageIdentity(
                package_name=metadata.package_name,
                version_name=metadata.version_name,
                version_code=metadata.version_code,
            )
        else:
            warnings.append("Could not determine package identity from manifest.")

        # 6. Status determination
        if errors:
            status = AnalysisStatus.FAILED
        elif warnings or not metadata.package_name:
            status = AnalysisStatus.PARTIAL
        else:
            status = AnalysisStatus.COMPLETE

        return AndroidPackage(
            input_path=input_path,
            package_type=PackageType.APK,
            input_format=InputFormat.SINGLE_APK,
            hashes=file_hashes,
            metadata=metadata,
            identity=identity,
            certificates=certs,
            files=files,
            dex_files=dex_files,
            native_libraries=native_libs,
            status=status,
            warnings=warnings,
            errors=errors,
        )
