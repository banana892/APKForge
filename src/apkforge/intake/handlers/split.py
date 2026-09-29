"""Split APK directory handler."""

from __future__ import annotations

from typing import TYPE_CHECKING

from apkforge.core.logging import get_logger
from apkforge.core.models import AnalysisStatus
from apkforge.intake import (
    AndroidPackage,
    APKMetadata,
    DEXFile,
    InputFormat,
    NativeLibrary,
    PackageFile,
    PackageIdentity,
    PackageType,
    SigningCertificate,
    SplitAPKInfo,
    SplitType,
)
from apkforge.intake.handlers.base import (
    BasePackageHandler,
    classify_split_type,
    inspect_single_apk,
)
from apkforge.intake.hashing import compute_file_hashes

if TYPE_CHECKING:
    from pathlib import Path

    from apkforge.core.config import ExtractionLimits
    from apkforge.core.workspace import Workspace
    from apkforge.intake.detector import DetectionResult

__all__ = ["SplitAPKHandler"]

_log = get_logger(__name__)


class SplitAPKHandler(BasePackageHandler):
    """Handler for directories containing multiple split APK files."""

    @classmethod
    def can_handle(cls, detection: DetectionResult) -> bool:
        return detection.format == InputFormat.SPLIT_DIRECTORY

    def process(
        self,
        input_path: Path,
        workspace: Workspace,
        limits: ExtractionLimits,
    ) -> AndroidPackage:
        warnings: list[str] = []
        errors: list[str] = []

        # Find all .apk files in the input directory
        try:
            apk_files = sorted([p for p in input_path.glob("*.apk") if p.is_file()])
        except OSError as exc:
            errors.append(f"Failed scanning split directory {input_path}: {exc}")
            return AndroidPackage(
                input_path=input_path,
                package_type=PackageType.SPLIT,
                input_format=InputFormat.SPLIT_DIRECTORY,
                status=AnalysisStatus.FAILED,
                errors=errors,
            )

        if not apk_files:
            errors.append(f"No .apk files found in directory {input_path}")
            return AndroidPackage(
                input_path=input_path,
                package_type=PackageType.SPLIT,
                input_format=InputFormat.SPLIT_DIRECTORY,
                status=AnalysisStatus.FAILED,
                errors=errors,
            )

        splits: list[SplitAPKInfo] = []
        base_apk_path: Path | None = None
        base_meta: APKMetadata | None = None
        base_certs: list[SigningCertificate] = []
        base_files: list[PackageFile] = []
        base_dex: list[DEXFile] = []
        base_libs: list[NativeLibrary] = []
        package_names: dict[str, Path] = {}
        primary_hashes = None

        # Copy split APKs to workspace to guarantee original input immutability
        staged_dir = workspace.subpath("input", "splits")
        staged_dir.mkdir(parents=True, exist_ok=True)

        for original_apk in apk_files:
            staged_apk = staged_dir / original_apk.name
            try:
                self._stage_file(original_apk, staged_apk)
            except Exception as exc:
                warnings.append(f"Failed staging {original_apk.name}: {exc}")
                continue

            try:
                apk_hashes = compute_file_hashes(original_apk)
            except Exception as exc:
                warnings.append(f"Could not hash {original_apk.name}: {exc}")
                continue

            split_type = classify_split_type(original_apk.name)
            (
                meta,
                certs,
                files,
                dex_files,
                native_libs,
                insp_warnings,
            ) = inspect_single_apk(staged_apk)
            warnings.extend(insp_warnings)

            if meta.package_name:
                package_names[meta.package_name] = original_apk

            split_info = SplitAPKInfo(
                name=original_apk.name,
                path=original_apk,
                split_type=split_type,
                hashes=apk_hashes,
                package_name=meta.package_name,
                metadata={
                    "version_name": meta.version_name,
                    "version_code": meta.version_code,
                    "min_sdk": meta.min_sdk,
                    "target_sdk": meta.target_sdk,
                },
            )
            splits.append(split_info)

            # Detect primary base APK
            if split_type == SplitType.BASE and base_apk_path is None:
                base_apk_path = original_apk
                base_meta = meta
                base_certs = certs
                base_files = files
                base_dex = dex_files
                base_libs = native_libs
                primary_hashes = apk_hashes

        # Fallback if no explicit base APK named
        if base_apk_path is None and splits:
            for s in splits:
                if s.package_name:
                    base_apk_path = s.path
                    base_meta, base_certs, base_files, base_dex, base_libs, _ = inspect_single_apk(
                        staged_dir / s.name
                    )
                    primary_hashes = s.hashes
                    s.split_type = SplitType.BASE
                    break
            if base_apk_path is None:
                s = splits[0]
                base_apk_path = s.path
                base_meta, base_certs, base_files, base_dex, base_libs, _ = inspect_single_apk(
                    staged_dir / s.name
                )
                primary_hashes = s.hashes
                s.split_type = SplitType.BASE

        # Validate package identity across all splits
        if len(package_names) > 1:
            warnings.append(f"Package name mismatch across splits: {list(package_names.keys())}")

        identity = None
        if base_meta and base_meta.package_name:
            identity = PackageIdentity(
                package_name=base_meta.package_name,
                version_name=base_meta.version_name,
                version_code=base_meta.version_code,
            )
        else:
            warnings.append("Could not determine package identity from split base APK.")

        if errors:
            status = AnalysisStatus.FAILED
        elif warnings or identity is None:
            status = AnalysisStatus.PARTIAL
        else:
            status = AnalysisStatus.COMPLETE

        return AndroidPackage(
            input_path=input_path,
            package_type=PackageType.SPLIT,
            input_format=InputFormat.SPLIT_DIRECTORY,
            hashes=primary_hashes,
            metadata=base_meta or APKMetadata(),
            identity=identity,
            certificates=base_certs,
            files=base_files,
            dex_files=base_dex,
            native_libraries=base_libs,
            splits=splits,
            status=status,
            warnings=warnings,
            errors=errors,
        )
