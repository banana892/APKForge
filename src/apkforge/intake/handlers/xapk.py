"""XAPK bundle package handler."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from apkforge.core.logging import get_logger
from apkforge.core.models import AnalysisStatus
from apkforge.intake import (
    AndroidPackage,
    APKMetadata,
    InputFormat,
    PackageIdentity,
    PackageType,
    SplitAPKInfo,
    SplitType,
)
from apkforge.intake.archive import SafeZipExtractor, validate_zip
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

__all__ = ["XAPKHandler"]

_log = get_logger(__name__)


class XAPKHandler(BasePackageHandler):
    """Handler for .xapk bundle archives."""

    @classmethod
    def can_handle(cls, detection: DetectionResult) -> bool:
        return detection.format == InputFormat.XAPK_BUNDLE

    def process(
        self,
        input_path: Path,
        workspace: Workspace,
        limits: ExtractionLimits,
    ) -> AndroidPackage:
        warnings: list[str] = []
        errors: list[str] = []
        extra_data: dict[str, object] = {}

        # 1. Validate original XAPK archive
        try:
            zip_warnings = validate_zip(input_path)
            warnings.extend(zip_warnings)
        except Exception as exc:
            errors.append(f"XAPK archive validation failed: {exc}")
            return AndroidPackage(
                input_path=input_path,
                package_type=PackageType.XAPK,
                input_format=InputFormat.XAPK_BUNDLE,
                status=AnalysisStatus.FAILED,
                errors=errors,
            )

        # 2. Hash original XAPK file bytes
        try:
            original_hashes = compute_file_hashes(input_path)
        except Exception as exc:
            errors.append(f"Original hash calculation failed: {exc}")
            original_hashes = None

        # 3. Read manifest.json if present
        extractor = SafeZipExtractor(input_path, limits)
        manifest_json_data: dict[str, object] = {}
        try:
            raw_manifest = extractor.read_entry("manifest.json")
            manifest_json_data = json.loads(raw_manifest.decode("utf-8", errors="replace"))
            extra_data["xapk_manifest"] = manifest_json_data
        except Exception as exc:
            _log.debug("No valid manifest.json in XAPK: %s", exc)

        # 4. Safely extract contained APK files into workspace
        extract_dir = workspace.subpath("extracted", "xapk")
        extract_dir.mkdir(parents=True, exist_ok=True)

        try:
            entries = extractor.list_entries()
            apk_entries = [e.filename for e in entries if e.filename.lower().endswith(".apk")]

            if not apk_entries:
                errors.append("XAPK bundle contains no .apk files.")
                return AndroidPackage(
                    input_path=input_path,
                    package_type=PackageType.XAPK,
                    input_format=InputFormat.XAPK_BUNDLE,
                    hashes=original_hashes,
                    status=AnalysisStatus.FAILED,
                    errors=errors,
                    warnings=warnings,
                )

            extracted_paths = extractor.extract_to(extract_dir, entry_names=apk_entries)
        except Exception as exc:
            errors.append(f"Safe extraction failed: {exc}")
            return AndroidPackage(
                input_path=input_path,
                package_type=PackageType.XAPK,
                input_format=InputFormat.XAPK_BUNDLE,
                hashes=original_hashes,
                status=AnalysisStatus.FAILED,
                errors=errors,
                warnings=warnings,
            )

        # 5. Identify contained APKs
        splits: list[SplitAPKInfo] = []
        base_apk_path: Path | None = None
        base_meta: APKMetadata | None = None
        base_certs = []
        base_files = []
        base_dex = []
        base_libs = []
        package_names: dict[str, Path] = {}

        for apk_file in extracted_paths:
            try:
                apk_hashes = compute_file_hashes(apk_file)
            except Exception as exc:
                warnings.append(f"Could not hash split {apk_file.name}: {exc}")
                continue

            split_type = classify_split_type(apk_file.name)
            meta, certs, files, dex_files, native_libs, insp_warnings = inspect_single_apk(apk_file)
            warnings.extend(insp_warnings)

            if meta.package_name:
                package_names[meta.package_name] = apk_file

            splits.append(
                SplitAPKInfo(
                    name=apk_file.name,
                    path=apk_file,
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
            )

            # Check if this matches the declared package_name in manifest.json or is base
            declared_pkg = manifest_json_data.get("package_name")
            if (
                split_type == SplitType.BASE
                or apk_file.name == f"{declared_pkg}.apk"
                or apk_file.name == "base.apk"
            ) and base_apk_path is None:
                base_apk_path = apk_file
                base_meta = meta
                base_certs = certs
                base_files = files
                base_dex = dex_files
                base_libs = native_libs

        # Fallback for base APK selection if not explicitly marked
        if base_apk_path is None and splits:
            for s in splits:
                if s.package_name:
                    base_apk_path = s.path
                    (
                        base_meta,
                        base_certs,
                        base_files,
                        base_dex,
                        base_libs,
                        _,
                    ) = inspect_single_apk(s.path)
                    s.split_type = SplitType.BASE
                    break
            if base_apk_path is None:
                s = splits[0]
                base_apk_path = s.path
                (
                    base_meta,
                    base_certs,
                    base_files,
                    base_dex,
                    base_libs,
                    _,
                ) = inspect_single_apk(s.path)
                s.split_type = SplitType.BASE

        # 6. Cross-check manifest.json against actual APK manifest
        if manifest_json_data and base_meta:
            declared_pkg = manifest_json_data.get("package_name")
            if declared_pkg and base_meta.package_name and declared_pkg != base_meta.package_name:
                warnings.append(
                    f"XAPK manifest package_name mismatch: manifest.json claims {declared_pkg!r} "
                    f"but APK contains {base_meta.package_name!r}"
                )
            declared_code = manifest_json_data.get("version_code")
            is_mismatch = (
                declared_code
                and base_meta.version_code
                and str(declared_code) != str(base_meta.version_code)
            )
            if is_mismatch:
                warnings.append(
                    f"XAPK manifest version_code mismatch: manifest.json claims {declared_code} "
                    f"but APK contains {base_meta.version_code}"
                )

        if len(package_names) > 1:
            warnings.append(
                f"Split package name mismatch across APKs: {list(package_names.keys())}"
            )

        identity = None
        if base_meta and base_meta.package_name:
            identity = PackageIdentity(
                package_name=base_meta.package_name,
                version_name=base_meta.version_name,
                version_code=base_meta.version_code,
            )
        else:
            warnings.append("Could not determine package identity from XAPK base split.")

        if errors:
            status = AnalysisStatus.FAILED
        elif warnings or identity is None:
            status = AnalysisStatus.PARTIAL
        else:
            status = AnalysisStatus.COMPLETE

        return AndroidPackage(
            input_path=input_path,
            package_type=PackageType.XAPK,
            input_format=InputFormat.XAPK_BUNDLE,
            hashes=original_hashes,
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
            extra=extra_data,
        )
