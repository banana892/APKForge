"""APK intake service — orchestrates detection, validation, workspace, and extraction."""

from __future__ import annotations

from pathlib import Path

from apkforge.core.config import APKForgeConfig, load_default_config
from apkforge.core.logging import get_logger
from apkforge.core.models import AnalysisStatus, APKInput
from apkforge.core.workspace import Workspace
from apkforge.intake import AndroidPackage
from apkforge.intake.detector import PackageDetector
from apkforge.intake.handlers import (
    APKSHandler,
    BasePackageHandler,
    SingleAPKHandler,
    SplitAPKHandler,
    XAPKHandler,
)

__all__ = ["APKIntakeService"]

_log = get_logger(__name__)


class APKIntakeService:
    """Service coordinating the APK intake pipeline.

    The intake service is format-agnostic: callers provide any path (APK, APKS,
    XAPK, or directory of splits) and receive a normalized :class:`AndroidPackage`.
    """

    def __init__(self, config: APKForgeConfig | None = None) -> None:
        self._config = config or load_default_config()
        self._handlers: list[BasePackageHandler] = [
            SingleAPKHandler(),
            APKSHandler(),
            XAPKHandler(),
            SplitAPKHandler(),
        ]

    def register_handler(self, handler: BasePackageHandler) -> None:
        """Register a custom package handler (prefixed to take precedence)."""
        self._handlers.insert(0, handler)

    def process(
        self,
        input_path: Path | str,
        *,
        keep_workspace: bool | None = None,
    ) -> AndroidPackage:
        """Run the full intake pipeline on *input_path*.

        Args:
            input_path: Path to the target APK, APKS, XAPK, or split directory.
            keep_workspace: Override workspace retention.  If None, uses
                configuration defaults (keep_on_failure / keep_on_success).

        Returns:
            AndroidPackage: Normalized package representation with all metadata,
                hashes, files, DEX files, and certificates.
        """
        path = Path(input_path).resolve()
        _log.info("Starting intake for: %s", path)

        # 1. Detection
        detection = PackageDetector.detect(path)
        _log.debug("Detection result: %s (valid=%s)", detection.format, detection.is_valid)

        if not detection.is_valid:
            return AndroidPackage(
                input_path=path,
                package_type=detection.package_type,
                input_format=detection.format,
                status=AnalysisStatus.FAILED,
                errors=[detection.reason or "Invalid package input"],
            )

        # 2. Select Handler
        handler: BasePackageHandler | None = None
        for h in self._handlers:
            if h.can_handle(detection):
                handler = h
                break

        if handler is None:
            return AndroidPackage(
                input_path=path,
                package_type=detection.package_type,
                input_format=detection.format,
                status=AnalysisStatus.FAILED,
                errors=[f"Unsupported input format: {detection.format}"],
            )

        # 3. Create isolated workspace
        base_dir = self._config.workspace.base_directory
        source_input = APKInput(path=path)
        workspace = Workspace.create(source_input, base_dir=base_dir)

        # 4. Process with handler inside workspace
        success = False
        package: AndroidPackage | None = None
        try:
            package = handler.process(
                input_path=path,
                workspace=workspace,
                limits=self._config.extraction,
            )
            success = package.status != AnalysisStatus.FAILED
        except Exception as exc:
            _log.exception("Unhandled error during intake processing: %s", exc)
            package = AndroidPackage(
                input_path=path,
                package_type=detection.package_type,
                input_format=detection.format,
                status=AnalysisStatus.FAILED,
                errors=[f"Intake pipeline failed unexpectedly: {exc}"],
            )
        finally:
            # Deterministic workspace lifecycle cleanup (also on BaseException)
            should_keep = (
                keep_workspace
                if keep_workspace is not None
                else (
                    self._config.workspace.keep_on_success
                    if success
                    else self._config.workspace.keep_on_failure
                )
            )
            if not should_keep or package is None:
                workspace.cleanup(success=success)
            else:
                # Hand ownership of the retained workspace to the caller.
                package.workspace_root = workspace.root
                _log.info("Retaining workspace at: %s", workspace.root)
        return package
