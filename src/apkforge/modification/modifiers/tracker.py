"""Phase 7 TrackerModifier — removes third-party tracker and ad SDK components.

Handles:
    - REMOVE_TRACKER
    - REMOVE_AD_COMPONENT

This modifier coordinates multi-layer removal:
1. Remove tracker-related ContentProvider / Service / Receiver from the manifest.
2. Remove tracker package directories from the decoded smali/dex workspace.
3. Remove tracker-associated resource files (e.g. XML configs, layouts).

Security invariant: operates only on the working copy inside the workspace.
"""

from __future__ import annotations

import logging
import re
import shutil
from typing import TYPE_CHECKING, ClassVar

from apkforge.modification.modifiers.base import (
    ModificationExecutionContext,
    ModificationStepResult,
    StepStatus,
)

if TYPE_CHECKING:
    from pathlib import Path

    from apkforge.modification.models import PlannedChange

_log = logging.getLogger(__name__)


class TrackerModifier:
    """Modifier that removes third-party tracker/ad SDK components."""

    modifier_id: str = "TrackerModifier"
    name: str = "Tracker & Ad SDK Remover"
    description: str = (
        "Removes third-party tracking, advertising, and analytics SDK classes, "
        "manifest components, and associated resources from the workspace."
    )
    supported_change_types: ClassVar[list[str]] = [
        "remove_tracker",
        "remove_ad_component",
    ]

    # Well-known tracker packages to identify in decoded smali directories
    KNOWN_TRACKER_PACKAGES: ClassVar[dict[str, list[str]]] = {
        "Google AdMob": ["com/google/android/gms/ads", "com/google/ads"],
        "Facebook Ads": ["com/facebook/ads"],
        "Google Firebase Analytics": [
            "com/google/firebase/analytics",
            "com/google/android/gms/measurement",
        ],
        "Google Analytics": ["com/google/android/gms/analytics"],
        "Adjust": ["com/adjust/sdk"],
        "AppsFlyer": ["com/appsflyer"],
        "Crashlytics": ["com/google/firebase/crashlytics", "com/crashlytics"],
        "Facebook SDK": ["com/facebook/appevents", "com/facebook/FacebookSdk"],
        "Unity Ads": ["com/unity3d/ads"],
        "ironSource": ["com/ironsource"],
        "AppLovin": ["com/applovin"],
        "Flurry": ["com/flurry"],
        "MoPub": ["com/mopub"],
        "InMobi": ["com/inmobi"],
        "Chartboost": ["com/chartboost"],
    }

    def preflight(
        self,
        change: PlannedChange,
        context: ModificationExecutionContext,
    ) -> ModificationStepResult:
        """Validate that tracker removal prerequisites are met."""
        result = ModificationStepResult(
            change_id=change.id,
            modifier_id=self.modifier_id,
        )

        if not context.workspace_dir.exists():
            result.status = StepStatus.FAILED
            result.message = "Workspace directory does not exist."
            return result

        result.status = StepStatus.SUCCESS
        result.message = (
            f"Preflight passed for tracker removal: '{change.target}'. "
            f"Workspace is ready."
        )
        return result

    def apply(
        self,
        change: PlannedChange,
        context: ModificationExecutionContext,
    ) -> ModificationStepResult:
        """Remove tracker SDK components from the workspace."""
        result = ModificationStepResult(
            change_id=change.id,
            modifier_id=self.modifier_id,
        )

        tracker_name = change.target
        removed_items: list[str] = []

        # 1. Remove smali directories matching known packages
        smali_dirs = self._find_smali_directories(context.workspace_dir)
        packages = self.KNOWN_TRACKER_PACKAGES.get(tracker_name, [])

        # Also try to derive packages from evidence
        for ev in change.evidence:
            if (ev.snippet and "/" in ev.snippet) or (ev.snippet and "." in ev.snippet):
                packages.append(ev.snippet.replace(".", "/"))

        if context.dry_run:
            result.status = StepStatus.DRY_RUN
            result.message = (
                f"[DRY RUN] Would remove tracker '{tracker_name}' "
                f"({len(packages)} package patterns, "
                f"{len(smali_dirs)} smali directories to scan)."
            )
            return result

        for smali_dir in smali_dirs:
            for pkg_path in packages:
                target_dir = smali_dir / pkg_path
                if target_dir.exists() and target_dir.is_dir():
                    shutil.rmtree(target_dir)
                    removed_items.append(f"smali:{target_dir.relative_to(context.workspace_dir)}")
                    _log.info("Removed tracker smali directory: %s", target_dir)

        # 2. Remove manifest components for this tracker
        manifest_removals = self._remove_tracker_from_manifest(
            context.workspace_dir, tracker_name, packages
        )
        removed_items.extend(manifest_removals)

        # 3. Remove tracker-specific resource files
        resource_removals = self._remove_tracker_resources(
            context.workspace_dir, tracker_name, packages
        )
        removed_items.extend(resource_removals)

        if removed_items:
            result.status = StepStatus.SUCCESS
            result.message = (
                f"Removed tracker '{tracker_name}': "
                f"{len(removed_items)} items removed."
            )
            result.files_deleted = removed_items
        else:
            result.status = StepStatus.SKIPPED
            result.message = (
                f"No files found for tracker '{tracker_name}' in workspace. "
                f"The APK may not have been decoded, or packages differ."
            )

        return result

    def rollback(
        self,
        change: PlannedChange,
        context: ModificationExecutionContext,
        step_result: ModificationStepResult,
    ) -> ModificationStepResult:
        """Tracker removal rollback requires re-extraction from original APK."""
        result = ModificationStepResult(
            change_id=change.id,
            modifier_id=self.modifier_id,
        )
        result.status = StepStatus.FAILED
        result.message = (
            "Tracker removal rollback requires re-extraction of classes and "
            "resources from the original APK backup."
        )
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_smali_directories(workspace_dir: Path) -> list[Path]:
        """Find all smali/ and smali_classesN/ directories in the workspace."""
        smali_dirs: list[Path] = []
        for child in workspace_dir.iterdir():
            if child.is_dir() and (child.name == "smali" or child.name.startswith("smali_")):
                smali_dirs.append(child)
        return sorted(smali_dirs)

    @staticmethod
    def _remove_tracker_from_manifest(
        workspace_dir: Path,
        tracker_name: str,
        packages: list[str],
    ) -> list[str]:
        """Remove tracker-related components from decoded manifest XML."""
        manifest_path = workspace_dir / "AndroidManifest.xml"
        if not manifest_path.exists():
            return []

        removed: list[str] = []
        try:
            xml = manifest_path.read_text(encoding="utf-8")
            original = xml

            # Convert package paths to Java-style names for manifest matching
            java_packages = [p.replace("/", ".") for p in packages]

            for java_pkg in java_packages:
                # Remove provider, service, receiver elements containing this package
                for tag in ("provider", "service", "receiver", "activity"):
                    pattern = (
                        rf'<{tag}\s+[^>]*android:name\s*=\s*"'
                        rf'{re.escape(java_pkg)}[^"]*"[^>]*/?>'
                        rf'(?:\s*</{tag}>)?'
                    )
                    new_xml, count = re.subn(pattern, "", xml, flags=re.IGNORECASE | re.DOTALL)
                    if count > 0:
                        xml = new_xml
                        removed.append(f"manifest:{tag}:{java_pkg}")

            if xml != original:
                manifest_path.write_text(xml, encoding="utf-8")
        except OSError as exc:
            _log.warning("Could not process manifest for tracker removal: %s", exc)

        return removed

    @staticmethod
    def _remove_tracker_resources(
        workspace_dir: Path,
        tracker_name: str,
        packages: list[str],
    ) -> list[str]:
        """Remove tracker-related resource files (XML configs, layouts)."""
        removed: list[str] = []
        res_dir = workspace_dir / "res"
        if not res_dir.exists():
            return removed

        # Look for XML files that reference tracker packages
        tracker_keywords = [p.replace("/", ".").lower() for p in packages]
        tracker_keywords.append(tracker_name.lower().replace(" ", "_"))

        for xml_file in res_dir.rglob("*.xml"):
            try:
                content = xml_file.read_text(encoding="utf-8", errors="ignore").lower()
                for kw in tracker_keywords:
                    if kw in content and len(kw) > 5:
                        rel = str(xml_file.relative_to(workspace_dir))
                        xml_file.unlink()
                        removed.append(f"resource:{rel}")
                        _log.debug("Removed tracker resource: %s", rel)
                        break
            except OSError:
                continue

        return removed
