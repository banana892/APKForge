"""Impact analysis engine for proposed modifications."""

from __future__ import annotations

from typing import TYPE_CHECKING

from apkforge.modification.models import ChangeType, ImpactAssessment, ModificationRisk

if TYPE_CHECKING:
    from apkforge.modification.rules import ModificationContext


class ImpactAnalyzer:
    """Evaluates the direct, functional, and side effects of proposed modifications."""

    @staticmethod
    def assess_impact(
        change_type: ChangeType,
        target: str,
        context: ModificationContext | None = None,
    ) -> ImpactAssessment:
        """Compute structured impact analysis for a planned change."""
        direct: list[str] = []
        functional: list[str] = []
        side_effects: list[str] = []
        manifest_changes: list[str] = []
        dex_changes: list[str] = []
        file_changes: list[str] = []
        res_changes: list[str] = []
        native_changes: list[str] = []

        if change_type == ChangeType.REMOVE_PERMISSION:
            direct.append(f"Permission <uses-permission name='{target}'> omitted from manifest.")
            functional.append(
                f"Features invoking Android APIs protected by '{target}' will fail with "
                f"SecurityException if called at runtime."
            )
            side_effects.append(
                "Runtime permission request dialogs for this permission will not be displayed."
            )
            manifest_changes.append(f"Remove <uses-permission android:name='{target}' />")
            file_changes.append("AndroidManifest.xml")

        elif change_type == ChangeType.DISABLE_COMPONENT:
            direct.append(f"Component '{target}' disabled via android:enabled='false'.")
            functional.append(
                f"Intents and background tasks targeting '{target}' will not be delivered or "
                f"instantiated."
            )
            side_effects.append(
                "Calling components expecting a response or binder from this component may timeout."
            )
            manifest_changes.append(f"Update component '{target}' with android:enabled='false'")
            file_changes.append("AndroidManifest.xml")

        elif change_type == ChangeType.REMOVE_COMPONENT:
            direct.append(f"Component '{target}' declaration completely removed from manifest.")
            functional.append(
                f"System package manager will no longer register '{target}' as a valid endpoint."
            )
            side_effects.append(
                "Explicit Intents sent to this component from internal activities will raise "
                "ActivityNotFoundException or ComponentNotFoundException."
            )
            manifest_changes.append(f"Delete component tag for '{target}'")
            file_changes.append("AndroidManifest.xml")

        elif change_type == ChangeType.MODIFY_COMPONENT:
            direct.append(f"Component '{target}' exported attribute updated to 'false'.")
            functional.append(
                f"External third-party applications will no longer be able to launch '{target}'."
            )
            side_effects.append(
                "System broadcasts or widgets requiring exported access will be rejected."
            )
            manifest_changes.append(f"Set android:exported='false' on '{target}'")
            file_changes.append("AndroidManifest.xml")

        elif change_type == ChangeType.REMOVE_TRACKER:
            direct.append(
                f"Tracking/advertising SDK '{target}' classes, components, and hooks removed."
            )
            functional.append(
                f"User telemetry, event tracking, and ad displays associated with '{target}' cease."
            )
            side_effects.append(
                "Application code calling SDK methods may throw NoClassDefFoundError unless "
                "SDK calls are stubbed or stripped."
            )
            dex_changes.append(f"Strip or stub bytecode packages for '{target}'")
            manifest_changes.append(f"Remove initialization providers and metadata for '{target}'")
            file_changes.extend(["AndroidManifest.xml", "classes.dex"])

        elif change_type == ChangeType.REMOVE_EMBEDDED_PAYLOAD:
            direct.append(f"Embedded binary payload '{target}' deleted from archive.")
            functional.append(
                f"Runtime mechanisms attempting to load or execute '{target}' will fail."
            )
            side_effects.append(
                "If the payload contained legitimate secondary modules, associated features fail."
            )
            file_changes.append(target)

        elif change_type == ChangeType.MODIFY_CONFIGURATION:
            direct.append(f"Application configuration attribute '{target}' modified.")
            if "debuggable" in target.lower():
                functional.append("JDWP debugger attachment and heap inspection will be disabled.")
                side_effects.append("Development debugging tools will no longer connect via ADB.")
                manifest_changes.append("Set android:debuggable='false' on <application>")
            elif "cleartext" in target.lower():
                functional.append("All network connections will be restricted to encrypted HTTPS.")
                side_effects.append("Legacy HTTP endpoints or local LAN APIs will fail to connect.")
                manifest_changes.append("Set android:usesCleartextTraffic='false' on <application>")
            elif "backup" in target.lower():
                functional.append("ADB backup extraction of application data will be blocked.")
                side_effects.append("Device-to-device migration using ADB backup will be skipped.")
                manifest_changes.append("Set android:allowBackup='false' on <application>")
            file_changes.append("AndroidManifest.xml")

        else:
            direct.append(f"Operation '{change_type.value}' applied to target '{target}'.")
            functional.append("Target functionality altered.")
            file_changes.append("AndroidManifest.xml")

        return ImpactAssessment(
            direct_effects=direct,
            potential_functional_effects=functional,
            potential_side_effects=side_effects,
            expected_file_changes=file_changes,
            expected_manifest_changes=manifest_changes,
            expected_dex_changes=dex_changes,
            expected_resource_changes=res_changes,
            expected_native_changes=native_changes,
            rebuild_required=True,
            resign_required=True,
            verification_required=True,
        )

    @staticmethod
    def assess_risk(
        change_type: ChangeType,
        target: str,
        has_dynamic_code: bool = False,
        is_exported: bool = False,
        has_api_references: bool = False,
    ) -> tuple[ModificationRisk, str]:
        """Estimate modification risk and return an explainable rationale."""
        if change_type == ChangeType.MODIFY_CONFIGURATION:
            return (
                ModificationRisk.LOW,
                "Manifest security hardening flags (e.g. disabling debuggable or cleartext) "
                "generally do not alter application core business logic.",
            )

        if change_type == ChangeType.REMOVE_PERMISSION:
            if has_api_references:
                return (
                    ModificationRisk.HIGH,
                    f"Permission '{target}' has detected bytecode API references; removing it "
                    f"will cause SecurityExceptions during execution of those code paths.",
                )
            if has_dynamic_code:
                return (
                    ModificationRisk.MEDIUM,
                    f"Permission '{target}' has no direct static API usage, but dynamic class "
                    f"loading was detected in DEX; runtime reflection might still use it.",
                )
            return (
                ModificationRisk.LOW,
                f"Permission '{target}' is declared but no corresponding framework API references "
                f"or dependent components were discovered by static inspection.",
            )

        if change_type == ChangeType.REMOVE_TRACKER:
            return (
                ModificationRisk.MEDIUM,
                f"Removing tracker SDK '{target}' alters third-party analytics and ads; "
                f"code calling the SDK requires stubbing to prevent NoClassDefFoundError.",
            )

        if change_type in (ChangeType.REMOVE_COMPONENT, ChangeType.DISABLE_COMPONENT):
            if is_exported:
                return (
                    ModificationRisk.MEDIUM,
                    f"Component '{target}' is exported; disabling it removes an external IPC "
                    f"entry point, which may break third-party integration or system callbacks.",
                )
            return (
                ModificationRisk.LOW,
                f"Component '{target}' is internal; disabling it will not affect external apps.",
            )

        if change_type == ChangeType.REMOVE_EMBEDDED_PAYLOAD:
            return (
                ModificationRisk.MEDIUM,
                f"Removing embedded file '{target}' prevents payload execution; ensure no "
                f"vital application assets or secondary feature modules depend on this file.",
            )

        if change_type in (ChangeType.DEX_MODIFICATION, ChangeType.NATIVE_MODIFICATION):
            return (
                ModificationRisk.HIGH,
                f"Direct binary modification of '{target}' alters compiled code structure, "
                f"carrying risk of runtime verification errors or crashes.",
            )

        return (
            ModificationRisk.MEDIUM,
            f"Modifying '{target}' carries potential operational risk.",
        )
