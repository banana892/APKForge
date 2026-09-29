"""Validation step generation for planned modifications."""

from __future__ import annotations

from apkforge.modification.models import ChangeType


class ValidationGenerator:
    """Generates verification steps for post-modification assurance."""

    @staticmethod
    def generate_steps(change_type: ChangeType, target: str) -> list[str]:
        """Generate ordered validation steps for a specific modification proposal."""
        if change_type == ChangeType.REMOVE_PERMISSION:
            return [
                f"Verify <uses-permission android:name='{target}' /> is absent from rebuilt "
                f"AndroidManifest.xml.",
                "Re-run Core Inspection (apkforge inspect) to confirm permission is absent from "
                "manifest inventory.",
                "Re-run Privacy Analysis (apkforge privacy) to confirm permission capability is "
                "cleared.",
                "Execute APK Diff (apkforge diff) to confirm only the specified permission was "
                "modified.",
            ]

        if change_type == ChangeType.DISABLE_COMPONENT:
            return [
                f"Verify component '{target}' declaration contains android:enabled='false' in "
                f"AndroidManifest.xml.",
                "Re-run Security Analysis (apkforge security) to confirm component attack surface "
                "is neutralized.",
                "Launch application in testing environment to confirm startup without "
                "ComponentNotFoundException.",
            ]

        if change_type == ChangeType.REMOVE_COMPONENT:
            return [
                f"Verify component tag for '{target}' is completely deleted from "
                f"AndroidManifest.xml.",
                "Re-run Core Inspection (apkforge inspect) to confirm component count "
                "decreased by 1.",
                "Confirm no internal Intent filters or manifest aliases reference the deleted "
                "component.",
            ]

        if change_type == ChangeType.MODIFY_COMPONENT:
            return [
                f"Verify component '{target}' specifies android:exported='false' in "
                f"AndroidManifest.xml.",
                "Re-run Security Analysis (apkforge security) to verify unprotected exported "
                "finding is cleared.",
                "Attempt to trigger component via external ADB am start/broadcast; verify "
                "SecurityException is raised.",
            ]

        if change_type == ChangeType.REMOVE_TRACKER:
            return [
                f"Verify bytecode packages and classes associated with '{target}' are removed or "
                f"stubbed in DEX.",
                f"Verify tracker initialization ContentProviders and metadata tags for '{target}' "
                f"are removed.",
                "Re-run Privacy Analysis (apkforge privacy) to verify tracker signature is no "
                "longer detected.",
                "Run APK Diff (apkforge diff) to verify associated network endpoints are cleared.",
            ]

        if change_type == ChangeType.REMOVE_EMBEDDED_PAYLOAD:
            return [
                f"Verify binary payload file '{target}' is absent from the rebuilt archive.",
                "Re-run Security Analysis (apkforge security) to confirm embedded payload finding "
                "is resolved.",
                "Verify archive integrity and DEX checksum consistency.",
            ]

        if change_type == ChangeType.MODIFY_CONFIGURATION:
            return [
                f"Verify configuration attribute '{target}' is correctly set in "
                f"AndroidManifest.xml.",
                "Re-run Security Analysis (apkforge security) to verify configuration issue "
                "is resolved.",
                "Re-run Core Inspection (apkforge inspect) to verify application flags.",
            ]

        return [
            f"Verify modification '{change_type.value}' applied to '{target}'.",
            "Re-run Core Inspection (apkforge inspect) to verify structural integrity.",
            "Compare original and rebuilt APK using APK Diff (apkforge diff).",
        ]
