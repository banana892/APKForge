"""Rule definitions and context for modification planning."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar, Protocol

from apkforge.core.models import Confidence, Evidence
from apkforge.modification.impact import ImpactAnalyzer
from apkforge.modification.models import (
    ChangeType,
    ModificationRisk,
    PlannedChange,
    Reversibility,
)
from apkforge.modification.validation import ValidationGenerator

if TYPE_CHECKING:
    from pathlib import Path

    from apkforge.diff.models import DiffResult
    from apkforge.inspection.models import InspectionResult
    from apkforge.intake import AndroidPackage
    from apkforge.privacy.models import PrivacyResult
    from apkforge.security.models import SecurityResult

_log = logging.getLogger(__name__)


@dataclass
class ModificationContext:
    """Consolidated static analysis context provided to modification rules."""

    apk_path: Path
    apk_sha256: str
    package: AndroidPackage | None = None
    inspection: InspectionResult | None = None
    privacy: PrivacyResult | None = None
    security: SecurityResult | None = None
    diff: DiffResult | None = None

    def has_permission(self, name: str) -> bool:
        """Check if manifest declares the specified permission."""
        if not self.inspection or not self.inspection.manifest:
            return False
        clean = name.lower().replace("android.permission.", "")
        for p in self.inspection.manifest.permissions:
            p_clean = p.name.lower().replace("android.permission.", "")
            if clean == p_clean or clean in p_clean:
                return True
        return False

    def has_api(self, api_substr: str) -> bool:
        """Check if any DEX file references the given API class or method substring."""
        if not self.inspection or not self.inspection.dex:
            return False
        sub = api_substr.lower()
        for df in self.inspection.dex.dex_files:
            for api_ref in df.api_references:
                if sub in api_ref.lower():
                    return True
        return False

    def has_dynamic_loading(self) -> bool:
        """Check if dynamic code loading indicators (DexClassLoader) are present."""
        if self.security:
            for f in self.security.findings:
                if "dynload" in f.id.lower() or "dynamic" in f.title.lower():
                    return True
        return self.has_api("DexClassLoader") or self.has_api("PathClassLoader")

    def has_obfuscation(self) -> bool:
        """Check if significant obfuscation was detected."""
        if self.inspection and self.inspection.obfuscation:
            return self.inspection.obfuscation.is_likely_obfuscated
        return False


class ModificationRule(Protocol):
    """Protocol for rules that identify and propose planned modifications."""

    rule_id: str
    name: str
    description: str

    def identify(self, context: ModificationContext) -> list[PlannedChange]:
        """Analyze the context and generate zero or more planned change proposals."""
        ...


class UnusedPermissionRule:
    """Proposes removing declared permissions that lack corresponding API evidence."""

    rule_id = "PLAN-RULE-UNUSED-PERMISSION"
    name = "Unused Permission Removal"
    description = (
        "Identifies declared permissions without corresponding bytecode API references "
        "or component requirements."
    )

    # Mapping of sensitive permissions to required API substrings
    SENSITIVE_PERM_APIS: ClassVar[dict[str, list[str]]] = {
        "RECORD_AUDIO": ["AudioRecord", "MediaRecorder"],
        "CAMERA": ["camera2", "CameraManager", "android.hardware.Camera"],
        "ACCESS_FINE_LOCATION": ["LocationManager", "FusedLocationProviderClient"],
        "ACCESS_COARSE_LOCATION": ["LocationManager", "FusedLocationProviderClient"],
        "READ_CONTACTS": ["ContactsContract"],
        "READ_SMS": ["SmsManager", "Telephony"],
        "RECEIVE_SMS": ["SmsMessage", "Telephony"],
        "READ_CALL_LOG": ["CallLog", "TelephonyManager"],
        "READ_PHONE_STATE": ["TelephonyManager"],
    }

    def identify(self, context: ModificationContext) -> list[PlannedChange]:
        """Propose removing unused permissions."""
        changes: list[PlannedChange] = []
        if not context.inspection or not context.inspection.manifest:
            return changes

        has_dyn = context.has_dynamic_loading()
        has_obf = context.has_obfuscation()

        for p in context.inspection.manifest.permissions:
            p_name = p.name
            p_short = p_name.replace("android.permission.", "")

            # Check if this is a sensitive permission with known API patterns
            if p_short in self.SENSITIVE_PERM_APIS:
                required_apis = self.SENSITIVE_PERM_APIS[p_short]
                api_found = any(context.has_api(api) for api in required_apis)

                if not api_found:
                    conf = Confidence.MEDIUM if (has_dyn or has_obf) else Confidence.HIGH
                    risk, risk_expl = ImpactAnalyzer.assess_risk(
                        ChangeType.REMOVE_PERMISSION,
                        p_name,
                        has_dynamic_code=has_dyn,
                        has_api_references=False,
                    )
                    impact = ImpactAnalyzer.assess_impact(
                        ChangeType.REMOVE_PERMISSION,
                        p_name,
                        context,
                    )
                    steps = ValidationGenerator.generate_steps(
                        ChangeType.REMOVE_PERMISSION,
                        p_name,
                    )

                    reason = (
                        f"Permission '{p_name}' is declared in the manifest, but no supporting "
                        f"framework API calls ({', '.join(required_apis)}) were detected in "
                        f"DEX bytecode."
                    )
                    if has_dyn or has_obf:
                        reason += (
                            " Note: Dynamic class loading or obfuscation is present; runtime "
                            "reflection could invoke APIs indirectly."
                        )

                    ev = [
                        Evidence(
                            description=f"Manifest declared permission: {p_name}",
                            location=f"manifest:permission:{p_name}",
                            snippet=p_name,
                        )
                    ]

                    changes.append(
                        PlannedChange(
                            id=f"CHANGE-PERM-{p_short}",
                            change_type=ChangeType.REMOVE_PERMISSION,
                            target=p_name,
                            operation=f"Remove <uses-permission android:name='{p_name}' />",
                            reason=reason,
                            evidence=ev,
                            confidence=conf,
                            risk=risk,
                            risk_explanation=risk_expl,
                            impact=impact,
                            reversibility=Reversibility.REVERSIBLE,
                            reversibility_explanation=(
                                "Removing a permission declaration can be completely reversed by "
                                "re-adding the XML tag."
                            ),
                            validation_steps=steps,
                            tags=["permission", "privacy", "attack_surface"],
                            rule_id=self.rule_id,
                            backend="ManifestModifier",
                        )
                    )

        return changes


class TrackerRemovalRule:
    """Proposes removing third-party tracker, advertising, and analytics SDKs."""

    rule_id = "PLAN-RULE-TRACKER-REMOVAL"
    name = "Tracker & Ad SDK Removal"
    description = (
        "Proposes removing detected third-party tracking, advertising, and analytics SDKs."
    )

    def identify(self, context: ModificationContext) -> list[PlannedChange]:
        """Propose removing detected tracker SDKs."""
        changes: list[PlannedChange] = []
        if not context.privacy:
            return changes

        sdks = context.privacy.all_detected_sdks
        if not sdks:
            return changes

        for sdk in sdks:
            target_name = sdk.name
            target_id = target_name.upper().replace(" ", "_").replace("-", "_")

            ev: list[Evidence] = list(sdk.evidence)
            if not ev:
                for pkg in sdk.matched_packages:
                    ev.append(
                        Evidence(
                            description=f"Tracker SDK package: {pkg}",
                            location="dex:package",
                            snippet=pkg,
                        )
                    )
                for ep in sdk.matched_endpoints:
                    ev.append(
                        Evidence(
                            description=f"Tracker SDK endpoint: {ep}",
                            location="dex:strings",
                            snippet=ep,
                        )
                    )

            risk, risk_expl = ImpactAnalyzer.assess_risk(
                ChangeType.REMOVE_TRACKER,
                target_name,
            )
            impact = ImpactAnalyzer.assess_impact(
                ChangeType.REMOVE_TRACKER,
                target_name,
                context,
            )
            steps = ValidationGenerator.generate_steps(
                ChangeType.REMOVE_TRACKER,
                target_name,
            )

            changes.append(
                PlannedChange(
                    id=f"CHANGE-TRACKER-{target_id}",
                    change_type=ChangeType.REMOVE_TRACKER,
                    target=target_name,
                    operation=f"Remove {target_name} SDK classes, components, and endpoints",
                    reason=(
                        f"Third-party tracking SDK '{target_name}' was detected. Removing it "
                        f"eliminates user data collection and telemetry transmissions."
                    ),
                    evidence=ev,
                    confidence=sdk.confidence,
                    risk=risk,
                    risk_explanation=risk_expl,
                    impact=impact,
                    reversibility=Reversibility.PARTIALLY_REVERSIBLE,
                    reversibility_explanation=(
                        "Bytecode classes and initialization providers can be restored from "
                        "the original APK backup."
                    ),
                    validation_steps=steps,
                    tags=["tracker", "advertising", "privacy"],
                    rule_id=self.rule_id,
                    backend="TrackerModifier",
                )
            )

        return changes


class InsecureManifestHardeningRule:
    """Proposes hardening insecure manifest configuration flags."""

    rule_id = "PLAN-RULE-MANIFEST-HARDENING"
    name = "Manifest Security Hardening"
    description = (
        "Proposes disabling insecure development and transport flags in AndroidManifest.xml."
    )

    def identify(self, context: ModificationContext) -> list[PlannedChange]:
        """Propose hardening manifest flags."""
        changes: list[PlannedChange] = []
        if not context.inspection or not context.inspection.manifest:
            return changes

        app_info = context.inspection.manifest.application
        if not app_info:
            return changes

        # 1. debuggable=true
        if app_info.debuggable:
            target = "android:debuggable"
            ev = [
                Evidence(
                    description="Manifest declares android:debuggable='true'",
                    location="manifest:application:debuggable",
                    snippet="android:debuggable='true'",
                )
            ]
            changes.append(
                PlannedChange(
                    id="CHANGE-CONFIG-DEBUGGABLE",
                    change_type=ChangeType.MODIFY_CONFIGURATION,
                    target=target,
                    operation="Set android:debuggable='false' on <application>",
                    reason=(
                        "Application is marked debuggable, allowing arbitrary debugger attachment, "
                        "memory dumping, and internal process manipulation."
                    ),
                    evidence=ev,
                    confidence=Confidence.CONFIRMED,
                    risk=ModificationRisk.LOW,
                    risk_explanation=(
                        "Disabling debuggable protects process memory without altering logic."
                    ),
                    impact=ImpactAnalyzer.assess_impact(
                        ChangeType.MODIFY_CONFIGURATION,
                        target,
                        context,
                    ),
                    reversibility=Reversibility.REVERSIBLE,
                    reversibility_explanation="Easily reversed by changing attribute value.",
                    validation_steps=ValidationGenerator.generate_steps(
                        ChangeType.MODIFY_CONFIGURATION,
                        target,
                    ),
                    tags=["manifest", "configuration", "hardening"],
                    rule_id=self.rule_id,
                    backend="ManifestModifier",
                )
            )

        # 2. usesCleartextTraffic=true
        if app_info.uses_cleartext_traffic:
            target = "android:usesCleartextTraffic"
            ev = [
                Evidence(
                    description="Manifest declares android:usesCleartextTraffic='true'",
                    location="manifest:application:usesCleartextTraffic",
                    snippet="android:usesCleartextTraffic='true'",
                )
            ]
            changes.append(
                PlannedChange(
                    id="CHANGE-CONFIG-CLEARTEXT",
                    change_type=ChangeType.MODIFY_CONFIGURATION,
                    target=target,
                    operation="Set android:usesCleartextTraffic='false' on <application>",
                    reason=(
                        "Application explicitly permits unencrypted HTTP network traffic, "
                        "enabling network eavesdropping and MITM manipulation."
                    ),
                    evidence=ev,
                    confidence=Confidence.CONFIRMED,
                    risk=ModificationRisk.LOW,
                    risk_explanation="Enforcing HTTPS protects user communications.",
                    impact=ImpactAnalyzer.assess_impact(
                        ChangeType.MODIFY_CONFIGURATION,
                        target,
                        context,
                    ),
                    reversibility=Reversibility.REVERSIBLE,
                    reversibility_explanation="Easily reversed by restoring XML flag.",
                    validation_steps=ValidationGenerator.generate_steps(
                        ChangeType.MODIFY_CONFIGURATION,
                        target,
                    ),
                    tags=["manifest", "configuration", "network_security"],
                    rule_id=self.rule_id,
                    backend="ManifestModifier",
                )
            )

        # 3. allowBackup=true
        if app_info.allow_backup:
            target = "android:allowBackup"
            ev = [
                Evidence(
                    description="Manifest declares android:allowBackup='true'",
                    location="manifest:application:allowBackup",
                    snippet="android:allowBackup='true'",
                )
            ]
            changes.append(
                PlannedChange(
                    id="CHANGE-CONFIG-BACKUP",
                    change_type=ChangeType.MODIFY_CONFIGURATION,
                    target=target,
                    operation="Set android:allowBackup='false' on <application>",
                    reason=(
                        "Application allows ADB backup extraction of local databases and private "
                        "SharedPreferences."
                    ),
                    evidence=ev,
                    confidence=Confidence.CONFIRMED,
                    risk=ModificationRisk.LOW,
                    risk_explanation="Disabling backup prevents physical ADB data extraction.",
                    impact=ImpactAnalyzer.assess_impact(
                        ChangeType.MODIFY_CONFIGURATION,
                        target,
                        context,
                    ),
                    reversibility=Reversibility.REVERSIBLE,
                    reversibility_explanation="Easily reversed by setting allowBackup='true'.",
                    validation_steps=ValidationGenerator.generate_steps(
                        ChangeType.MODIFY_CONFIGURATION,
                        target,
                    ),
                    tags=["manifest", "configuration", "data_protection"],
                    rule_id=self.rule_id,
                    backend="ManifestModifier",
                )
            )

        return changes


class UnprotectedExportedComponentRule:
    """Proposes securing or disabling unprotected exported components."""

    rule_id = "PLAN-RULE-EXPORTED-COMPONENT"
    name = "Unprotected Exported Component Hardening"
    description = (
        "Proposes setting android:exported='false' on components accessible to all apps without "
        "permission requirements."
    )

    def identify(self, context: ModificationContext) -> list[PlannedChange]:
        """Propose securing exported components."""
        changes: list[PlannedChange] = []
        if not context.inspection or not context.inspection.manifest:
            return changes

        # Check services
        for s in context.inspection.manifest.services:
            if s.exported and not s.permission:
                target = s.name
                cid = f"CHANGE-COMP-SERVICE-{target.split('.')[-1].upper()}"
                ev = [
                    Evidence(
                        description=f"Exported Service without permission: {target}",
                        location=f"manifest:service:{target}",
                        snippet=f"Service: {target} (exported=true)",
                    )
                ]
                changes.append(
                    PlannedChange(
                        id=cid,
                        change_type=ChangeType.MODIFY_COMPONENT,
                        target=target,
                        operation=f"Set android:exported='false' on Service '{target}'",
                        reason=(
                            f"Service '{target}' is exported without permission protection, "
                            f"allowing any application on the device to invoke it."
                        ),
                        evidence=ev,
                        confidence=Confidence.CONFIRMED,
                        risk=ModificationRisk.MEDIUM,
                        risk_explanation=(
                            "Setting exported='false' closes external IPC access; verify that "
                            "external system intents (e.g. FCM) do not require it."
                        ),
                        impact=ImpactAnalyzer.assess_impact(
                            ChangeType.MODIFY_COMPONENT,
                            target,
                            context,
                        ),
                        reversibility=Reversibility.REVERSIBLE,
                        reversibility_explanation="Exported flag can be toggled back to true.",
                        validation_steps=ValidationGenerator.generate_steps(
                            ChangeType.MODIFY_COMPONENT,
                            target,
                        ),
                        tags=["component", "ipc", "attack_surface"],
                        rule_id=self.rule_id,
                        backend="ManifestModifier",
                    )
                )

        # Check providers
        for pr in context.inspection.manifest.providers:
            if pr.exported and not pr.permission:
                target = pr.name
                cid = f"CHANGE-COMP-PROVIDER-{target.split('.')[-1].upper()}"
                ev = [
                    Evidence(
                        description=f"Exported Content Provider without permission: {target}",
                        location=f"manifest:provider:{target}",
                        snippet=f"Provider: {target} (exported=true)",
                    )
                ]
                changes.append(
                    PlannedChange(
                        id=cid,
                        change_type=ChangeType.MODIFY_COMPONENT,
                        target=target,
                        operation=f"Set android:exported='false' on Provider '{target}'",
                        reason=(
                            f"ContentProvider '{target}' is exported without read/write "
                            f"permissions, risking database information disclosure."
                        ),
                        evidence=ev,
                        confidence=Confidence.CONFIRMED,
                        risk=ModificationRisk.MEDIUM,
                        risk_explanation=(
                            "Prevents unauthorized apps from querying database content."
                        ),
                        impact=ImpactAnalyzer.assess_impact(
                            ChangeType.MODIFY_COMPONENT,
                            target,
                            context,
                        ),
                        reversibility=Reversibility.REVERSIBLE,
                        reversibility_explanation="Exported flag can be restored.",
                        validation_steps=ValidationGenerator.generate_steps(
                            ChangeType.MODIFY_COMPONENT,
                            target,
                        ),
                        tags=["component", "provider", "database"],
                        rule_id=self.rule_id,
                        backend="ManifestModifier",
                    )
                )

        return changes


class EmbeddedPayloadRemovalRule:
    """Proposes removing suspicious standalone ELF or nested APK payloads."""

    rule_id = "PLAN-RULE-PAYLOAD-REMOVAL"
    name = "Embedded Payload Removal"
    description = "Proposes removing suspicious standalone executable files or nested APK archives."

    def identify(self, context: ModificationContext) -> list[PlannedChange]:
        """Propose removing embedded payloads identified in security analysis."""
        changes: list[PlannedChange] = []
        if not context.security:
            return changes

        for finding in context.security.findings:
            if "payload" in finding.category.lower() or "payload" in finding.id.lower():
                # Extract file path from finding evidence
                for ev in finding.evidence:
                    if ev.location and ("file:" in ev.location or "embedded:" in ev.location):
                        path = ev.location.split(":")[-1]
                        cid = f"CHANGE-PAYLOAD-{path.replace('/', '_').replace('.', '_').upper()}"
                        changes.append(
                            PlannedChange(
                                id=cid,
                                change_type=ChangeType.REMOVE_EMBEDDED_PAYLOAD,
                                target=path,
                                operation=f"Delete embedded payload file '{path}'",
                                reason=(
                                    f"Security finding '{finding.id}' identified suspicious "
                                    f"embedded executable payload at '{path}'."
                                ),
                                evidence=[ev],
                                confidence=finding.confidence,
                                risk=ModificationRisk.MEDIUM,
                                risk_explanation=(
                                    f"Removing standalone payload '{path}' eliminates execution "
                                    f"risk; confirm no vital application assets rely on this file."
                                ),
                                impact=ImpactAnalyzer.assess_impact(
                                    ChangeType.REMOVE_EMBEDDED_PAYLOAD,
                                    path,
                                    context,
                                ),
                                reversibility=Reversibility.REVERSIBLE,
                                reversibility_explanation=(
                                    "Payload file can be re-inserted from backup."
                                ),
                                validation_steps=ValidationGenerator.generate_steps(
                                    ChangeType.REMOVE_EMBEDDED_PAYLOAD,
                                    path,
                                ),
                                tags=["payload", "malware_mitigation", "binary"],
                                rule_id=self.rule_id,
                                backend="ArchiveModifier",
                            )
                        )

        return changes


class DiffRegressionMitigationRule:
    """Proposes rolling back security regressions introduced by APK modifications."""

    rule_id = "PLAN-RULE-DIFF-REGRESSION-MITIGATION"
    name = "Diff Security Regression Mitigation"
    description = (
        "Detects newly introduced dangerous permissions and attack surfaces from diff "
        "results and proposes rolling them back."
    )

    def identify(self, context: ModificationContext) -> list[PlannedChange]:
        """Propose rolling back diff regressions."""
        changes: list[PlannedChange] = []
        if not context.diff:
            return changes

        # Check added permissions
        if context.diff.permissions:
            for p in context.diff.permissions.added:
                p_str = str(p)
                cid = f"CHANGE-DIFF-REVERT-PERM-{p_str.split('.')[-1].upper()}"
                ev = [
                    Evidence(
                        description=f"Permission added in modified version: {p_str}",
                        location=f"diff:permission:{p_str}",
                        snippet=f"+ permission: {p_str}",
                    )
                ]
                changes.append(
                    PlannedChange(
                        id=cid,
                        change_type=ChangeType.REMOVE_PERMISSION,
                        target=p_str,
                        operation=f"Revert added permission <uses-permission name='{p_str}' />",
                        reason=(
                            f"Diff analysis shows permission '{p_str}' was newly introduced in "
                            f"the modified APK version. Proposing rollback to original profile."
                        ),
                        evidence=ev,
                        confidence=Confidence.CONFIRMED,
                        risk=ModificationRisk.LOW,
                        risk_explanation=(
                            f"Reverting permission '{p_str}' restores original security baseline."
                        ),
                        impact=ImpactAnalyzer.assess_impact(
                            ChangeType.REMOVE_PERMISSION,
                            p_str,
                            context,
                        ),
                        reversibility=Reversibility.REVERSIBLE,
                        reversibility_explanation="Can be re-added if required.",
                        validation_steps=ValidationGenerator.generate_steps(
                            ChangeType.REMOVE_PERMISSION,
                            p_str,
                        ),
                        tags=["diff", "regression", "rollback"],
                        rule_id=self.rule_id,
                        backend="ManifestModifier",
                    )
                )

        return changes
