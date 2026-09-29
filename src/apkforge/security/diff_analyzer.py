"""Diff-aware security analysis: detects security-relevant changes between APK versions."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from apkforge.core.models import Confidence, Evidence, Severity
from apkforge.diff.models import ChangeType
from apkforge.security.models import SecurityFinding

if TYPE_CHECKING:
    from apkforge.diff.models import DiffResult

_log = logging.getLogger(__name__)

DANGEROUS_PERMISSIONS = {
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.INSTALL_PACKAGES",
    "android.permission.REQUEST_INSTALL_PACKAGES",
}


class DiffSecurityAnalyzer:
    """Analyzes a Phase 3 DiffResult to identify security regressions and capability additions."""

    def analyze(self, diff_result: DiffResult) -> list[SecurityFinding]:
        """Analyze structural diff results for security-relevant changes."""
        findings: list[SecurityFinding] = []

        # 1. Added Dangerous Permissions
        added_perms: list[str] = []
        if hasattr(diff_result, "permissions") and diff_result.permissions:
            raw_added = getattr(diff_result.permissions, "added", []) or []
            for p in raw_added:
                p_name = p.name if hasattr(p, "name") else str(p)
                if p_name in DANGEROUS_PERMISSIONS or any(
                    dp.endswith("." + p_name) for dp in DANGEROUS_PERMISSIONS
                ):
                    added_perms.append(p_name)

        if added_perms:
            ev = [
                Evidence(
                    description=f"Dangerous permission added in modified APK: {p}",
                    location=f"diff:permission:{p}",
                    snippet=f"+ permission: {p}",
                )
                for p in added_perms
            ]
            perms_str = ", ".join(added_perms)
            findings.append(
                SecurityFinding(
                    id="SEC-DIFF-ADDED-DANGEROUS-PERMISSIONS",
                    category="diff_modification",
                    title=(
                        f"Security Regression: {len(added_perms)} Dangerous Permission(s) "
                        f"Introduced"
                    ),
                    description=(
                        f"The modified APK introduced sensitive Android permissions not present "
                        f"in the original version: {perms_str}."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    evidence=ev,
                    assessment=(
                        "Introducing dangerous permissions expands the attack surface and"
                        "hardware data capabilities"
                        "of the application compared to its baseline."
                    ),
                    limitations=[
                        "Version upgrades frequently introduce new features that require"
                        "additional permissions legitimately."
                    ],
                    references=["CWE-250: Execution with Unnecessary Privileges"],
                    tags=["diff", "permissions", "regression"],
                )
            )

        # 2. Signing Certificate Changed
        cert_changed = False
        if hasattr(diff_result, "certificates") and diff_result.certificates:
            c = diff_result.certificates
            status = getattr(c, "status", "UNCHANGED")
            cert_changed = status not in ("UNCHANGED", "SAME") or getattr(
                c, "fingerprint_changes", None
            )

        if cert_changed:
            status_val = getattr(diff_result.certificates, "status", "CHANGED")
            ev = [
                Evidence(
                    description="Signing certificates or fingerprints modified between versions",
                    location="diff:certificates",
                    snippet=f"Certificate status: {status_val}",
                )
            ]
            findings.append(
                SecurityFinding(
                    id="SEC-DIFF-CERTIFICATE-CHANGED",
                    category="diff_modification",
                    title="Cryptographic Signing Certificate Changed",
                    description=(
                        "The application signing certificate differs between the two APK versions. "
                        "This indicates the application was re-signed with a different private key."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    evidence=ev,
                    assessment=(
                        "A changed signing identity prevents automated system updates and breaks"
                        "Android Signature-level"
                        "permission protections. This is a primary indicator of third-party"
                        "repacking or modification."
                    ),
                    limitations=[
                        "Key rotation or migration to new developer credentials can legitimately"
                        "alter signing certificates."
                    ],
                    references=[
                        "CWE-295: Improper Certificate Validation",
                        "CWE-347: Improper Verification of Cryptographic Signature",
                    ],
                    tags=["diff", "certificate", "signature", "repack"],
                )
            )

        # 3. Added Exported Components
        added_exported = []
        if hasattr(diff_result, "components") and diff_result.components:
            for comp_list in (
                diff_result.components.activities,
                diff_result.components.services,
                diff_result.components.receivers,
                diff_result.components.providers,
            ):
                for comp in comp_list:
                    if (
                        getattr(comp, "change_type", None) == ChangeType.ADDED
                        and getattr(comp, "exported_after", False) is True
                    ):
                        added_exported.append(comp)

        if added_exported:
            ev = [
                Evidence(
                    description=f"Exported component added: [{c.component_type}] {c.name}",
                    location=f"diff:component:{c.name}",
                    snippet=f"+ [{c.component_type}] {c.name} (exported=true)",
                )
                for c in added_exported[:5]
            ]
            findings.append(
                SecurityFinding(
                    id="SEC-DIFF-ADDED-EXPORTED-COMPONENTS",
                    category="diff_modification",
                    title=f"New Exported Components Introduced ({len(added_exported)} components)",
                    description=(
                        f"The modified APK introduced {len(added_exported)} new exported "
                        f"component(s) accessible to other applications on the device."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    evidence=ev,
                    assessment=(
                        "Exposing new entry points increases the inter-process attack surface of"
                        "the application."
                    ),
                    limitations=[
                        "New activities or public share targets are standard additions in"
                        "application updates."
                    ],
                    references=["CWE-926: Improper Export of Android Application Components"],
                    tags=["diff", "component", "exported"],
                )
            )

        # 4. Added Native Libraries
        added_native: list[str] = []
        if hasattr(diff_result, "native") and diff_result.native:
            for lib in getattr(diff_result.native, "libraries_added", []):
                added_native.append(getattr(lib, "path", str(lib)))

        if added_native:
            ev = [
                Evidence(
                    description=f"Native binary library introduced: {p}",
                    location=f"diff:file:{p}",
                    snippet=f"+ native: {p}",
                )
                for p in added_native[:5]
            ]
            findings.append(
                SecurityFinding(
                    id="SEC-DIFF-ADDED-NATIVE-LIBS",
                    category="diff_modification",
                    title=f"Native Library Binaries Added ({len(added_native)} libraries)",
                    description=(
                        f"The modified APK includes {len(added_native)} new compiled "
                        f"native library (.so) file(s)."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    evidence=ev,
                    assessment=(
                        "Introducing compiled native binaries adds native C/C++ execution paths"
                        "that cannot be"
                        "inspected using standard DEX bytecode decompilation."
                    ),
                    limitations=[
                        "Adding native C++ dependencies, multimedia codecs, or rendering engines"
                        "is common in updates."
                    ],
                    references=["CWE-506: Embedded Malicious Code"],
                    tags=["diff", "native", "libraries"],
                )
            )

        # 5. Added External Network Endpoints
        added_domains: list[str] = []
        if hasattr(diff_result, "network") and diff_result.network:
            added_domains = list(getattr(diff_result.network, "domains_added", []))

        if added_domains:
            ev = [
                Evidence(
                    description=f"New domain endpoint introduced: {d}",
                    location=f"diff:domain:{d}",
                    snippet=f"+ domain: {d}",
                )
                for d in added_domains[:5]
            ]
            domains_sample = ", ".join(added_domains[:5])
            findings.append(
                SecurityFinding(
                    id="SEC-DIFF-ADDED-ENDPOINTS",
                    category="diff_modification",
                    title=f"New Network Domain Endpoints Introduced ({len(added_domains)} domains)",
                    description=(
                        f"The modified APK introduces references to {len(added_domains)} new "
                        f"network domain(s) not in original package: {domains_sample}."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    evidence=ev,
                    assessment=(
                        "New network endpoints indicate new remote communication targets or"
                        "added third-party services."
                    ),
                    limitations=[
                        "Application updates frequently add new CDN hosts, API backends, or"
                        "analytics providers."
                    ],
                    references=["CWE-200: Exposure of Sensitive Information"],
                    tags=["diff", "network", "endpoints"],
                )
            )

        # 6. Added Dynamic Loading or Command Execution APIs
        added_apis: list[str] = []
        if hasattr(diff_result, "dex") and diff_result.dex:
            added_apis = list(getattr(diff_result.dex, "api_references_added", []))

        has_new_dyn = any(
            loader in a for a in added_apis for loader in ("DexClassLoader", "PathClassLoader")
        )
        has_new_exec = any(e in a for a in added_apis for e in ("Runtime.exec", "ProcessBuilder"))

        if has_new_dyn or has_new_exec:
            ev = []
            if has_new_dyn:
                ev.append(
                    Evidence(
                        description="Dynamic bytecode loading API introduced in diff",
                        location="diff:api:DexClassLoader",
                        snippet="+ DexClassLoader API",
                    )
                )
            if has_new_exec:
                ev.append(
                    Evidence(
                        description="OS Command execution API introduced in diff",
                        location="diff:api:Runtime.exec",
                        snippet="+ Runtime.exec / ProcessBuilder API",
                    )
                )

            findings.append(
                SecurityFinding(
                    id="SEC-DIFF-ADDED-EXECUTION-APIS",
                    category="diff_modification",
                    title="Code Execution / Dynamic Loading APIs Introduced in Modified APK",
                    description=(
                        "The modified APK references process execution or dynamic class loading"
                        "APIs that were"
                        "not present in the baseline APK."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    evidence=ev,
                    assessment=(
                        "Introducing dynamic loading or command execution in a modified APK is a"
                        "strong indicator"
                        "of payload delivery or arbitrary code execution mechanisms."
                    ),
                    limitations=[
                        "Legitimate framework refactorings or plugin SDK updates may introduce"
                        "dynamic loading."
                    ],
                    references=[
                        "CWE-94: Improper Control of Generation of Code ('Code Injection')",
                        "CWE-78: OS Command Injection",
                    ],
                    tags=["diff", "execution", "dynamic_loading"],
                )
            )

        return sorted(findings, key=lambda f: f.id)
