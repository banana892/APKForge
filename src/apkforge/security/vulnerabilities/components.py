"""Component exposure and export vulnerability analyzer."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from apkforge.core.models import Confidence, Evidence, Severity
from apkforge.security.models import SecurityFinding

if TYPE_CHECKING:
    from apkforge.security.rules import SecurityEvidenceIndex

_log = logging.getLogger(__name__)


class ComponentVulnerabilityAnalyzer:
    """Analyzes exported Android components lacking permission protection."""

    def analyze(self, index: SecurityEvidenceIndex) -> list[SecurityFinding]:
        """Inspect activities, services, receivers, and providers for exposure vulnerabilities."""
        findings: list[SecurityFinding] = []

        # 1. Exported Content Providers without permissions
        providers = index.components.get("providers", [])
        unprotected_providers = [
            p for p in providers if p.get("exported", False) and not p.get("permission")
        ]

        if unprotected_providers:
            ev = [
                Evidence(
                    description=f"Exported content provider lacking permission: {p.get('name')}",
                    location=f"manifest:provider:{p.get('name')}",
                    snippet=f"Provider: {p.get('name')} (exported=true, permission=None)",
                )
                for p in unprotected_providers[:5]
            ]
            findings.append(
                SecurityFinding(
                    id="SEC-VULN-EXPORTED-PROVIDER",
                    category="exported_component",
                    title="Exported Content Provider Lacks Permission Protection",
                    description=(
                        f"Found {len(unprotected_providers)} Content Provider(s) declared with "
                        f"android:exported='true' without a required permission guard."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    evidence=ev,
                    assessment=(
                        "Any third-party app installed on the device can query, insert, update,"
                        "or delete data"
                        "in this content provider. If input is improperly sanitized, this can"
                        "lead to SQL injection"
                        "or arbitrary local file disclosure."
                    ),
                    limitations=[
                        "Publicly accessible search suggestion or sharing providers may"
                        "intentionally remain unprotected."
                    ],
                    references=[
                        "CWE-926: Improper Export of Android Application Components",
                        "CWE-89: SQL Injection",
                    ],
                    tags=["exported_component", "provider", "vulnerability"],
                )
            )

        # 2. Exported Services without permissions
        services = index.components.get("services", [])
        unprotected_services = [
            s for s in services if s.get("exported", False) and not s.get("permission")
        ]

        if unprotected_services:
            ev = [
                Evidence(
                    description=f"Exported service lacking permission: {s.get('name')}",
                    location=f"manifest:service:{s.get('name')}",
                    snippet=f"Service: {s.get('name')} (exported=true, permission=None)",
                )
                for s in unprotected_services[:5]
            ]
            findings.append(
                SecurityFinding(
                    id="SEC-VULN-EXPORTED-SERVICE",
                    category="exported_component",
                    title="Exported Service Component Lacks Permission Protection",
                    description=(
                        f"Found {len(unprotected_services)} Service(s) exported without "
                        f"an android:permission attribute."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    evidence=ev,
                    assessment=(
                        "Exported services without permissions can be started or bound to by any"
                        "application"
                        "on the device, potentially triggering unintended background tasks or"
                        "state modifications."
                    ),
                    limitations=[
                        "Services handling public system actions (e.g. Firebase messaging) are"
                        "designed to be exported."
                    ],
                    references=["CWE-926: Improper Export of Android Application Components"],
                    tags=["exported_component", "service", "vulnerability"],
                )
            )

        # 3. Exported Broadcast Receivers without permissions
        receivers = index.components.get("receivers", [])
        unprotected_receivers = [
            r for r in receivers if r.get("exported", False) and not r.get("permission")
        ]

        if unprotected_receivers:
            ev = [
                Evidence(
                    description=f"Exported broadcast receiver lacking permission: {r.get('name')}",
                    location=f"manifest:receiver:{r.get('name')}",
                    snippet=f"Receiver: {r.get('name')} (exported=true, permission=None)",
                )
                for r in unprotected_receivers[:5]
            ]
            findings.append(
                SecurityFinding(
                    id="SEC-VULN-EXPORTED-RECEIVER",
                    category="exported_component",
                    title="Exported Broadcast Receiver Lacks Permission Protection",
                    description=(
                        f"Found {len(unprotected_receivers)} Broadcast Receiver(s) declared with "
                        f"android:exported='true' without permission constraints."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    evidence=ev,
                    assessment=(
                        "Any application on the device can send broadcast intents to this"
                        "receiver,"
                        "potentially triggering internal workflows with forged parameters."
                    ),
                    limitations=[
                        "Receivers listening to system broadcasts (e.g. connectivity changes)"
                        "must be exported."
                    ],
                    references=["CWE-926: Improper Export of Android Application Components"],
                    tags=["exported_component", "receiver", "vulnerability"],
                )
            )

        return sorted(findings, key=lambda f: f.id)
