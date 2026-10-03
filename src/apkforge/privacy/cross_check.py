"""Cross-check and reconciliation between Phase F Privacy findings and Phase B Security findings.

Compares findings across analyzers without rewriting Phase-B verdicts, identifying:
1. Overlapping findings
2. Findings new to Phase F
3. Findings whose evidence becomes stronger
4. Findings whose evidence is incomplete/partial
5. Disagreements and discrepancies with technical explanations preserving both pieces of evidence.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from apkforge.privacy.models import EvidenceState

if TYPE_CHECKING:
    from apkforge.privacy.models import PrivacyResult
    from apkforge.security.models import SecurityResult


class DiscrepancyItem(BaseModel):
    """Detailed record of a discrepancy between security and privacy analyzers."""

    category: str
    privacy_evidence: str
    security_evidence: str
    explanation: str


class PhaseBComparisonResult(BaseModel):
    """Reconciliation and comparison report between Phase F and Phase B."""

    overlapping_findings: list[dict[str, Any]] = Field(default_factory=list)
    new_privacy_findings: list[dict[str, Any]] = Field(default_factory=list)
    security_only_findings: list[dict[str, Any]] = Field(default_factory=list)
    strengthened_findings: list[dict[str, Any]] = Field(default_factory=list)
    incomplete_evidence_findings: list[dict[str, Any]] = Field(default_factory=list)
    discrepancies: list[DiscrepancyItem] = Field(default_factory=list)

    def to_markdown(self) -> str:
        """Render markdown summary of cross-check comparison."""
        lines = [
            "# Phase F Privacy vs Phase B Security Cross-Check",
            "",
            f"- Overlapping Findings: {len(self.overlapping_findings)}",
            f"- New Phase F Privacy Findings: {len(self.new_privacy_findings)}",
            f"- Security-Only Findings: {len(self.security_only_findings)}",
            f"- Strengthened Findings: {len(self.strengthened_findings)}",
            f"- Incomplete / Partial Findings: {len(self.incomplete_evidence_findings)}",
            f"- Discrepancies Identified: {len(self.discrepancies)}",
            "",
            "## 1. Overlapping Findings",
        ]
        for item in self.overlapping_findings:
            lines.append(
                f"- **{item.get('topic', 'General')}**: Privacy `[{item.get('privacy_id')}]` "
                f"<-> Security `[{item.get('security_id')}]`"
            )

        lines.extend(["", "## 2. New Phase F Findings (Trackers, Endpoints, Permissions)"])
        for item in self.new_privacy_findings[:15]:
            lines.append(f"- `[{item.get('id')}]` ({item.get('category')}): {item.get('title')}")
        if len(self.new_privacy_findings) > 15:
            lines.append(f"- ... and {len(self.new_privacy_findings) - 15} more")

        lines.extend(["", "## 3. Strengthened Findings"])
        for item in self.strengthened_findings:
            lines.append(f"- **{item.get('topic')}**: {item.get('reason')}")

        lines.extend(["", "## 4. Incomplete / Partial Analysis"])
        for item in self.incomplete_evidence_findings:
            lines.append(f"- `[{item.get('id')}]`: {item.get('limitation')}")

        lines.extend(["", "## 5. Discrepancies & Explanations"])
        if not self.discrepancies:
            lines.append("No contradictory evidence found between analyzers.")
        for disc in self.discrepancies:
            lines.append(f"### {disc.category}")
            lines.append(f"- **Privacy Analyzer Observation**: {disc.privacy_evidence}")
            lines.append(f"- **Security Analyzer Observation**: {disc.security_evidence}")
            lines.append(f"- **Explanation**: {disc.explanation}")

        return "\n".join(lines)


def compare_privacy_with_security(
    privacy_res: PrivacyResult,
    security_res: SecurityResult,
) -> PhaseBComparisonResult:
    """Execute cross-check between privacy and security analysis results."""
    overlapping: list[dict[str, Any]] = []
    new_privacy: list[dict[str, Any]] = []
    sec_only: list[dict[str, Any]] = []
    strengthened: list[dict[str, Any]] = []
    incomplete: list[dict[str, Any]] = []
    discrepancies: list[DiscrepancyItem] = []

    matched_sec_ids: set[str] = set()

    for pf in privacy_res.findings:
        is_overlap = False
        p_cat = pf.category.lower()
        p_title = pf.title.lower()

        # Check for incomplete / partial
        if pf.evidence_state in (EvidenceState.PARTIAL, EvidenceState.UNKNOWN):
            incomplete.append(
                {
                    "id": pf.id,
                    "title": pf.title,
                    "state": pf.evidence_state.value,
                    "limitation": pf.limitations[0] if pf.limitations else "Partial evidence",
                }
            )

        for sf in security_res.findings:
            s_cat = sf.category.lower()
            s_title = sf.title.lower()

            # Correlate topics: boot / persistence, device ID, location, camera, mic, dynamic code
            topic = None
            if "boot" in p_title and "boot" in s_title:
                topic = "Boot Persistence"
            elif "identifier" in p_cat and ("identifier" in s_title or "phone" in s_title):
                topic = "Device Identifiers"
            elif "location" in p_cat and "location" in s_title:
                topic = "Location Capability"
            elif "camera" in p_cat and "camera" in s_title:
                topic = "Camera Access"
            elif ("audio" in p_cat or "microphone" in p_cat) and (
                "audio" in s_title or "microphone" in s_title or "record" in s_title
            ):
                topic = "Audio Recording"
            elif "dynamic" in p_cat and "dynamic" in s_cat:
                topic = "Dynamic Code Loading"

            if topic:
                is_overlap = True
                matched_sec_ids.add(sf.id)
                overlapping.append(
                    {
                        "topic": topic,
                        "privacy_id": pf.id,
                        "security_id": sf.id,
                        "privacy_title": pf.title,
                        "security_title": sf.title,
                    }
                )

                # Check if evidence was strengthened by dual observation
                if pf.evidence_locations and sf.evidence:
                    strengthened.append(
                        {
                            "topic": topic,
                            "privacy_id": pf.id,
                            "security_id": sf.id,
                            "reason": (
                                f"Corroborated by both Phase B ({len(sf.evidence)} items) "
                                f"and Phase F ({len(pf.evidence_locations)} locations)."
                            ),
                        }
                    )
                break

        if not is_overlap:
            new_privacy.append(
                {
                    "id": pf.id,
                    "category": pf.category,
                    "title": pf.title,
                    "evidence_state": pf.evidence_state.value,
                }
            )

    for sf in security_res.findings:
        if sf.id not in matched_sec_ids:
            sec_only.append(
                {
                    "id": sf.id,
                    "category": sf.category,
                    "title": sf.title,
                    "severity": sf.severity.value,
                }
            )

    # Discrepancy checks:
    # 1. Tracker/Ad classification vs Spyware/Malware labeling
    for sdk in privacy_res.all_detected_sdks:
        for sf in security_res.findings:
            name_match = (
                sdk.name.lower() in sf.title.lower() or sdk.name.lower() in sf.description.lower()
            )
            is_malware_label = "spyware" in sf.category.lower() or "malware" in sf.category.lower()
            if name_match and is_malware_label:
                discrepancies.append(
                    DiscrepancyItem(
                        category=f"SDK Classification: {sdk.name}",
                        privacy_evidence=(
                            f"Phase F categorizes {sdk.name} as third-party "
                            f"{sdk.category.value} SDK with confidence {sdk.confidence.value}."
                        ),
                        security_evidence=(
                            f"Phase B flagged {sf.id} under {sf.category} ({sf.severity.value})."
                        ),
                        explanation=(
                            "Phase F adheres to the strict privacy principle that third-party SDK "
                            "presence does not prove malicious intent or active user surveillance "
                            "without runtime proof."
                        ),
                    )
                )

    # 2. Declared permission vs Code reference
    for usage in privacy_res.permissions.usage_details:
        if usage.usage_status.value == "declared_only":
            for sf in security_res.findings:
                if usage.permission in sf.description or usage.permission in sf.title:
                    discrepancies.append(
                        DiscrepancyItem(
                            category=f"Permission Usage: {usage.permission}",
                            privacy_evidence=(
                                "Phase F found no static framework API calls or component "
                                f"references for {usage.permission} (DECLARED_ONLY)."
                            ),
                            security_evidence=(
                                f"Phase B noted {sf.id} based on permission presence."
                            ),
                            explanation=(
                                "Phase B evaluates declared permission attack surface; "
                                "Phase F static correlation refines this by observing that the "
                                "permission capability is not referenced in application bytecode."
                            ),
                        )
                    )

    return PhaseBComparisonResult(
        overlapping_findings=overlapping,
        new_privacy_findings=new_privacy,
        security_only_findings=sec_only,
        strengthened_findings=strengthened,
        incomplete_evidence_findings=incomplete,
        discrepancies=discrepancies,
    )
