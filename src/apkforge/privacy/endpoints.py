"""Network endpoint classification, provenance preservation, and SDK mapping."""

from __future__ import annotations

import urllib.parse
from typing import TYPE_CHECKING

from apkforge.core.models import Evidence
from apkforge.privacy.models import (
    ClassifiedEndpoint,
    EndpointCategory,
    EndpointResult,
)

if TYPE_CHECKING:
    from apkforge.inspection.models import InspectionResult
    from apkforge.privacy.models import DetectedSDK
    from apkforge.privacy.rules import EvidenceIndex, RuleEngine


class EndpointAnalyzer:
    """Classifies network endpoints, establishes provenance, and correlates with SDKs."""

    def __init__(self, rule_engine: RuleEngine) -> None:
        self._engine = rule_engine

    def analyze(
        self,
        inspection: InspectionResult,
        index: EvidenceIndex,
        detected_sdks: list[DetectedSDK] | None = None,
    ) -> EndpointResult:
        """Classify URLs and domains from Phase 2 inspection."""
        pkg_name = index.package_name or ""
        first_party_candidates = self._extract_first_party_candidates(pkg_name)

        classified: list[ClassifiedEndpoint] = []
        first_party_domains: set[str] = set()
        third_party_domains: set[str] = set()
        by_category: dict[str, set[str]] = {}

        network = inspection.network

        # 1. Process domains
        domains: set[str] = set()
        if network and network.domains:
            for d_ref in network.domains:
                domains.add(d_ref.domain.strip().lower())
        domains.update(d.strip().lower() for d in index.domains)

        for dom in sorted(domains):
            if not dom:
                continue

            is_first_party = self._is_domain_first_party(dom, first_party_candidates)
            if is_first_party:
                category = EndpointCategory.FIRST_PARTY
                purpose = "Application first-party service endpoint"
                sdk_name = None
                first_party_domains.add(dom)
            else:
                category, purpose, sdk_name = self._engine.classify_domain(dom)
                third_party_domains.add(dom)

            by_category.setdefault(category.value, set()).add(dom)

            evidence_items = [
                Evidence(
                    description=f"Extracted domain: {dom}",
                    location=f"domain:{dom}",
                    snippet=f"Extracted domain: {dom}",
                )
            ]

            classified.append(
                ClassifiedEndpoint(
                    endpoint=dom,
                    domain=dom,
                    is_url=False,
                    category=category,
                    purpose=purpose,
                    associated_sdk=sdk_name,
                    is_first_party=is_first_party,
                    provenance=["network:extracted_domain"],
                    evidence=evidence_items,
                )
            )

        # 2. Process URLs with provenance
        if network and network.urls:
            for u_ref in network.urls:
                url_str = u_ref.url.strip()
                if not url_str:
                    continue

                dom = self._extract_domain_from_url(url_str)
                is_first_party = self._is_domain_first_party(dom, first_party_candidates)

                if is_first_party:
                    category = EndpointCategory.FIRST_PARTY
                    purpose = "Application first-party service endpoint"
                    sdk_name = None
                    first_party_domains.add(dom)
                else:
                    category, purpose, sdk_name = self._engine.classify_domain(dom)
                    if dom:
                        third_party_domains.add(dom)

                by_category.setdefault(category.value, set()).add(url_str)

                # Provenance from EvidenceSource
                prov_list: list[str] = []
                prov_str = "network:url"
                if hasattr(u_ref, "source") and u_ref.source:
                    src = u_ref.source
                    loc_parts = []
                    file_src = getattr(src, "file", None) or getattr(src, "file_path", None)
                    if file_src:
                        loc_parts.append(str(file_src))
                    if src.class_name:
                        loc_parts.append(src.class_name)
                    if src.method_name:
                        loc_parts.append(src.method_name)
                    prov_str = " -> ".join(loc_parts) if loc_parts else "network:url"
                    prov_list.append(prov_str)

                classified.append(
                    ClassifiedEndpoint(
                        endpoint=url_str,
                        domain=dom,
                        is_url=True,
                        category=category,
                        purpose=purpose,
                        associated_sdk=sdk_name,
                        is_first_party=is_first_party,
                        provenance=prov_list,
                        evidence=[
                            Evidence(
                                description=f"Extracted URL: {url_str}",
                                location=prov_str,
                                snippet=f"Extracted URL: {url_str}",
                            )
                        ],
                    )
                )

        # Correlate endpoints with detected SDKs
        if detected_sdks:
            for ep in classified:
                if not ep.associated_sdk:
                    for sdk in detected_sdks:
                        for sdk_ep in sdk.matched_endpoints:
                            is_match = ep.domain and (
                                ep.domain == sdk_ep or ep.domain.endswith("." + sdk_ep)
                            )
                            if is_match:
                                ep.associated_sdk = sdk.name
                                if ep.category == EndpointCategory.UNKNOWN:
                                    ep.category = self._engine._sdk_cat_to_endpoint_cat(
                                        sdk.category
                                    )
                                break

        # Sort deterministic results
        sorted_by_cat = {k: sorted(v) for k, v in sorted(by_category.items())}

        return EndpointResult(
            total_endpoints=len(classified),
            first_party_domains=sorted(first_party_domains),
            third_party_domains=sorted(third_party_domains),
            classified_endpoints=sorted(classified, key=lambda e: (e.is_url, e.endpoint)),
            by_category=sorted_by_cat,
        )

    def _extract_domain_from_url(self, url: str) -> str:
        """Parse host/domain from a URL safely."""
        try:
            parsed = urllib.parse.urlparse(url)
            netloc = parsed.netloc or ""
            return netloc.split(":")[0].strip().lower()
        except Exception:
            return ""

    def _extract_first_party_candidates(self, package_name: str) -> set[str]:
        """Derive candidate first-party domain roots from the package name."""
        candidates: set[str] = set()
        if not package_name:
            return candidates

        parts = package_name.lower().split(".")
        # Example: com.example.myapp -> example.com, myapp.com
        if len(parts) >= 2 and parts[0] in ("com", "org", "net", "io", "app", "dev"):
            candidates.add(f"{parts[1]}.{parts[0]}")
            if len(parts) >= 3:
                candidates.add(f"{parts[2]}.com")
        elif len(parts) >= 2:
            candidates.add(f"{parts[0]}.{parts[1]}")

        return candidates

    def _is_domain_first_party(self, domain: str, candidates: set[str]) -> bool:
        """Check if domain matches candidate first-party roots."""
        if not domain or not candidates:
            return False

        norm_d = domain.lower()
        return any(norm_d == c or norm_d.endswith("." + c) for c in candidates)
