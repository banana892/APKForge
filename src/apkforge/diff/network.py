"""Network differ — compares extracted URLs, domains, and IP addresses."""

from __future__ import annotations

from typing import TYPE_CHECKING

from apkforge.diff.models import NetworkDiff, URLDiffItem

if TYPE_CHECKING:
    from apkforge.inspection.models import InspectionResult, URLReference

__all__ = ["NetworkDiffer"]


class NetworkDiffer:
    """Compares statically extracted network indicators between two APK packages."""

    def diff(self, insp_a: InspectionResult, insp_b: InspectionResult) -> NetworkDiff:
        """Execute network comparison between Inspection A and Inspection B."""
        net_a = insp_a.network
        net_b = insp_b.network

        # 1. Compare URLs
        urls_a: dict[str, URLReference] = {
            u.url.strip(): u for u in (net_a.urls if net_a else []) if u.url
        }
        urls_b: dict[str, URLReference] = {
            u.url.strip(): u for u in (net_b.urls if net_b else []) if u.url
        }

        urls_a_set = set(urls_a.keys())
        urls_b_set = set(urls_b.keys())

        urls_added: list[URLDiffItem] = []
        for u_str in sorted(urls_b_set - urls_a_set):
            ref = urls_b[u_str]
            src_file = ref.source.file if ref.source else None
            src_class = ref.source.class_name if ref.source else None
            src_method = ref.source.method_name if ref.source else None
            urls_added.append(
                URLDiffItem(
                    url=u_str,
                    source_file=src_file,
                    source_class=src_class,
                    source_method=src_method,
                )
            )

        urls_removed: list[URLDiffItem] = []
        for u_str in sorted(urls_a_set - urls_b_set):
            ref = urls_a[u_str]
            src_file = ref.source.file if ref.source else None
            src_class = ref.source.class_name if ref.source else None
            src_method = ref.source.method_name if ref.source else None
            urls_removed.append(
                URLDiffItem(
                    url=u_str,
                    source_file=src_file,
                    source_class=src_class,
                    source_method=src_method,
                )
            )

        urls_unchanged_count = len(urls_a_set & urls_b_set)

        # 2. Compare Domains
        doms_a = {d.domain.strip().lower() for d in (net_a.domains if net_a else []) if d.domain}
        doms_b = {d.domain.strip().lower() for d in (net_b.domains if net_b else []) if d.domain}

        domains_added = sorted(doms_b - doms_a)
        domains_removed = sorted(doms_a - doms_b)
        domains_unchanged_count = len(doms_a & doms_b)

        # 3. Compare IP Addresses
        ips_a = {ip.address.strip() for ip in (net_a.ip_addresses if net_a else []) if ip.address}
        ips_b = {ip.address.strip() for ip in (net_b.ip_addresses if net_b else []) if ip.address}

        ips_added = sorted(ips_b - ips_a)
        ips_removed = sorted(ips_a - ips_b)
        ips_unchanged_count = len(ips_a & ips_b)

        return NetworkDiff(
            urls_added=urls_added,
            urls_removed=urls_removed,
            urls_unchanged_count=urls_unchanged_count,
            domains_added=domains_added,
            domains_removed=domains_removed,
            domains_unchanged_count=domains_unchanged_count,
            ips_added=ips_added,
            ips_removed=ips_removed,
            ips_unchanged_count=ips_unchanged_count,
        )
