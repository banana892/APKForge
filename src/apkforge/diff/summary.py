"""Summary engine — aggregates quantitative metrics into a high-level diff overview."""

from __future__ import annotations

from typing import TYPE_CHECKING

from apkforge.diff.models import DiffSummary

if TYPE_CHECKING:
    from apkforge.diff.models import (
        CertificateDiff,
        ComponentDiff,
        DEXDiff,
        FileDiff,
        NativeDiff,
        NetworkDiff,
        PermissionDiff,
    )

__all__ = ["SummaryEngine"]


class SummaryEngine:
    """Computes concise summary metrics across all diff categories."""

    def build_summary(
        self,
        file_diff: FileDiff,
        perm_diff: PermissionDiff,
        comp_diff: ComponentDiff,
        dex_diff: DEXDiff,
        nat_diff: NativeDiff,
        net_diff: NetworkDiff,
        cert_diff: CertificateDiff,
    ) -> DiffSummary:
        """Aggregate counts from actual diff data into DiffSummary."""
        perms_add = len(perm_diff.added)
        perms_rem = len(perm_diff.removed)

        comps_add = comp_diff.total_added
        comps_rem = comp_diff.total_removed
        comps_mod = comp_diff.total_modified

        dex_add = len(dex_diff.dex_files_added)
        dex_rem = len(dex_diff.dex_files_removed)
        dex_mod = len(dex_diff.dex_files_modified)

        cls_add = len(dex_diff.classes_added)
        cls_rem = len(dex_diff.classes_removed)
        cls_mod = len(dex_diff.classes_modified)

        nat_add = len(nat_diff.libraries_added)
        nat_rem = len(nat_diff.libraries_removed)
        nat_mod = len(nat_diff.libraries_modified)

        dom_add = len(net_diff.domains_added)
        dom_rem = len(net_diff.domains_removed)

        url_add = len(net_diff.urls_added)
        url_rem = len(net_diff.urls_removed)

        f_add = file_diff.total_added
        f_rem = file_diff.total_removed
        f_mod = file_diff.total_modified

        cert_status = cert_diff.status

        # Build clean summary text lines
        text_lines: list[str] = []

        # Additions
        if perms_add > 0:
            text_lines.append(f"+ {perms_add} permission{'s' if perms_add != 1 else ''}")
        if comps_add > 0:
            text_lines.append(f"+ {comps_add} component{'s' if comps_add != 1 else ''}")
        if dex_add > 0:
            text_lines.append(f"+ {dex_add} DEX file{'s' if dex_add != 1 else ''}")
        if cls_add > 0:
            text_lines.append(f"+ {cls_add} class{'es' if cls_add != 1 else ''}")
        if nat_add > 0:
            text_lines.append(f"+ {nat_add} native librar{'ies' if nat_add != 1 else 'y'}")
        if dom_add > 0:
            text_lines.append(f"+ {dom_add} domain{'s' if dom_add != 1 else ''}")
        if url_add > 0:
            text_lines.append(f"+ {url_add} URL{'s' if url_add != 1 else ''}")

        # Removals
        if perms_rem > 0:
            text_lines.append(f"- {perms_rem} permission{'s' if perms_rem != 1 else ''}")
        if comps_rem > 0:
            text_lines.append(f"- {comps_rem} component{'s' if comps_rem != 1 else ''}")
        if dex_rem > 0:
            text_lines.append(f"- {dex_rem} DEX file{'s' if dex_rem != 1 else ''}")
        if cls_rem > 0:
            text_lines.append(f"- {cls_rem} class{'es' if cls_rem != 1 else ''}")
        if nat_rem > 0:
            text_lines.append(f"- {nat_rem} native librar{'ies' if nat_rem != 1 else 'y'}")
        if dom_rem > 0:
            text_lines.append(f"- {dom_rem} domain{'s' if dom_rem != 1 else ''}")
        if url_rem > 0:
            text_lines.append(f"- {url_rem} URL{'s' if url_rem != 1 else ''}")

        # Modifications
        if comps_mod > 0:
            text_lines.append(f"~ {comps_mod} component{'s' if comps_mod != 1 else ''} modified")
        if cls_mod > 0:
            text_lines.append(f"~ {cls_mod} class{'es' if cls_mod != 1 else ''} modified")
        if f_mod > 0:
            text_lines.append(f"~ {f_mod} file{'s' if f_mod != 1 else ''} modified")

        # Certificate status
        text_lines.append(f"Certificate: {cert_status}")

        return DiffSummary(
            permissions_added=perms_add,
            permissions_removed=perms_rem,
            components_added=comps_add,
            components_removed=comps_rem,
            components_modified=comps_mod,
            dex_files_added=dex_add,
            dex_files_removed=dex_rem,
            dex_files_modified=dex_mod,
            classes_added=cls_add,
            classes_removed=cls_rem,
            classes_modified=cls_mod,
            native_libraries_added=nat_add,
            native_libraries_removed=nat_rem,
            native_libraries_modified=nat_mod,
            domains_added=dom_add,
            domains_removed=dom_rem,
            urls_added=url_add,
            urls_removed=url_rem,
            files_added=f_add,
            files_removed=f_rem,
            files_modified=f_mod,
            certificate_status=cert_status,
            text_lines=text_lines,
        )
