"""Embedded differ — compares embedded APKs, DEX files, and executable payloads."""

from __future__ import annotations

from typing import TYPE_CHECKING

from apkforge.diff.models import EmbeddedDiff

if TYPE_CHECKING:
    from apkforge.inspection.models import InspectionResult

__all__ = ["EmbeddedDiffer"]


class EmbeddedDiffer:
    """Compares nested APKs, secondary DEX files, and executable payloads."""

    def diff(self, insp_a: InspectionResult, insp_b: InspectionResult) -> EmbeddedDiff:
        """Execute embedded file comparison between Inspection A and Inspection B."""
        emb_a = insp_a.embedded
        emb_b = insp_b.embedded

        # 1. Embedded APKs
        apks_a = {f.path for f in (emb_a.embedded_apks if emb_a else [])}
        apks_b = {f.path for f in (emb_b.embedded_apks if emb_b else [])}

        # 2. Embedded DEX
        dex_a = {f.path for f in (emb_a.embedded_dex if emb_a else [])}
        dex_b = {f.path for f in (emb_b.embedded_dex if emb_b else [])}

        # 3. Executables (ELF, scripts)
        exec_a = {f.path for f in (emb_a.executable_files if emb_a else [])}
        exec_b = {f.path for f in (emb_b.executable_files if emb_b else [])}

        return EmbeddedDiff(
            apks_added=sorted(apks_b - apks_a),
            apks_removed=sorted(apks_a - apks_b),
            dex_added=sorted(dex_b - dex_a),
            dex_removed=sorted(dex_a - dex_b),
            executables_added=sorted(exec_b - exec_a),
            executables_removed=sorted(exec_a - exec_b),
        )
