"""Optional AI explanations of APKForge results (``apkforge explain``, the GUI "Explain")."""

from apkforge.ai.explain import (
    AIConfig,
    ExplainError,
    Explanation,
    compact_result,
    detect_kind,
    explain,
)

__all__ = [
    "AIConfig",
    "ExplainError",
    "Explanation",
    "compact_result",
    "detect_kind",
    "explain",
]
