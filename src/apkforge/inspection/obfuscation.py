"""Obfuscation inspector — structural obfuscation indicators.

Produces quantitative indicators of obfuscation based on naming patterns.
This is a structural observation, NOT a malware verdict.

ProGuard/R8 obfuscation is standard practice for production Android apps.
These indicators support later analysis but do not alone establish malicious
intent.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from apkforge.core.logging import get_logger
from apkforge.inspection.models import (
    ObfuscationIndicators,
    ObfuscationInspection,
)

if TYPE_CHECKING:
    from apkforge.inspection.models import DEXInspection

__all__ = ["ObfuscationInspector"]

_log = get_logger(__name__)

# Thresholds
_SHORT_NAME_THRESHOLD = 2  # Characters
_OBFUSCATION_THRESHOLD_PCT = 50.0  # Percentage to suggest obfuscation
_SAMPLE_LIMIT = 10_000  # Max items to sample


def _extract_simple_name(full_name: str) -> str:
    """Extract the simple name from a fully-qualified name."""
    # "com.example.Foo" -> "Foo"
    if "." in full_name:
        return full_name.rsplit(".", 1)[-1]
    if "/" in full_name:
        return full_name.rsplit("/", 1)[-1]
    return full_name


def _is_generated_looking(name: str) -> bool:
    """Check if a name looks generated/obfuscated."""
    simple = _extract_simple_name(name)
    # Very short
    if len(simple) <= _SHORT_NAME_THRESHOLD:
        return True
    # All single letter + digits (e.g. "a1b2")
    if len(simple) <= 4 and all(c.isalnum() for c in simple):
        alpha = sum(1 for c in simple if c.isalpha())
        if alpha <= 2:
            return True
    return False


class ObfuscationInspector:
    """Detects structural indicators of code obfuscation.

    IMPORTANT: Obfuscation does NOT equal malicious intent.  These are
    quantitative observations only.
    """

    def inspect(
        self,
        dex_inspection: DEXInspection | None = None,
    ) -> tuple[ObfuscationInspection, list[str]]:
        """Analyse naming patterns in DEX classes, methods, and fields.

        Args:
            dex_inspection: DEX inspection result from the DEXInspector.

        Returns:
            Tuple of (ObfuscationInspection, warnings).
        """
        warnings: list[str] = []
        result = ObfuscationInspection()

        if dex_inspection is None:
            return result, warnings

        indicators = ObfuscationIndicators()

        # Sample class names
        all_classes = []
        for dex_file in dex_inspection.dex_files:
            all_classes.extend(dex_file.inventory.classes)
        class_names = [c.name for c in all_classes[:_SAMPLE_LIMIT]]

        # Filter out framework/library classes for a more meaningful sample
        app_classes = [
            n
            for n in class_names
            if not n.startswith(
                (
                    "android.",
                    "java.",
                    "javax.",
                    "kotlin.",
                    "kotlinx.",
                    "dalvik.",
                    "org.apache.",
                    "com.google.android.",
                    "androidx.",
                )
            )
        ]

        if app_classes:
            short_classes = sum(1 for n in app_classes if _is_generated_looking(n))
            indicators.short_class_name_pct = round((short_classes / len(app_classes)) * 100, 2)
            indicators.total_classes_sampled = len(app_classes)

        # Sample method names
        all_methods = []
        for dex_file in dex_inspection.dex_files:
            all_methods.extend(dex_file.inventory.methods)
        method_names = [
            m.name
            for m in all_methods[:_SAMPLE_LIMIT]
            if m.name
            not in (
                "<init>",
                "<clinit>",
                "toString",
                "hashCode",
                "equals",
                "valueOf",
                "values",
                "run",
                "get",
                "set",
            )
        ]

        if method_names:
            short_methods = sum(1 for n in method_names if len(n) <= _SHORT_NAME_THRESHOLD)
            indicators.short_method_name_pct = round((short_methods / len(method_names)) * 100, 2)
            indicators.total_methods_sampled = len(method_names)

        # Sample field names
        all_fields = []
        for dex_file in dex_inspection.dex_files:
            all_fields.extend(dex_file.inventory.fields)
        field_names = [f.name for f in all_fields[:_SAMPLE_LIMIT]]

        if field_names:
            short_fields = sum(1 for n in field_names if len(n) <= _SHORT_NAME_THRESHOLD)
            indicators.short_field_name_pct = round((short_fields / len(field_names)) * 100, 2)
            indicators.total_fields_sampled = len(field_names)

        # Build observations
        if indicators.total_classes_sampled > 0 and indicators.short_class_name_pct > 30:
            indicators.observations.append(
                f"{indicators.short_class_name_pct}% of {indicators.total_classes_sampled} "
                f"sampled app class names have ≤{_SHORT_NAME_THRESHOLD} characters."
            )

        if indicators.total_methods_sampled > 0 and indicators.short_method_name_pct > 30:
            indicators.observations.append(
                f"{indicators.short_method_name_pct}% of {indicators.total_methods_sampled} "
                f"sampled method names have ≤{_SHORT_NAME_THRESHOLD} characters."
            )

        if indicators.total_fields_sampled > 0 and indicators.short_field_name_pct > 30:
            indicators.observations.append(
                f"{indicators.short_field_name_pct}% of {indicators.total_fields_sampled} "
                f"sampled field names have ≤{_SHORT_NAME_THRESHOLD} characters."
            )

        result.indicators = indicators

        # Determine overall obfuscation likelihood (not a malware verdict)
        obfuscated_signals = 0
        if indicators.short_class_name_pct >= _OBFUSCATION_THRESHOLD_PCT:
            obfuscated_signals += 1
        if indicators.short_method_name_pct >= _OBFUSCATION_THRESHOLD_PCT:
            obfuscated_signals += 1
        if indicators.short_field_name_pct >= _OBFUSCATION_THRESHOLD_PCT:
            obfuscated_signals += 1

        result.is_likely_obfuscated = obfuscated_signals >= 2

        return result, warnings
