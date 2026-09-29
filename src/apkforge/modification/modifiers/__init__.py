"""APKForge Phase 7 Modification Framework — Built-in Modifiers.

This package provides the Modifier protocol, the ModifierRegistry,
the ModificationContext (execution-time), and the built-in modifier
implementations.
"""

from __future__ import annotations

from apkforge.modification.modifiers.base import (
    ModificationExecutionContext,
    ModificationResult,
    ModificationStepResult,
    Modifier,
    StepStatus,
)
from apkforge.modification.modifiers.registry import ModifierRegistry

__all__ = [
    "ModificationExecutionContext",
    "ModificationResult",
    "ModificationStepResult",
    "Modifier",
    "ModifierRegistry",
    "StepStatus",
]
