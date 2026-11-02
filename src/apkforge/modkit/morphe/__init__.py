"""Morphe Desktop ModKit adapter (Phase H.8.1 — discovery and compatibility only).

Morphe Desktop (https://github.com/MorpheMods/morphe-desktop) is a third-party Java
CLI that drives the Morphe Patcher patching engine. H.8.1 adds only discovery and
compatibility checking: detecting the configured JAR, checking the Java runtime,
probing ``--version`` and reporting a supported version range. Patch bundle
discovery and execution (H.8.2/H.8.3) are not implemented yet: :class:`MorpheAdapter`
declares no capabilities or operations, so ``apkforge modkit run morphe`` always
fails with "unknown operation" until those stages land.
"""

from __future__ import annotations

from apkforge.modkit.morphe.adapter import MIN_JAVA_MAJOR, MORPHE_MODKIT_ID, MorpheAdapter

__all__ = ["MIN_JAVA_MAJOR", "MORPHE_MODKIT_ID", "MorpheAdapter"]
