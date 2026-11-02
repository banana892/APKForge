"""Morphe Desktop ModKit adapter (Phase H.8.1 discovery/compatibility; H.8.2 patch
bundle discovery; H.8.3 patch selection and execution; H.8.4 keystore-based signing;
H.8.5 per-patch option pass-through; H.8.6 per-patch option discovery; H.8.7
build-tuning flags; H.8.8 remaining patch flags).

Morphe Desktop (https://github.com/MorpheApp/morphe-desktop) is a third-party Java
CLI that drives the Morphe Patcher patching engine. H.8.1 adds discovery and
compatibility checking: detecting the configured JAR, checking the Java runtime,
probing ``--version`` and reporting a supported version range. H.8.2 adds
:meth:`MorpheAdapter.list_patches`, a read-only query of a patch bundle's contents.
H.8.3 adds the ``patch`` operation: :class:`MorpheAdapter` now declares real
capabilities and operations, so ``apkforge modkit run morphe ... --operation patch``
drives the normal adapter contract (``build_command``/``execute``/``collect_output``).
H.8.4 adds optional keystore-based signing to that operation; the default stays
``--unsigned`` either way. H.8.5 adds the ``options`` parameter: comma-separated
``key=value`` pairs passed through to Morphe's own per-patch ``-O key=value``. H.8.6
adds ``with_options`` to :meth:`MorpheAdapter.list_patches`, parsing each patch's
``Options:`` metadata (key/title/description/required/default/type/possible values)
so H.8.5's option keys are discoverable through APKForge, not just Morphe's own CLI.
H.8.7 adds the ``striplibs``/``bytecode_mode``/``continue_on_error``/``validate``
parameters, passed straight through to Morphe's own same-named flags. H.8.8 adds
multiple ``--patches`` bundles, ``signer``, ``disable_purge``, ``verify_with_sdk`` and
the ``temporary_files_path`` config option.
"""

from __future__ import annotations

from apkforge.modkit.morphe.adapter import MIN_JAVA_MAJOR, MORPHE_MODKIT_ID, MorpheAdapter
from apkforge.modkit.morphe.patches import (
    PatchBundleListing,
    PatchCompatibility,
    PatchInfo,
    PatchOption,
    PatchOptionValue,
)

__all__ = [
    "MIN_JAVA_MAJOR",
    "MORPHE_MODKIT_ID",
    "MorpheAdapter",
    "PatchBundleListing",
    "PatchCompatibility",
    "PatchInfo",
    "PatchOption",
    "PatchOptionValue",
]
