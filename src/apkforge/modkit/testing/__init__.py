"""Reference ModKit (``test-modkit``) - APKForge's own deterministic test fixture.

It exists so the generic H.7 framework can be tested end to end without any
third-party tool. It is never registered unless explicitly enabled
(``APKFORGE_ENABLE_TEST_MODKIT=1`` or a ``[modkits.test-modkit]`` configuration
entry) and reports ``trust=TEST_ONLY``. It must never be used in production.
"""

from __future__ import annotations

from apkforge.modkit.testing.adapter import (
    TEST_MODKIT_ID,
    TOOL_PATH,
    TestModKitAdapter,
)
from apkforge.modkit.testing.tool import MARKER_ENTRY, SCENARIOS, VERSION

__all__ = [
    "MARKER_ENTRY",
    "SCENARIOS",
    "TEST_MODKIT_ID",
    "TOOL_PATH",
    "VERSION",
    "TestModKitAdapter",
]
