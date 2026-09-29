"""Asset inspector — APK assets/ directory inventory.

Inspects the ``assets/`` directory, recording path, size, SHA-256,
MIME type, and Shannon entropy for each asset file.

Identifies potentially interesting files (DEX, JAR, APK, SO, archives,
encrypted-looking blobs) based on file signatures and entropy.

Does NOT execute or automatically unpack arbitrary content.
"""

from __future__ import annotations

import math
import mimetypes
import zipfile
from collections import Counter
from typing import TYPE_CHECKING

from apkforge.core.logging import get_logger
from apkforge.inspection.models import (
    AssetEntry,
    AssetInspection,
)
from apkforge.intake.hashing import compute_sha256

if TYPE_CHECKING:
    from pathlib import Path

    from apkforge.intake import AndroidPackage

__all__ = ["AssetInspector"]

_log = get_logger(__name__)

# Maximum asset size for full analysis (avoid loading huge blobs)
_MAX_ASSET_BYTES = 64 * 1024 * 1024  # 64 MiB


def _detect_mime_type(path: str, data: bytes) -> str | None:
    """Detect MIME type from file extension and magic bytes."""
    # Try extension first
    mime, _ = mimetypes.guess_type(path)
    if mime:
        return mime

    # Magic byte detection
    if data[:4] == b"\x7fELF":
        return "application/x-elf"
    if data[:3] == b"dex":
        return "application/x-dex"
    if data[:4] == b"PK\x03\x04":
        return "application/zip"
    if data[:2] == b"\x1f\x8b":
        return "application/gzip"
    if data[:6] == b"7z\xbc\xaf\x27\x1c":
        return "application/x-7z-compressed"
    if data[:5] == b"\xfd7zXZ":
        return "application/x-xz"

    return None


def _compute_entropy(data: bytes) -> float:
    """Compute Shannon entropy of byte data (0.0 to 8.0)."""
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)
    entropy = 0.0

    for count in counts.values():
        if count > 0:
            prob = count / length
            entropy -= prob * math.log2(prob)

    return round(entropy, 4)


class AssetInspector:
    """Inspects the assets/ directory of an APK."""

    def inspect(
        self,
        apk_path: Path,
        package: AndroidPackage | None = None,
    ) -> tuple[AssetInspection, list[str]]:
        """Inspect all assets in the APK.

        Args:
            apk_path: Path to the APK file.
            package: Phase 1 AndroidPackage.

        Returns:
            Tuple of (AssetInspection, warnings).
        """
        warnings: list[str] = []
        result = AssetInspection()
        assets: list[AssetEntry] = []

        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue

                    if not info.filename.startswith("assets/"):
                        continue

                    sha256_val = None
                    mime = None
                    entropy = None

                    try:
                        if info.file_size <= _MAX_ASSET_BYTES:
                            data = zf.read(info.filename)
                            sha256_val = compute_sha256(data)
                            mime = _detect_mime_type(info.filename, data)
                            if len(data) >= 64:
                                entropy = _compute_entropy(data)
                        else:
                            warnings.append(
                                f"Asset '{info.filename}' too large ({info.file_size} bytes); "
                                f"skipping entropy/hash."
                            )
                    except Exception as exc:
                        warnings.append(f"Could not read asset '{info.filename}': {exc}")

                    assets.append(
                        AssetEntry(
                            path=info.filename,
                            size=info.file_size,
                            sha256=sha256_val,
                            mime_type=mime,
                            entropy=entropy,
                        )
                    )

        except (zipfile.BadZipFile, OSError) as exc:
            warnings.append(f"Could not open APK for asset inspection: {exc}")

        result.total_assets = len(assets)
        result.assets = assets

        return result, warnings
