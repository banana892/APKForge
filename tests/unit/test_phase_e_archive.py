"""Phase E1: archive inventory and raw diff."""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

import pytest

from apkforge.diff.archive import (
    ArchiveInventory,
    EntryKind,
    RawChange,
    classify_archive_path,
    raw_diff,
)


def _zip(
    path: Path, entries: dict[str, bytes], *, date: tuple[int, ...] = (2020, 1, 1, 0, 0, 0)
) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        for name, data in entries.items():
            info = zipfile.ZipInfo(name, date_time=date)  # type: ignore[arg-type]
            z.writestr(info, data)
    return path


BASE = {
    "AndroidManifest.xml": b"manifest",
    "classes.dex": b"dex\n035\x00one",
    "classes2.dex": b"dex\n035\x00two",
    "resources.arsc": b"\x02\x00table",
    "res/layout/main.xml": b"layout",
    "assets/a/b/c/deep.bin": b"deep",
    "lib/arm64-v8a/libx.so": b"\x7fELFarm64",
    "lib/x86_64/libx.so": b"\x7fELFx86",
    "META-INF/MANIFEST.MF": b"mf",
    "META-INF/CERT.SF": b"sf",
    "META-INF/CERT.RSA": b"rsa",
    "META-INF/androidx.core_core.version": b"1.0",
    "kotlin/collections/collections.kotlin_builtins": b"k",
}


class TestClassify:
    @pytest.mark.parametrize(
        ("path", "kind"),
        [
            ("AndroidManifest.xml", EntryKind.MANIFEST),
            ("classes.dex", EntryKind.DEX),
            ("classes17.dex", EntryKind.DEX),
            ("assets/classes.dex", EntryKind.ASSET),  # nested dex is not the app's code
            ("resources.arsc", EntryKind.RESOURCE_TABLE),
            ("res/drawable-xxhdpi/icon.png", EntryKind.RESOURCE),
            ("assets/web/index.html", EntryKind.ASSET),
            ("lib/armeabi-v7a/libfoo.so", EntryKind.NATIVE_LIBRARY),
            ("lib/armeabi-v7a/readme.txt", EntryKind.LIB_OTHER),
            ("lib/libtop.so", EntryKind.LIB_OTHER),
            ("META-INF/MANIFEST.MF", EntryKind.SIGNATURE),
            ("META-INF/KEY0.EC", EntryKind.SIGNATURE),
            ("META-INF/services/x.Y", EntryKind.META_INF),
            ("stamp-cert-sha256", EntryKind.SIGNING_METADATA),
            ("assets/payload.apk", EntryKind.EMBEDDED_ARCHIVE),
            ("assets/split_config.arm64_v8a.apk", EntryKind.EMBEDDED_ARCHIVE),
            ("lib/tool.jar", EntryKind.EMBEDDED_ARCHIVE),
            ("DebugProbesKt.bin", EntryKind.OTHER),
        ],
    )
    def test_kinds(self, path: str, kind: EntryKind) -> None:
        assert classify_archive_path(path) == kind


class TestInventory:
    def test_multi_dex_abis_nested_and_signature(self, tmp_path: Path) -> None:
        inv = ArchiveInventory.from_apk(_zip(tmp_path / "a.apk", BASE))
        s = inv.summary()
        assert s["dex_files"] == ["classes.dex", "classes2.dex"]
        assert s["abis"] == ["arm64-v8a", "x86_64"]
        assert inv.entries["assets/a/b/c/deep.bin"].kind == EntryKind.ASSET
        assert s["by_kind"]["signature"] == 3
        assert s["by_kind"]["meta_inf"] == 1
        e = inv.entries["classes.dex"]
        assert e.sha256 == hashlib.sha256(BASE["classes.dex"]).hexdigest()
        assert e.size == len(BASE["classes.dex"])

    def test_unusual_and_duplicate_paths_are_recorded(self, tmp_path: Path) -> None:
        p = tmp_path / "odd.apk"
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("AndroidManifest.xml", b"m")
            z.writestr("assets/../evil.txt", b"x")
            with pytest.warns(UserWarning):
                z.writestr("assets/dup.txt", b"1")
                z.writestr("assets/dup.txt", b"2")
        inv = ArchiveInventory.from_apk(p)
        assert inv.duplicate_names == ["assets/dup.txt"]
        assert "dot segment" in inv.entries["assets/../evil.txt"].notes
        assert inv.summary()["unusual_paths"] == ["assets/../evil.txt"]

    def test_not_a_zip_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "x.apk"
        p.write_bytes(b"not a zip")
        with pytest.raises(zipfile.BadZipFile):
            ArchiveInventory.from_apk(p)


class TestRawDiff:
    def test_added_removed_modified_unchanged(self, tmp_path: Path) -> None:
        a = _zip(tmp_path / "a.apk", BASE)
        changed = dict(BASE)
        del changed["META-INF/CERT.RSA"]
        changed["META-INF/APKFORGE.RSA"] = b"new"
        changed["classes.dex"] = b"dex\n035\x00ONE"
        b = _zip(tmp_path / "b.apk", changed)
        d = raw_diff(ArchiveInventory.from_apk(a), ArchiveInventory.from_apk(b))
        assert d.counts == {"added": 1, "removed": 1, "modified": 1, "unchanged": len(BASE) - 2}
        m = d.entry("classes.dex")
        assert m is not None and m.change == RawChange.MODIFIED
        assert m.sha256_before != m.sha256_after and m.size_before == m.size_after
        assert d.entry("META-INF/APKFORGE.RSA").change == RawChange.ADDED  # type: ignore[union-attr]
        assert d.entry("META-INF/CERT.RSA").change == RawChange.REMOVED  # type: ignore[union-attr]
        assert d.counts_by_kind["dex"] == {"modified": 1, "unchanged": 1}

    def test_no_pairing_or_normalisation(self, tmp_path: Path) -> None:
        """A move with identical content is removed + added at the raw layer."""
        a = _zip(tmp_path / "a.apk", {"res/Ab.xml": b"same"})
        b = _zip(tmp_path / "b.apk", {"res/layout/main.xml": b"same"})
        d = raw_diff(ArchiveInventory.from_apk(a), ArchiveInventory.from_apk(b))
        assert d.counts["added"] == 1 and d.counts["removed"] == 1

    def test_metadata_only_difference_is_not_a_content_change(self, tmp_path: Path) -> None:
        """Observed rebuild behaviour: timestamps differ between rebuilds, content does not."""
        a = _zip(tmp_path / "a.apk", BASE, date=(2020, 1, 1, 0, 0, 0))
        b = _zip(tmp_path / "b.apk", BASE, date=(2024, 6, 1, 12, 0, 0))
        d = raw_diff(ArchiveInventory.from_apk(a), ArchiveInventory.from_apk(b))
        assert d.counts["unchanged"] == len(BASE)
        assert d.metadata_only_changes == len(BASE)
        assert not d.changed()
