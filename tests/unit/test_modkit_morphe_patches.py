"""Phase H.8.2 - Morphe patch bundle discovery: text parser.

Fixture text is the real ``list-patches --with-packages --with-versions`` output
captured from the live MorpheApp/morphe-patches v2.0.0 bundle (including the one
real quirk: the first ``Index: 0`` comes out merged as ``INFO: Index: 0``).
"""

from __future__ import annotations

from apkforge.modkit.morphe.patches import parse_patch_listing

_SAMPLE = """\
INFO: Morphe data root: /x/morphe-data (JAR-adjacent)
INFO: GitHub: fetching patches-bundle.json from https://raw.githubusercontent.com/x
INFO: Resolved patches (v2.0.0) at /x/morphe-data/patches/v2.0.0__patches-2.0.0.mpp
INFO: Index: 0
Name: Clone app
Description: Changes the app package name to allow installing the same app multiple times.
Enabled: false

Index: 1
Name: Hide ads
Description: Adds options to hide fullscreen ads.
Enabled: true
Compatible packages:
\tPackage name: com.google.android.apps.youtube.music
\tCompatible versions:
\t\t9.30.53
\t\t9.20.53

Index: 2
Name: Video quality
Description: Adds options to set default video qualities.
Enabled: true
Compatible packages:
\tPackage name: com.google.android.youtube
\tCompatible versions:
\t\t21.30.216
"""


def test_parses_index_name_description_enabled() -> None:
    listing = parse_patch_listing("bundle.mpp", _SAMPLE)
    assert [p.index for p in listing.patches] == [0, 1, 2]
    p0 = listing.patches[0]
    assert p0.name == "Clone app" and p0.enabled is False
    assert p0.description.startswith("Changes the app package name")


def test_handles_the_info_index_0_merge_quirk() -> None:
    # The fixture's first line is "INFO: Index: 0", not "Index: 0": a real quirk of
    # Morphe's own output (its last startup log line has no trailing newline).
    listing = parse_patch_listing("bundle.mpp", _SAMPLE)
    assert listing.patches[0].index == 0


def test_universal_patch_has_no_compatibility() -> None:
    listing = parse_patch_listing("bundle.mpp", _SAMPLE)
    assert listing.patches[0].compatible == ()


def test_package_specific_patch_has_compatibility() -> None:
    listing = parse_patch_listing("bundle.mpp", _SAMPLE)
    hide_ads = listing.patches[1]
    assert len(hide_ads.compatible) == 1
    compat = hide_ads.compatible[0]
    assert compat.package == "com.google.android.apps.youtube.music"
    assert compat.versions == ("9.30.53", "9.20.53")


def test_resolved_version_and_path_captured_from_log() -> None:
    listing = parse_patch_listing("https://github.com/MorpheApp/morphe-patches", _SAMPLE)
    assert listing.resolved_version == "v2.0.0"
    assert listing.resolved_path == "/x/morphe-data/patches/v2.0.0__patches-2.0.0.mpp"


def test_local_file_has_no_resolved_version() -> None:
    text = "Index: 0\nName: Clone app\nDescription: d\nEnabled: false\n"
    listing = parse_patch_listing("local.mpp", text)
    assert listing.resolved_version is None and listing.resolved_path is None


def test_empty_output_yields_no_patches() -> None:
    listing = parse_patch_listing("bundle.mpp", "")
    assert listing.patches == ()
