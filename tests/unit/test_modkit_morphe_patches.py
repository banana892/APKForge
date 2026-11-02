"""Phase H.8.2/H.8.6 - Morphe patch bundle discovery: text parser.

Fixture text is the real ``list-patches --with-packages --with-versions`` output
captured from the live MorpheApp/morphe-patches v2.0.0 bundle (including the one
real quirk: the first ``Index: 0`` comes out merged as ``INFO: Index: 0``).
"""

from __future__ import annotations

from apkforge.modkit.morphe.patches import PatchOptionValue, parse_patch_listing

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


# -- H.8.6: --with-options --------------------------------------------------------

# Real "Clone app"/"Custom branding" shape with --with-options --with-packages
# --with-versions: a required String option with a single-line description and a
# possible value, two Boolean options with no description/possible values, then (a
# separate patch) a File option whose description is genuinely multi-line with
# inconsistent/no indentation - the actual reason options aren't parsed line-by-line -
# followed by a "Compatible packages:" section, which must still parse correctly.
_OPTIONS_SAMPLE = """\
Index: 0
Name: Clone app
Description: Changes the app package name to allow installing the same app multiple times.
Enabled: false
Options:
\tTitle: packageName
\tDescription: Package name to use for the cloned app.
\tRequired: true
\tKey: packageName
\tDefault: Default
\tPossible values:
\t\tDefault (Default)
\tType: String
\t
\tTitle: updatePermissions
\tRequired: false
\tKey: updatePermissions
\tDefault: true
\tType: Boolean
\t
\tTitle: updateProviders
\tRequired: false
\tKey: updateProviders
\tDefault: true
\tType: Boolean

Index: 1
Name: Custom branding
Description: Adds options to change the app icon and app name.
Enabled: true
Options:
\tTitle: appIcon
\tDescription:
\t            The app icon to use, including the notification icon.
\t
\t            'Automatic' uses the custom icon if one is provided.

\tRequired: false
\tKey: appIcon
\tPossible values:
\t\tnull (Automatic)
\t\toriginal (Original)
\tType: File

Compatible packages:
\tPackage name: com.google.android.apps.youtube.music
\tCompatible versions:
\t\t9.30.53
"""


def test_required_string_option_with_description_default_and_possible_value() -> None:
    listing = parse_patch_listing("bundle.mpp", _OPTIONS_SAMPLE)
    opt = listing.patches[0].options[0]
    assert opt.key == "packageName"
    assert opt.title == "packageName"
    assert opt.description == "Package name to use for the cloned app."
    assert opt.required is True
    assert opt.default == "Default"
    assert opt.type == "String"
    assert opt.possible_values == (PatchOptionValue(value="Default", label="Default"),)


def test_boolean_options_without_description_or_possible_values() -> None:
    listing = parse_patch_listing("bundle.mpp", _OPTIONS_SAMPLE)
    options = listing.patches[0].options
    assert len(options) == 3
    for opt in options[1:]:
        assert opt.description == ""
        assert opt.possible_values == ()
        assert opt.type == "Boolean"
        assert opt.default == "true"


def test_multiline_description_with_inconsistent_indentation() -> None:
    listing = parse_patch_listing("bundle.mpp", _OPTIONS_SAMPLE)
    appicon = listing.patches[1].options[0]
    assert "The app icon to use, including the notification icon." in appicon.description
    assert "'Automatic' uses the custom icon if one is provided." in appicon.description
    assert appicon.possible_values == (
        PatchOptionValue(value="null", label="Automatic"),
        PatchOptionValue(value="original", label="Original"),
    )


def test_compatible_packages_after_options_still_parses() -> None:
    listing = parse_patch_listing("bundle.mpp", _OPTIONS_SAMPLE)
    custom_branding = listing.patches[1]
    assert len(custom_branding.compatible) == 1
    assert custom_branding.compatible[0].package == "com.google.android.apps.youtube.music"
    assert custom_branding.compatible[0].versions == ("9.30.53",)


def test_patch_without_options_section_has_none() -> None:
    listing = parse_patch_listing("bundle.mpp", _SAMPLE)
    assert all(p.options == () for p in listing.patches)
