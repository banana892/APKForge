"""Focused regression tests for diff verification gap fixes (Phase B Step 4).

Covers:
1. ComponentDiffer: enabled state comparison (True->False, False->True, unchanged, across all component types).
2. DEX method-body verification: code_hash comparison, identical vs changed bytecode, abstract/native methods, added/removed.
3. Manifest resource-reference normalization: equivalent @7F... resource refs vs resolved literals, genuinely different values.
4. Rename / canonicalization noise rule: identical SHA-256 at different paths -> RENAMED, differing content -> separate REMOVED/ADDED.
"""

from pathlib import Path

import pytest

from apkforge.diff.components import ComponentDiffer
from apkforge.diff.dex import DEXDiffer
from apkforge.diff.files import FileDiffer
from apkforge.diff.manifest import ManifestDiffer, is_semantically_equivalent
from apkforge.diff.models import ChangeType
from apkforge.inspection.models import (
    ActivityInfo,
    ApplicationInfo,
    BroadcastReceiverInfo,
    ClassInfo,
    ContentProviderInfo,
    DEXClassInventory,
    DEXFileInspection,
    DEXInspection,
    InspectionResult,
    IntentFilterInfo,
    ManifestInspection,
    MethodInfo,
    ServiceInfo,
)
from apkforge.intake import AndroidPackage, FileCategory, InputFormat, PackageFile, PackageType


def _make_pkg(files: list[PackageFile]) -> AndroidPackage:
    return AndroidPackage(
        input_path=Path("dummy.apk"),
        package_type=PackageType.APK,
        input_format=InputFormat.SINGLE_APK,
        files=files,
    )


# ---------------------------------------------------------------------------
# 1. ComponentDiffer: enabled state comparison
# ---------------------------------------------------------------------------


class TestComponentDifferEnabled:
    """Tests for component enabled state comparison across all component types."""

    def test_receiver_enabled_true_to_false(self) -> None:
        """Receiver changed from enabled=True to enabled=False is detected as modified."""
        r_a = BroadcastReceiverInfo(name="com.example.MyReceiver", enabled=True, exported=True)
        r_b = BroadcastReceiverInfo(name="com.example.MyReceiver", enabled=False, exported=True)

        insp_a = InspectionResult(manifest=ManifestInspection(receivers=[r_a]))
        insp_b = InspectionResult(manifest=ManifestInspection(receivers=[r_b]))

        diff = ComponentDiffer().diff(insp_a, insp_b)

        assert diff.total_modified == 1
        assert diff.total_added == 0
        assert diff.total_removed == 0
        assert len(diff.receivers) == 1
        change = diff.receivers[0]
        assert change.change_type == ChangeType.MODIFIED
        assert change.enabled_before is True
        assert change.enabled_after is False
        assert change.details.get("enabled_before") is True
        assert change.details.get("enabled_after") is False

    def test_activity_enabled_false_to_true(self) -> None:
        """Activity changed from enabled=False to enabled=True is detected as modified."""
        a_a = ActivityInfo(name="com.example.MainActivity", enabled=False, exported=True)
        a_b = ActivityInfo(name="com.example.MainActivity", enabled=True, exported=True)

        insp_a = InspectionResult(manifest=ManifestInspection(activities=[a_a]))
        insp_b = InspectionResult(manifest=ManifestInspection(activities=[a_b]))

        diff = ComponentDiffer().diff(insp_a, insp_b)

        assert diff.total_modified == 1
        change = diff.activities[0]
        assert change.change_type == ChangeType.MODIFIED
        assert change.enabled_before is False
        assert change.enabled_after is True

    def test_service_enabled_unchanged_produces_no_modification(self) -> None:
        """Service with unchanged enabled state produces UNCHANGED change_type."""
        s_a = ServiceInfo(name="com.example.MyService", enabled=True, exported=False)
        s_b = ServiceInfo(name="com.example.MyService", enabled=True, exported=False)

        insp_a = InspectionResult(manifest=ManifestInspection(services=[s_a]))
        insp_b = InspectionResult(manifest=ManifestInspection(services=[s_b]))

        diff = ComponentDiffer().diff(insp_a, insp_b)

        assert diff.total_modified == 0
        assert diff.total_unchanged == 1
        assert diff.services[0].change_type == ChangeType.UNCHANGED
        assert diff.services[0].enabled_before is True
        assert diff.services[0].enabled_after is True

    def test_provider_enabled_and_authorities(self) -> None:
        """Provider enabled change and authorities change are tracked."""
        p_a = ContentProviderInfo(name="com.example.Provider", authorities="auth.a", enabled=True)
        p_b = ContentProviderInfo(name="com.example.Provider", authorities="auth.a", enabled=False)

        insp_a = InspectionResult(manifest=ManifestInspection(providers=[p_a]))
        insp_b = InspectionResult(manifest=ManifestInspection(providers=[p_b]))

        diff = ComponentDiffer().diff(insp_a, insp_b)

        assert diff.total_modified == 1
        change = diff.providers[0]
        assert change.change_type == ChangeType.MODIFIED
        assert change.enabled_before is True
        assert change.enabled_after is False

    def test_preserves_exported_permission_and_intent_filters(self) -> None:
        """Existing diff dimensions (exported, permission, intent filters) are preserved."""
        f_a = IntentFilterInfo(actions=["android.intent.action.MAIN"])
        f_b = IntentFilterInfo(actions=["android.intent.action.VIEW"])
        r_a = BroadcastReceiverInfo(
            name="com.example.Rec", enabled=True, exported=False, permission="perm.A", intent_filters=[f_a]
        )
        r_b = BroadcastReceiverInfo(
            name="com.example.Rec", enabled=True, exported=True, permission="perm.B", intent_filters=[f_b]
        )

        insp_a = InspectionResult(manifest=ManifestInspection(receivers=[r_a]))
        insp_b = InspectionResult(manifest=ManifestInspection(receivers=[r_b]))

        diff = ComponentDiffer().diff(insp_a, insp_b)

        assert diff.total_modified == 1
        change = diff.receivers[0]
        assert change.exported_before is False
        assert change.exported_after is True
        assert change.permission_before == "perm.A"
        assert change.permission_after == "perm.B"
        assert change.intent_filter_diff is not None
        assert "android.intent.action.VIEW" in change.intent_filter_diff.actions_added


# ---------------------------------------------------------------------------
# 2. DEX method-body verification
# ---------------------------------------------------------------------------


class TestDEXMethodBodyVerification:
    """Tests for DEX method-body code_hash comparison and differentiation."""

    def test_identical_method_body_is_unchanged(self) -> None:
        """Methods with identical signatures and code hashes produce no modification."""
        m_a = MethodInfo(
            name="doWork",
            class_name="com.example.Worker",
            return_type="void",
            parameters=["int"],
            access_flags="public",
            code_hash="abcdef1234567890",
        )
        m_b = MethodInfo(
            name="doWork",
            class_name="com.example.Worker",
            return_type="void",
            parameters=["int"],
            access_flags="public",
            code_hash="abcdef1234567890",
        )
        cls_a = ClassInfo(name="com.example.Worker")
        cls_b = ClassInfo(name="com.example.Worker")

        inv_a = DEXClassInventory(classes=[cls_a], methods=[m_a])
        inv_b = DEXClassInventory(classes=[cls_b], methods=[m_b])
        dex_a = DEXInspection(dex_files=[DEXFileInspection(path="classes.dex", size=100, sha256="h1", inventory=inv_a)])
        dex_b = DEXInspection(dex_files=[DEXFileInspection(path="classes.dex", size=100, sha256="h1", inventory=inv_b)])

        diff = DEXDiffer().diff(InspectionResult(dex=dex_a), InspectionResult(dex=dex_b))

        assert len(diff.classes_modified) == 0
        assert diff.classes_unchanged_count == 1

    def test_changed_method_body_detected(self) -> None:
        """Methods with identical signatures but differing code hashes are detected as modified."""
        m_a = MethodInfo(
            name="calculate",
            class_name="com.example.Calculator",
            return_type="int",
            parameters=[],
            access_flags="public",
            code_hash="hash_v1_original",
        )
        m_b = MethodInfo(
            name="calculate",
            class_name="com.example.Calculator",
            return_type="int",
            parameters=[],
            access_flags="public",
            code_hash="hash_v2_modified",
        )
        cls_a = ClassInfo(name="com.example.Calculator")
        cls_b = ClassInfo(name="com.example.Calculator")

        inv_a = DEXClassInventory(classes=[cls_a], methods=[m_a])
        inv_b = DEXClassInventory(classes=[cls_b], methods=[m_b])
        dex_a = DEXInspection(dex_files=[DEXFileInspection(path="classes.dex", size=100, sha256="h1", inventory=inv_a)])
        dex_b = DEXInspection(dex_files=[DEXFileInspection(path="classes.dex", size=100, sha256="h2", inventory=inv_b)])

        diff = DEXDiffer().diff(InspectionResult(dex=dex_a), InspectionResult(dex=dex_b))

        assert len(diff.classes_modified) == 1
        c_diff = diff.classes_modified[0]
        assert len(c_diff.methods_modified) == 1
        m_diff = c_diff.methods_modified[0]
        assert m_diff.method_name == "calculate"
        assert m_diff.code_changed is True
        assert m_diff.code_hash_before == "hash_v1_original"
        assert m_diff.code_hash_after == "hash_v2_modified"

    def test_method_added_and_removed_distinguishable(self) -> None:
        """Adding a new method and removing an old method is distinguishable from method body modification."""
        m_old = MethodInfo(name="oldMethod", class_name="com.example.Service", return_type="void")
        m_new = MethodInfo(name="newMethod", class_name="com.example.Service", return_type="void")

        cls_a = ClassInfo(name="com.example.Service")
        cls_b = ClassInfo(name="com.example.Service")

        inv_a = DEXClassInventory(classes=[cls_a], methods=[m_old])
        inv_b = DEXClassInventory(classes=[cls_b], methods=[m_new])
        dex_a = DEXInspection(dex_files=[DEXFileInspection(path="classes.dex", size=100, sha256="h1", inventory=inv_a)])
        dex_b = DEXInspection(dex_files=[DEXFileInspection(path="classes.dex", size=100, sha256="h2", inventory=inv_b)])

        diff = DEXDiffer().diff(InspectionResult(dex=dex_a), InspectionResult(dex=dex_b))

        assert len(diff.classes_modified) == 1
        c_diff = diff.classes_modified[0]
        assert len(c_diff.methods_modified) == 0  # Not a modification of existing method
        assert len(c_diff.methods_removed) == 1
        assert "oldMethod()void" in c_diff.methods_removed[0]
        assert len(c_diff.methods_added) == 1
        assert "newMethod()void" in c_diff.methods_added[0]

    def test_abstract_native_methods_no_code(self) -> None:
        """Abstract or native methods without code items (code_hash=None) do not crash or report false diffs."""
        m_a = MethodInfo(
            name="nativeInit",
            class_name="com.example.NativeBridge",
            access_flags="public native",
            code_hash=None,
        )
        m_b = MethodInfo(
            name="nativeInit",
            class_name="com.example.NativeBridge",
            access_flags="public native",
            code_hash=None,
        )
        cls_a = ClassInfo(name="com.example.NativeBridge")
        cls_b = ClassInfo(name="com.example.NativeBridge")

        inv_a = DEXClassInventory(classes=[cls_a], methods=[m_a])
        inv_b = DEXClassInventory(classes=[cls_b], methods=[m_b])
        dex_a = DEXInspection(dex_files=[DEXFileInspection(path="classes.dex", size=100, sha256="h1", inventory=inv_a)])
        dex_b = DEXInspection(dex_files=[DEXFileInspection(path="classes.dex", size=100, sha256="h1", inventory=inv_b)])

        diff = DEXDiffer().diff(InspectionResult(dex=dex_a), InspectionResult(dex=dex_b))

        assert len(diff.classes_modified) == 0
        assert diff.classes_unchanged_count == 1


# ---------------------------------------------------------------------------
# 3. Manifest resource-reference normalization
# ---------------------------------------------------------------------------


class TestManifestResourceNormalization:
    """Tests for manifest attribute resource-reference normalization."""

    def test_equivalent_resource_reference_vs_resolved_value(self) -> None:
        """A raw resource reference resolved in resource_map is recognized as equivalent to the literal."""
        # APK A has unresolved reference @7F130332 mapped to 'de.danoeh.antennapod.provider'
        # APK B has inlined literal string 'de.danoeh.antennapod.provider'
        prov_a = ContentProviderInfo(name="androidx.core.content.FileProvider", authorities="@7F130332")
        prov_b = ContentProviderInfo(
            name="androidx.core.content.FileProvider", authorities="de.danoeh.antennapod.provider"
        )

        insp_a = InspectionResult(
            manifest=ManifestInspection(
                providers=[prov_a],
                resource_map={"@7F130332": "de.danoeh.antennapod.provider"},
            )
        )
        insp_b = InspectionResult(
            manifest=ManifestInspection(
                providers=[prov_b],
                resource_map={},
            )
        )

        diff = ComponentDiffer().diff(insp_a, insp_b)

        assert diff.total_modified == 0
        assert diff.total_unchanged == 1
        assert diff.providers[0].change_type == ChangeType.UNCHANGED

    def test_genuinely_different_manifest_values_produce_diff(self) -> None:
        """Genuinely different authority strings still produce a detected modification."""
        prov_a = ContentProviderInfo(name="com.example.Provider", authorities="auth.original")
        prov_b = ContentProviderInfo(name="com.example.Provider", authorities="auth.tampered")

        insp_a = InspectionResult(manifest=ManifestInspection(providers=[prov_a]))
        insp_b = InspectionResult(manifest=ManifestInspection(providers=[prov_b]))

        diff = ComponentDiffer().diff(insp_a, insp_b)

        assert diff.total_modified == 1
        change = diff.providers[0]
        assert change.change_type == ChangeType.MODIFIED
        assert change.details.get("authorities_before") == "auth.original"
        assert change.details.get("authorities_after") == "auth.tampered"

    def test_resource_ref_resolving_to_different_value_produces_diff(self) -> None:
        """If a resource ref resolves to a value different from the comparison target, it produces a diff."""
        prov_a = ContentProviderInfo(name="com.example.Provider", authorities="@7F130001")
        prov_b = ContentProviderInfo(name="com.example.Provider", authorities="com.example.target")

        insp_a = InspectionResult(
            manifest=ManifestInspection(
                providers=[prov_a],
                resource_map={"@7F130001": "com.example.other"},
            )
        )
        insp_b = InspectionResult(manifest=ManifestInspection(providers=[prov_b]))

        diff = ComponentDiffer().diff(insp_a, insp_b)

        assert diff.total_modified == 1
        assert diff.providers[0].change_type == ChangeType.MODIFIED

    def test_manifest_differ_application_attributes_equivalence(self) -> None:
        """ManifestDiffer does not produce a diff for equivalent application attributes."""
        app_a = ApplicationInfo(label="@7F100001", debuggable=False)
        app_b = ApplicationInfo(label="My App", debuggable=False)

        insp_a = InspectionResult(
            manifest=ManifestInspection(application=app_a, resource_map={"@7F100001": "My App"})
        )
        insp_b = InspectionResult(manifest=ManifestInspection(application=app_b))

        diff = ManifestDiffer().diff(insp_a, insp_b)

        assert len(diff.attribute_changes) == 0


# ---------------------------------------------------------------------------
# 4. Rename / canonicalization noise rule
# ---------------------------------------------------------------------------


class TestRenameCanonicalizationRule:
    """Tests for file rename / path canonicalization detection."""

    def test_same_content_different_path_is_renamed(self) -> None:
        """Identical file content moved to a different path is classified as RENAMED."""
        hash_img = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        entry_a = PackageFile(path="res/drawable-xhdpi-v4/icon.png", size=1024, compressed_size=1024, category=FileCategory.RESOURCE, sha256=hash_img)
        entry_b = PackageFile(path="res/drawable/icon.png", size=1024, compressed_size=1024, category=FileCategory.RESOURCE, sha256=hash_img)

        pkg_a = _make_pkg([entry_a])
        pkg_b = _make_pkg([entry_b])

        insp_a = InspectionResult(package=pkg_a)
        insp_b = InspectionResult(package=pkg_b)

        diff = FileDiffer().diff(insp_a, insp_b)

        assert diff.total_renamed == 1
        assert diff.total_added == 0
        assert diff.total_removed == 0
        assert diff.total_modified == 0

        renamed = [e for e in diff.entries if e.change_type == ChangeType.RENAMED]
        assert len(renamed) == 1
        assert renamed[0].old_path == "res/drawable-xhdpi-v4/icon.png"
        assert renamed[0].path == "res/drawable/icon.png"
        assert renamed[0].sha256_before == hash_img
        assert renamed[0].sha256_after == hash_img

    def test_different_content_different_path_is_real_remove_and_add(self) -> None:
        """Differing file content at different paths remains separate REMOVED and ADDED entries."""
        entry_a = PackageFile(path="res/drawable/old.png", size=100, compressed_size=100, category=FileCategory.RESOURCE, sha256="hash_old")
        entry_b = PackageFile(path="res/drawable/new.png", size=200, compressed_size=200, category=FileCategory.RESOURCE, sha256="hash_new")

        pkg_a = _make_pkg([entry_a])
        pkg_b = _make_pkg([entry_b])

        insp_a = InspectionResult(package=pkg_a)
        insp_b = InspectionResult(package=pkg_b)

        diff = FileDiffer().diff(insp_a, insp_b)

        assert diff.total_renamed == 0
        assert diff.total_removed == 1
        assert diff.total_added == 1
        assert diff.total_modified == 0

    def test_ordinary_add_and_remove_unchanged_behavior(self) -> None:
        """Adding a completely new file and removing an unrelated file preserves normal add/remove."""
        entry_rem = PackageFile(path="assets/removed_config.json", size=50, compressed_size=50, category=FileCategory.ASSET, sha256="hash_rem")
        entry_add = PackageFile(path="assets/added_config.json", size=60, compressed_size=60, category=FileCategory.ASSET, sha256="hash_add")

        pkg_a = _make_pkg([entry_rem])
        pkg_b = _make_pkg([entry_add])

        insp_a = InspectionResult(package=pkg_a)
        insp_b = InspectionResult(package=pkg_b)

        diff = FileDiffer().diff(insp_a, insp_b)

        assert diff.total_removed == 1
        assert diff.total_added == 1
        assert diff.total_renamed == 0

    def test_file_at_same_path_with_changed_content_is_modified(self) -> None:
        """A file at the same path with altered SHA-256 is correctly classified as MODIFIED."""
        entry_a = PackageFile(path="AndroidManifest.xml", size=500, compressed_size=500, category=FileCategory.MANIFEST, sha256="hash_orig")
        entry_b = PackageFile(path="AndroidManifest.xml", size=480, compressed_size=480, category=FileCategory.MANIFEST, sha256="hash_mod")

        pkg_a = _make_pkg([entry_a])
        pkg_b = _make_pkg([entry_b])

        insp_a = InspectionResult(package=pkg_a)
        insp_b = InspectionResult(package=pkg_b)

        diff = FileDiffer().diff(insp_a, insp_b)

        assert diff.total_modified == 1
        assert diff.total_renamed == 0
        assert diff.total_added == 0
        assert diff.total_removed == 0
        assert diff.entries[0].change_type == ChangeType.MODIFIED
