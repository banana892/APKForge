"""C.5: expected-vs-actual classification of DiffEngine results and the no-op baseline."""

from __future__ import annotations

import hashlib
from typing import Any

from apkforge.builders.semantic_baseline import (
    NoopSemanticBaseline,
    NoopSemanticEntry,
    SemanticResult,
    classify_noop_diff,
)
from apkforge.core.models import AnalysisStatus
from apkforge.diff.comparisons import COMPARATORS
from apkforge.diff.expectations import (
    ExpectedChange,
    Observation,
    ObservationClass,
    observe,
    verify_expectations,
)
from apkforge.diff.manifest_tree import ManifestTreeDiff
from apkforge.diff.models import (
    AssetDiff,
    CertificateDiff,
    ChangeType,
    ComparatorResult,
    ComparisonStatus,
    ComponentChange,
    ComponentDiff,
    DEXDiff,
    DiffChange,
    DiffResult,
    DiffSummary,
    EmbeddedDiff,
    FileDiff,
    FileEntryDiff,
    IdentityDiff,
    ManifestDiff,
    NativeDiff,
    NetworkDiff,
    PackageIdentity,
    PermissionDiff,
    ResourceDiff,
    StringDiff,
)
from apkforge.diff.normalization import NoiseFingerprint, ToolchainIdentity

BOOT = "android.permission.RECEIVE_BOOT_COMPLETED"
RECV = "com.example.BootReceiver"


SIGNER_BEFORE = "11" * 32
SIGNER_AFTER = "ab" * 32  # FakeService signs with this certificate


def _h(*parts: str) -> str:
    """Deterministic fake SHA-256 for simulated archive content."""
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def _complete_comparisons() -> dict[str, ComparatorResult]:
    return {
        name: ComparatorResult(comparator=name, status=ComparisonStatus.UNCHANGED, complete=True)
        for name in COMPARATORS
    }


def _diff(**kw: Any) -> DiffResult:
    """Simulated original-vs-rebuild diff: rebuild noise only, every comparator complete."""
    parts: dict[str, Any] = {
        "apk_a": PackageIdentity(package_name="com.example"),
        "apk_b": PackageIdentity(package_name="com.example"),
        "identity": IdentityDiff(),
        "manifest": ManifestDiff(),
        "permissions": PermissionDiff(),
        "components": ComponentDiff(),
        "dex": DEXDiff(),
        "strings": StringDiff(),
        "network": NetworkDiff(),
        "native": NativeDiff(),
        "resources": ResourceDiff(),
        "assets": AssetDiff(),
        "embedded": EmbeddedDiff(),
        "certificates": CertificateDiff(
            status="CHANGED",
            count_before=1,
            count_after=1,
            certificates_before=[{"sha256_fingerprint": SIGNER_BEFORE}],
            certificates_after=[{"sha256_fingerprint": SIGNER_AFTER}],
        ),
        "files": FileDiff(entries=_rebuild_noise_files()),
        "summary": DiffSummary(),
        "manifest_tree": ManifestTreeDiff(status="complete"),
        "comparisons": _complete_comparisons(),
    }
    parts.update(kw)
    return DiffResult(**parts)


def noise_baseline(sha256: str, toolchain: ToolchainIdentity | None = None) -> NoopSemanticBaseline:
    """A v2 (content-aware) no-op baseline whose fingerprint is the simulated noise."""
    verdict = verify_expectations(_diff(), [])
    entry = NoopSemanticEntry(
        id="app",
        filename="app.apk",
        sha256=sha256,
        build_success=True,
        result=SemanticResult.EQUIVALENT,
        noise_rule_counts=dict(verdict.noise_rule_counts),
        fingerprint=NoiseFingerprint.from_verdict(verdict),
    )
    return NoopSemanticBaseline(toolchain_identity=toolchain or SIM_TOOLCHAIN, entries=[entry])


SIM_TOOLCHAIN = ToolchainIdentity(
    java="sim-java", apktool="sim-apktool", build_tools="sim-bt", zipalign="sim-bt",
    apksigner="sim-as", android_platform="android-sim",
)  # fmt: skip


def _f(path: str, kind: ChangeType, category: str, **kw: Any) -> FileEntryDiff:
    if kind != ChangeType.ADDED:
        kw.setdefault("sha256_before", _h(kw.get("old_path") or path, "before"))
    if kind != ChangeType.REMOVED:
        kw.setdefault("sha256_after", _h(path, "after"))
    return FileEntryDiff(path=path, change_type=kind, category=category, **kw)


def _rebuild_noise_files() -> list[FileEntryDiff]:
    return [
        _f("AndroidManifest.xml", ChangeType.MODIFIED, "manifest"),
        _f("classes.dex", ChangeType.MODIFIED, "dex"),
        _f("resources.arsc", ChangeType.MODIFIED, "resource_table"),
        _f("META-INF/MANIFEST.MF", ChangeType.MODIFIED, "signature"),
        _f("META-INF/OLD.RSA", ChangeType.REMOVED, "certificate", size_before=1),
        _f("META-INF/APKFORGE.RSA", ChangeType.ADDED, "certificate", size_after=1),
        _f(
            "res/layout/main.xml",
            ChangeType.RENAMED,
            "resource",
            old_path="res/Ab.xml",
            details={"match_basis": "resource_identity"},
        ),
    ]


def _receiver(name: str = RECV, **kw: Any) -> ComponentChange:
    base: dict[str, Any] = {
        "name": name,
        "component_type": "receiver",
        "change_type": ChangeType.MODIFIED,
        "exported_before": True,
        "exported_after": True,
        "enabled_before": True,
        "enabled_after": False,
        "details": {"enabled_before": True, "enabled_after": False},
    }
    base.update(kw)
    return ComponentChange(**base)


EXPECTED = [
    ExpectedChange(category="uses_permission", kind="removed", identifier=BOOT),
    ExpectedChange(
        category="component",
        kind="modified",
        identifier=RECV,
        detail={"component_type": "receiver", "enabled": [True, False]},
    ),
]


def _planned_diff(**kw: Any) -> DiffResult:
    parts: dict[str, Any] = {
        "permissions": PermissionDiff(removed=[BOOT]),
        "components": ComponentDiff(receivers=[_receiver()]),
    }
    parts.update(kw)
    return _diff(**parts)


class TestExpectedVsActual:
    def test_planned_changes_plus_noise_pass(self) -> None:
        v = verify_expectations(_planned_diff(), EXPECTED)
        assert v.passed, v.failures
        assert len(v.of(ObservationClass.EXPECTED_MODIFICATION)) == 2
        assert not v.of(ObservationClass.UNEXPECTED) and not v.expected_missing
        assert v.noise_rule_counts["signature_replaced"] == 3
        assert v.noise_rule_counts["resource_path_canonicalized"] == 1

    def test_missing_expected_change_fails(self) -> None:
        v = verify_expectations(_diff(permissions=PermissionDiff(removed=[BOOT])), EXPECTED)
        assert not v.passed
        assert [e.identifier for e in v.expected_missing] == [RECV]

    def test_unrelated_receiver_change_is_unexpected(self) -> None:
        other = _receiver("androidx.profileinstaller.ProfileInstallReceiver")
        diff = _planned_diff(components=ComponentDiff(receivers=[_receiver(), other]))
        v = verify_expectations(diff, EXPECTED)
        assert not v.passed
        assert [c.observation.identifier for c in v.of(ObservationClass.UNEXPECTED)] == [
            "androidx.profileinstaller.ProfileInstallReceiver"
        ]

    def test_extra_attribute_on_target_is_unexpected(self) -> None:
        # Disabled as planned but also un-exported: the detail no longer matches.
        changed = _receiver(exported_after=False)
        v = verify_expectations(
            _planned_diff(components=ComponentDiff(receivers=[changed])), EXPECTED
        )
        assert not v.passed and v.expected_missing
        assert v.of(ObservationClass.UNEXPECTED)[0].observation.detail["exported"] == [True, False]

    def test_extra_permission_removed_is_unexpected(self) -> None:
        diff = _planned_diff(
            permissions=PermissionDiff(removed=[BOOT, "android.permission.INTERNET"])
        )
        v = verify_expectations(diff, EXPECTED)
        assert not v.passed
        assert v.of(ObservationClass.UNEXPECTED)[0].observation.identifier == (
            "android.permission.INTERNET"
        )

    def test_intent_filter_change_on_target_is_unexpected(self) -> None:
        from apkforge.diff.models import IntentFilterDiff

        changed = _receiver(
            intent_filter_diff=IntentFilterDiff(
                actions_removed=["android.intent.action.MY_PACKAGE_REPLACED"]
            )
        )
        v = verify_expectations(
            _planned_diff(components=ComponentDiff(receivers=[changed])), EXPECTED
        )
        assert not v.passed

    def test_dex_class_change_is_never_noise(self) -> None:
        from apkforge.diff.models import ClassDiff

        dex = DEXDiff(
            dex_files_modified=["classes.dex"],
            classes_modified=[ClassDiff(class_name="a.B", change_type=ChangeType.MODIFIED)],
        )
        v = verify_expectations(_planned_diff(dex=dex), EXPECTED)
        assert not v.passed
        assert v.of(ObservationClass.UNEXPECTED)[0].observation.category == "dex_class"

    def test_non_signature_meta_inf_change_is_unexpected(self) -> None:
        files = [
            *_rebuild_noise_files(),
            _f("META-INF/services/a.B", ChangeType.MODIFIED, "signature"),
        ]
        v = verify_expectations(_planned_diff(files=FileDiff(entries=files)), EXPECTED)
        assert [c.observation.identifier for c in v.of(ObservationClass.UNEXPECTED)] == [
            "META-INF/services/a.B"
        ]

    def test_compiler_marker_is_noise_but_other_strings_are_not(self) -> None:
        strings = StringDiff(
            total_removed=2,
            removed_sample=['~~R8{"backend":"dex","version":"8.11.18"}', "http://tracker"],
        )
        v = verify_expectations(_planned_diff(strings=strings), EXPECTED)
        assert v.noise_rule_counts["dex_compiler_marker_removed"] == 1
        assert [c.observation.identifier for c in v.of(ObservationClass.UNEXPECTED)] == [
            "http://tracker"
        ]

    def test_truncated_output_is_unknown(self) -> None:
        strings = StringDiff(total_added=60, added_sample=[f"s{i}" for i in range(50)])
        v = verify_expectations(_planned_diff(strings=strings), EXPECTED)
        assert not v.passed and v.of(ObservationClass.UNKNOWN)

    def test_incomplete_diff_fails(self) -> None:
        v = verify_expectations(_planned_diff(status=AnalysisStatus.PARTIAL), EXPECTED)
        assert not v.passed and "not complete" in v.failures[0]
        v = verify_expectations(_planned_diff(limitations=["dex differ failed"]), EXPECTED)
        assert not v.passed

    def test_noise_restricted_to_baseline_rules(self) -> None:
        allowed = {
            "signature_replaced",
            "certificate_replaced",
            "manifest_reencoded",
            "dex_reencoded",
            "resource_table_reencoded",
        }
        v = verify_expectations(_planned_diff(), EXPECTED, allowed_noise_rules=allowed)
        assert not v.passed
        (u,) = v.of(ObservationClass.UNEXPECTED)
        assert u.rule == "resource_path_canonicalized"

    def test_manifest_resource_path_needs_paired_rename(self) -> None:
        change = DiffChange(
            change_type=ChangeType.MODIFIED,
            category="manifest.application",
            identifier="networkSecurityConfig",
            before="res/Ab.xml",
            after="res/layout/main.xml",
        )
        v = verify_expectations(
            _planned_diff(manifest=ManifestDiff(attribute_changes=[change])), EXPECTED
        )
        assert v.passed, v.failures
        unpaired = change.model_copy(update={"after": "res/xml/other.xml"})
        v = verify_expectations(
            _planned_diff(manifest=ManifestDiff(attribute_changes=[unpaired])), EXPECTED
        )
        assert not v.passed

    def test_residue_accepted_only_on_exact_match(self) -> None:
        files = [
            *_rebuild_noise_files(),
            _f("res/Xy.xml", ChangeType.REMOVED, "resource", size_before=7),
            _f("res/drawable/x.xml", ChangeType.ADDED, "resource", size_after=7),
        ]
        diff = _planned_diff(files=FileDiff(entries=files))
        residue = {("file", "removed", "res/Xy.xml"), ("file", "added", "res/drawable/x.xml")}
        assert verify_expectations(diff, EXPECTED, allowed_residue=residue).passed
        assert not verify_expectations(
            diff, EXPECTED, allowed_residue=set(list(residue)[:1])
        ).passed

    def test_observe_covers_every_category(self) -> None:
        diff = _planned_diff(
            identity=IdentityDiff(
                changes=[
                    DiffChange(
                        change_type=ChangeType.MODIFIED,
                        category="identity",
                        identifier="version_code",
                        before=1,
                        after=2,
                    )
                ]
            ),
            network=NetworkDiff(domains_added=["evil.example"]),
            embedded=EmbeddedDiff(dex_added=["assets/x.dex"]),
        )
        cats = {o.category for o in observe(diff)}
        assert {
            "identity",
            "network_host",
            "embedded",
            "uses_permission",
            "component",
            "file",
            "certificate",
        } <= cats
        assert not verify_expectations(diff, EXPECTED).passed


class TestNoopClassification:
    def test_noise_only_is_equivalent(self) -> None:
        result, detail = classify_noop_diff(_diff())
        assert result == SemanticResult.EQUIVALENT and not detail["unexpected"]

    def test_size_matched_unpaired_resources_are_residue(self) -> None:
        files = [
            *_rebuild_noise_files(),
            _f("res/Xy.xml", ChangeType.REMOVED, "resource", size_before=7),
            _f("res/drawable/x.xml", ChangeType.ADDED, "resource", size_after=7),
        ]
        result, detail = classify_noop_diff(_diff(files=FileDiff(entries=files)))
        assert result == SemanticResult.EQUIVALENT_WITH_RESIDUE
        assert len(detail["residue"]) == 2

    def test_size_mismatch_is_not_equivalent(self) -> None:
        files = [
            *_rebuild_noise_files(),
            _f("res/Xy.xml", ChangeType.REMOVED, "resource", size_before=7),
            _f("res/drawable/x.xml", ChangeType.ADDED, "resource", size_after=9),
        ]
        result, _ = classify_noop_diff(_diff(files=FileDiff(entries=files)))
        assert result == SemanticResult.NOT_EQUIVALENT

    def test_partial_diff_is_undetermined(self) -> None:
        result, _ = classify_noop_diff(_diff(status=AnalysisStatus.PARTIAL))
        assert result == SemanticResult.UNDETERMINED

    def test_allowances_only_for_equivalent_entries(self) -> None:
        good = NoopSemanticEntry(
            id="a",
            filename="a.apk",
            sha256="aa",
            build_success=True,
            result=SemanticResult.EQUIVALENT_WITH_RESIDUE,
            noise_rule_counts={"dex_reencoded": 1},
            residue=[Observation(category="file", kind="added", identifier="res/x.xml")],
        )
        bad = NoopSemanticEntry(
            id="b",
            filename="b.apk",
            sha256="bb",
            build_success=True,
            result=SemanticResult.NOT_EQUIVALENT,
        )
        b = NoopSemanticBaseline(entries=[good, bad])
        assert b.allowances("AA") == ({"dex_reencoded"}, {("file", "added", "res/x.xml")})
        assert b.allowances("bb") is None and b.allowances("cc") is None
