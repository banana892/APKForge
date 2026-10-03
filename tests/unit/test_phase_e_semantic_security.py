"""Phase E3/E4: per-comparator status and the security-relevant diff."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from apkforge.diff.comparisons import assess_comparators
from apkforge.diff.engine import DiffEngine
from apkforge.diff.expectations import verify_expectations
from apkforge.diff.models import (
    ChangeType,
    ClassDiff,
    ComparisonStatus,
    ComponentChange,
    ComponentDiff,
    DEXDiff,
    EmbeddedDiff,
    FileDiff,
    FileEntryDiff,
    NativeDiff,
    NativeLibraryDiff,
    NetworkDiff,
    PermissionDiff,
    StringDiff,
    URLDiffItem,
)
from apkforge.diff.security import build_security_diff
from tests.fixtures import create_synthetic_apk
from tests.unit.test_c5_expectations import _diff, _rebuild_noise_files, noise_baseline


def _insp(**statuses: str) -> SimpleNamespace:
    base = dict.fromkeys(
        ("manifest", "dex", "native", "resources", "assets", "network", "embedded"), "complete"
    )
    base.update(statuses)
    return SimpleNamespace(inspector_statuses=base)


class TestComparators:
    def test_complete_noop(self) -> None:
        d = _diff()
        d.manifest_tree.status = "complete"
        res = assess_comparators(d, _insp(), _insp())  # type: ignore[arg-type]
        assert (
            res["permissions"].status == ComparisonStatus.UNCHANGED and res["permissions"].complete
        )
        assert res["certificate"].status == ComparisonStatus.MODIFIED
        assert res["resource_table"].status == ComparisonStatus.NOT_COMPARABLE
        assert not res["resource_table"].complete

    def test_failed_differ_is_undetermined_not_unchanged(self) -> None:
        res = assess_comparators(_diff(), _insp(), _insp(), failed={"dex"})  # type: ignore[arg-type]
        assert res["dex"].status == ComparisonStatus.UNDETERMINED and not res["dex"].complete

    def test_partial_inspection_is_partial(self) -> None:
        res = assess_comparators(_diff(), _insp(dex="partial"), _insp())  # type: ignore[arg-type]
        assert res["dex"].status == ComparisonStatus.PARTIAL
        assert "partial" in (res["dex"].reason or "")
        failed = assess_comparators(_diff(), _insp(), _insp(dex="failed"))  # type: ignore[arg-type]
        assert failed["dex"].status == ComparisonStatus.UNDETERMINED

    def test_truncated_strings_are_partial(self) -> None:
        d = _diff(strings=StringDiff(total_added=80, added_sample=["s"] * 50))
        res = assess_comparators(d, _insp(), _insp())  # type: ignore[arg-type]
        assert res["strings"].status == ComparisonStatus.PARTIAL

    def test_without_inspections_dependent_comparators_undetermined(self) -> None:
        res = assess_comparators(_diff())
        assert res["permissions"].status == ComparisonStatus.UNDETERMINED
        assert res["files"].complete  # depends on no inspector

    def test_manifest_tree_unavailable_is_undetermined(self) -> None:
        d = _diff()
        d.manifest_tree.status, d.manifest_tree.reason = "failed", "not binary XML"
        res = assess_comparators(d, _insp(), _insp())  # type: ignore[arg-type]
        assert res["manifest_tree"].status == ComparisonStatus.UNDETERMINED

    def test_real_engine_on_synthetic_apks(self, tmp_path: Path) -> None:
        """Text manifests cannot be decoded as binary XML: undetermined, never unchanged."""
        a = create_synthetic_apk(tmp_path / "a.apk")
        b = create_synthetic_apk(tmp_path / "b.apk", native_abis=["x86_64"])
        d = DiffEngine().diff(a, b)
        assert d.raw is not None and d.raw.counts["added"] == 1
        assert d.comparisons["manifest_tree"].status == ComparisonStatus.UNDETERMINED
        assert d.schema_version == 2


def _sec_diff():  # type: ignore[no-untyped-def]
    svc = ComponentChange(
        name="com.example.Sync",
        component_type="service",
        change_type=ChangeType.ADDED,
        exported_after=False,
    )
    return _diff(
        permissions=PermissionDiff(added=["android.permission.READ_PHONE_STATE"]),
        components=ComponentDiff(services=[svc]),
        network=NetworkDiff(
            domains_added=["example-domain.com"],
            domains_removed=["old.example.org"],
            urls_added=[URLDiffItem(url="https://example-domain.com/a", source_file="classes.dex")],
        ),
        native=NativeDiff(
            libraries_added=[
                NativeLibraryDiff(
                    path="lib/x86/libnew.so",
                    abi="x86",
                    change_type=ChangeType.ADDED,
                    sha256_after="1" * 64,
                )
            ],
            libraries_removed=[
                NativeLibraryDiff(
                    path="lib/x86/libold.so", abi="x86", change_type=ChangeType.REMOVED
                )
            ],
            libraries_modified=[
                NativeLibraryDiff(
                    path="lib/x86/libmod.so", abi="x86", change_type=ChangeType.MODIFIED
                )
            ],
        ),
        dex=DEXDiff(
            classes_added=["com.example.New"],
            classes_removed=["com.example.Old"],
            classes_modified=[
                ClassDiff(
                    class_name="com.example.Main",
                    change_type=ChangeType.MODIFIED,
                    methods_added=["run()V"],
                )
            ],
        ),
        embedded=EmbeddedDiff(apks_added=["assets/payload.apk"]),
    )


class TestSecurityDiff:
    def test_categories_are_populated_descriptively(self) -> None:
        sec = build_security_diff(_sec_diff())
        subjects = {k: [i.subject for i in s.items] for k, s in sec.sections.items()}
        assert subjects["permissions"] == ["android.permission.READ_PHONE_STATE"]
        assert subjects["components"] == ["service com.example.Sync"]
        assert subjects["network_domains"] == ["example-domain.com", "old.example.org"]
        assert subjects["urls"] == ["https://example-domain.com/a"]
        assert sorted(subjects["native_libraries"]) == [
            "lib/x86/libmod.so",
            "lib/x86/libnew.so",
            "lib/x86/libold.so",
        ]
        assert set(subjects["dex"]) == {"com.example.New", "com.example.Old", "com.example.Main"}
        assert subjects["embedded_executables"] == ["assets/payload.apk"]
        assert subjects["certificate"] == ["signing certificate"]
        assert "malicious" in sec.disclaimer  # states it does NOT infer maliciousness
        for item in sec.items():
            assert item.classification is None  # no verdict given: nothing is judged

    def test_classification_attached_from_verdict(self) -> None:
        d = _sec_diff()
        v = verify_expectations(d, [], fingerprint=noise_baseline("a" * 64).entries[0].fingerprint)
        sec = build_security_diff(d, v)
        perm = sec.sections["permissions"].items[0]
        assert perm.classification == "unexpected"
        assert sec.sections["certificate"].items[0].classification == "rebuild_noise"

    def test_availability_reflects_comparator_status(self) -> None:
        d = _sec_diff()
        d.comparisons["network"].complete = False
        d.comparisons["network"].status = ComparisonStatus.PARTIAL
        sec = build_security_diff(d)
        assert sec.status == "partial"
        assert sec.sections["network_domains"].availability == "partial"
        assert "network_domains" in sec.incomplete_categories

    def test_noise_only_diff_has_only_certificate(self) -> None:
        sec = build_security_diff(_diff(files=FileDiff(entries=_rebuild_noise_files())))
        assert {k for k, s in sec.sections.items() if s.items} == {"certificate"}

    def test_embedded_archive_from_raw_diff(self, tmp_path: Path) -> None:
        a = create_synthetic_apk(tmp_path / "a.apk")
        b = create_synthetic_apk(tmp_path / "b.apk", extra_files={"assets/x.jar": b"PK\x03\x04"})
        sec = build_security_diff(DiffEngine().diff(a, b))
        assert "assets/x.jar" in [i.subject for i in sec.sections["embedded_executables"].items]
        assert sec.status == "partial"  # synthetic manifests are not binary XML


def test_file_entry_import_is_used() -> None:  # keep the import list honest
    assert FileEntryDiff
