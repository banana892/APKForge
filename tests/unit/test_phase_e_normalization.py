"""Phase E2/E5: content-aware noise, baselines, toolchain identity, expected vs actual."""

from __future__ import annotations

import pytest

from apkforge.builders.semantic_baseline import (
    BaselineStatus,
    NoopSemanticBaseline,
    NoopSemanticEntry,
    SemanticResult,
    classify_noop_diff,
)
from apkforge.diff.expectations import ExpectedChange, ObservationClass, verify_expectations
from apkforge.diff.models import (
    CertificateDiff,
    ChangeType,
    ComparatorResult,
    ComparisonStatus,
    FileDiff,
    FileEntryDiff,
    PermissionDiff,
    StringDiff,
)
from apkforge.diff.normalization import (
    NORMALIZATION_SCHEMA_VERSION,
    ContentPolicy,
    NoiseFingerprint,
    ToolchainIdentity,
    archive_entries_for,
)
from apkforge.verification.pair import check_baseline, classify
from tests.unit.test_c5_expectations import (
    SIGNER_AFTER,
    SIM_TOOLCHAIN,
    _complete_comparisons,
    _diff,
    _f,
    _h,
    _rebuild_noise_files,
    noise_baseline,
)

SHA = "a" * 64


def _fp() -> NoiseFingerprint:
    fp = noise_baseline(SHA).entries[0].fingerprint
    assert fp is not None
    return fp


def _files(*replace: FileEntryDiff) -> FileDiff:
    by_path = {e.path: e for e in _rebuild_noise_files()}
    for e in replace:
        by_path[e.path] = e
    return FileDiff(entries=list(by_path.values()))


def _cls(verdict, ident: str) -> ObservationClass:  # type: ignore[no-untyped-def]
    return next(c.classification for c in verdict.observations if c.observation.identifier == ident)


class TestFingerprint:
    def test_from_noop_verdict_records_content(self) -> None:
        fp = _fp()
        dex = next(a for a in fp.accepted if a.identifier == "classes.dex")
        assert dex.rule == "dex_reencoded" and dex.policy == ContentPolicy.EXACT
        assert dex.content_before == _h("classes.dex", "before")
        assert dex.content_after == _h("classes.dex", "after")
        sig = next(a for a in fp.accepted if a.identifier == "META-INF/MANIFEST.MF")
        assert sig.policy == ContentPolicy.PATH_ONLY
        cert = next(a for a in fp.accepted if a.category == "certificate")
        assert cert.policy == ContentPolicy.SIGNER and cert.content_after == SIGNER_AFTER

    def test_identical_rebuild_is_content_noise(self) -> None:
        v = verify_expectations(_diff(), [], fingerprint=_fp())
        assert v.passed and v.mode == "content_fingerprint"
        assurances = {c.assurance for c in v.observations}
        assert assurances == {"content", "path_only", "signer"}

    def test_accepted_path_with_different_content_is_unexpected(self) -> None:
        """Section 30: path == accepted noise path, content hash differs -> not noise."""
        tampered = _f(
            "res/layout/main.xml",
            ChangeType.RENAMED,
            "resource",
            old_path="res/Ab.xml",
            details={"match_basis": "resource_identity"},
            sha256_after="f" * 64,
        )
        d = _diff(files=_files(tampered))
        legacy = verify_expectations(d, [], allowed_noise_rules={"resource_path_canonicalized"})
        assert _cls(legacy, "res/layout/main.xml") == ObservationClass.REBUILD_NOISE  # blind spot
        v = verify_expectations(d, [], fingerprint=_fp())
        assert _cls(v, "res/layout/main.xml") == ObservationClass.UNEXPECTED
        assert not v.passed

    def test_content_mismatch_is_unknown_when_toolchain_unknown(self) -> None:
        tampered = _f("classes.dex", ChangeType.MODIFIED, "dex", sha256_after="e" * 64)
        v = verify_expectations(
            _diff(files=_files(tampered)),
            [],
            fingerprint=_fp(),
            content_mismatch=ObservationClass.UNKNOWN,
        )
        assert _cls(v, "classes.dex") == ObservationClass.UNKNOWN

    def test_signature_files_path_only_but_new_signature_file_unexpected(self) -> None:
        extra = _f("META-INF/EVIL.SF", ChangeType.ADDED, "signature")
        changed_mf = _f(
            "META-INF/MANIFEST.MF", ChangeType.MODIFIED, "signature", sha256_after="9" * 64
        )
        v = verify_expectations(_diff(files=_files(extra, changed_mf)), [], fingerprint=_fp())
        assert _cls(v, "META-INF/MANIFEST.MF") == ObservationClass.REBUILD_NOISE
        assert _cls(v, "META-INF/EVIL.SF") == ObservationClass.UNEXPECTED

    def test_certificate_must_be_the_signing_certificate(self) -> None:
        other = CertificateDiff(
            status="CHANGED",
            certificates_before=[{"sha256_fingerprint": "11" * 32}],
            certificates_after=[{"sha256_fingerprint": "cd" * 32}],
        )
        v = verify_expectations(_diff(certificates=other), [], fingerprint=_fp())
        assert _cls(v, "signing_certificate") == ObservationClass.UNEXPECTED
        ok = verify_expectations(_diff(), [], fingerprint=_fp(), expected_signer="AB:" * 31 + "AB")
        assert _cls(ok, "signing_certificate") == ObservationClass.REBUILD_NOISE
        wrong = verify_expectations(_diff(), [], fingerprint=_fp(), expected_signer="cd" * 32)
        assert _cls(wrong, "signing_certificate") == ObservationClass.UNEXPECTED

    def test_rule_shaped_change_absent_from_fingerprint_is_unexpected(self) -> None:
        new_res = _f("res/xml/new.xml", ChangeType.MODIFIED, "resource")
        v = verify_expectations(_diff(files=_files(new_res)), [], fingerprint=_fp())
        c = next(c for c in v.observations if c.observation.identifier == "res/xml/new.xml")
        assert c.classification == ObservationClass.UNEXPECTED and c.rule == "resource_reencoded"

    def test_compiler_marker_matches_by_identifier(self) -> None:
        marker = '~~R8{"version":"8"}'
        noop = _diff(strings=StringDiff(total_removed=1, removed_sample=[marker]))
        fp = NoiseFingerprint.from_verdict(verify_expectations(noop, []))
        assert verify_expectations(noop, [], fingerprint=fp).passed
        other = _diff(strings=StringDiff(total_removed=1, removed_sample=['~~R8{"version":"9"}']))
        assert not verify_expectations(other, [], fingerprint=fp).passed


class TestPlannedEntries:
    def _manifest_changed(self, **kw):  # type: ignore[no-untyped-def]
        changed = _f("AndroidManifest.xml", ChangeType.MODIFIED, "manifest", sha256_after="7" * 64)
        perms = PermissionDiff(removed=["android.permission.X"])
        return _diff(files=_files(changed), permissions=perms, **kw)

    def test_planned_manifest_entry_with_complete_semantics(self) -> None:
        exp = [
            ExpectedChange(
                category="uses_permission", kind="removed", identifier="android.permission.X"
            )
        ]
        v = verify_expectations(
            self._manifest_changed(),
            exp,
            fingerprint=_fp(),
            planned_entries={"AndroidManifest.xml"},
        )
        assert _cls(v, "AndroidManifest.xml") == ObservationClass.PLANNED_ENTRY
        assert v.passed

    def test_unplanned_manifest_content_change_is_unexpected(self) -> None:
        v = verify_expectations(self._manifest_changed(), [], fingerprint=_fp())
        assert _cls(v, "AndroidManifest.xml") == ObservationClass.UNEXPECTED

    def test_planned_entry_with_incomplete_semantics_is_unknown(self) -> None:
        comps = _complete_comparisons()
        comps["manifest_tree"] = ComparatorResult(
            comparator="manifest_tree", status=ComparisonStatus.UNDETERMINED, complete=False
        )
        v = verify_expectations(
            self._manifest_changed(comparisons=comps),
            [],
            fingerprint=_fp(),
            planned_entries={"AndroidManifest.xml"},
        )
        assert _cls(v, "AndroidManifest.xml") == ObservationClass.UNKNOWN

    def test_planned_resource_table_is_unknown(self) -> None:
        arsc = _f("resources.arsc", ChangeType.MODIFIED, "resource_table", sha256_after="6" * 64)
        v = verify_expectations(
            _diff(files=_files(arsc)), [], fingerprint=_fp(), planned_entries={"resources.arsc"}
        )
        assert _cls(v, "resources.arsc") == ObservationClass.UNKNOWN

    def test_archive_mapping(self) -> None:
        entries, unmapped = archive_entries_for(
            [
                "AndroidManifest.xml",
                "smali/a/B.smali",
                "smali_classes3/c/D.smali",
                "res/values/strings.xml",
                "res/layout/x.xml",
                "assets/f.txt",
                "lib/x86/l.so",
                "unknown/top.bin",
                "apktool.yml",
            ]
        )
        assert entries == {
            "AndroidManifest.xml",
            "classes.dex",
            "classes3.dex",
            "resources.arsc",
            "res/layout/x.xml",
            "assets/f.txt",
            "lib/x86/l.so",
            "top.bin",
        }
        assert unmapped == ["apktool.yml"]


class TestExpectedVsActual:
    def test_content_pinned_expectation(self) -> None:
        add = FileEntryDiff(
            path="assets/m.txt",
            change_type=ChangeType.ADDED,
            category="asset",
            size_after=3,
            sha256_after="1" * 64,
        )
        d = _diff(files=FileDiff(entries=[*_rebuild_noise_files(), add]))
        exp = ExpectedChange(
            category="file",
            kind="added",
            identifier="assets/m.txt",
            detail={"file_category": "asset", "size": 3},
        )
        good = exp.model_copy(update={"content_after": "1" * 64})
        bad = exp.model_copy(update={"content_after": "2" * 64})
        assert verify_expectations(d, [good], fingerprint=_fp()).passed
        v = verify_expectations(d, [bad], fingerprint=_fp())
        assert (
            v.expected_missing == [bad] and _cls(v, "assets/m.txt") == ObservationClass.UNEXPECTED
        )

    def test_vague_expectation_does_not_match(self) -> None:
        d = _diff(permissions=PermissionDiff(removed=["android.permission.X"]))
        vague = ExpectedChange(category="manifest", kind="modified", identifier="manifest")
        v = verify_expectations(d, [vague], fingerprint=_fp())
        assert v.expected_missing == [vague]
        assert _cls(v, "android.permission.X") == ObservationClass.UNEXPECTED


class TestToolchainAndBaselines:
    def test_identity_differences(self) -> None:
        other = SIM_TOOLCHAIN.model_copy(update={"apktool": "2.10.0"})
        assert SIM_TOOLCHAIN.differences(SIM_TOOLCHAIN) == []
        assert SIM_TOOLCHAIN.differences(other) == [
            "apktool: baseline sim-apktool vs current 2.10.0"
        ]
        schema = SIM_TOOLCHAIN.model_copy(
            update={"normalization_schema": NORMALIZATION_SCHEMA_VERSION + 1}
        )
        assert SIM_TOOLCHAIN.differences(schema)

    @pytest.mark.parametrize(
        ("current", "status", "usable"),
        [
            (SIM_TOOLCHAIN, BaselineStatus.COMPATIBLE, True),
            (
                SIM_TOOLCHAIN.model_copy(update={"build_tools": "34.0.0"}),
                BaselineStatus.INCOMPATIBLE,
                False,
            ),
            (None, BaselineStatus.TOOLCHAIN_UNKNOWN, True),
        ],
    )
    def test_check(
        self, current: ToolchainIdentity | None, status: BaselineStatus, usable: bool
    ) -> None:
        c = noise_baseline(SHA).check(SHA, current)
        assert (c.status, c.usable) == (status, usable)

    def test_legacy_no_entry_not_equivalent_missing(self) -> None:
        legacy = NoopSemanticBaseline(
            schema_version=1,
            entries=[
                NoopSemanticEntry(
                    id="x",
                    filename="x.apk",
                    sha256=SHA,
                    build_success=True,
                    result=SemanticResult.EQUIVALENT,
                )
            ],
        )
        assert legacy.check(SHA, SIM_TOOLCHAIN).status == BaselineStatus.LEGACY_PATH_RULES
        assert legacy.check("b" * 64, SIM_TOOLCHAIN).status == BaselineStatus.NO_ENTRY
        legacy.entries[0].result = SemanticResult.UNDETERMINED
        assert legacy.check(SHA, SIM_TOOLCHAIN).status == BaselineStatus.NOT_EQUIVALENT
        assert check_baseline(None, SHA, SIM_TOOLCHAIN).status == BaselineStatus.MISSING

    def test_incompatible_baseline_accepts_no_noise(self) -> None:
        """Toolchain-B differences are never reinterpreted as toolchain-A noise."""
        base = noise_baseline(SHA)
        other = SIM_TOOLCHAIN.model_copy(update={"apktool": "2.10.0"})
        chk = base.check(SHA, other)
        v = classify(_diff(), [], base, chk, sha256=SHA)
        assert not v.passed
        assert not v.of(ObservationClass.REBUILD_NOISE)
        assert "noise floor not established: BASELINE_INCOMPATIBLE" in v.failures

    def test_baseline_json_roundtrip_and_portability(self) -> None:
        base = noise_baseline(SHA)
        text = base.model_dump_json()
        assert "/home/" not in text and "/tmp/" not in text
        again = NoopSemanticBaseline.model_validate_json(text)
        assert again.check(SHA, SIM_TOOLCHAIN).status == BaselineStatus.COMPATIBLE
        assert again.entries[0].fingerprint == base.entries[0].fingerprint

    def test_noop_classification_is_reproducible(self) -> None:
        r1, d1 = classify_noop_diff(_diff())
        r2, d2 = classify_noop_diff(_diff())
        assert r1 == r2 == SemanticResult.EQUIVALENT
        assert d1["fingerprint"] == d2["fingerprint"]


class TestEvidenceDerivedRules:
    """Rules added from observed corpus rebuild behaviour (artifacts/phase-e)."""

    def _tree_change(self, before: str, after: str, rb: str | None, ra: str | None):  # type: ignore[no-untyped-def]
        from apkforge.diff.manifest_tree import ManifestTreeChange, ManifestTreeDiff

        ch = ManifestTreeChange(
            kind="modified",
            element="application#0/provider[name=androidx.core.content.FileProvider]",
            tag="provider",
            attribute="android:authorities",
            before=before,
            after=after,
            before_resolved=rb,
            after_resolved=ra,
        )
        return ManifestTreeDiff(status="complete", changes=[ch])

    def test_reference_inlined_is_noise_only_when_resolved_value_matches(self) -> None:
        """AntennaPod: @7F130332 -> 'de.danoeh.antennapod.provider' in a no-op rebuild."""
        noop = _diff(
            manifest_tree=self._tree_change("@7F130332", "app.provider", "app.provider", None)
        )
        v = verify_expectations(noop, [])
        c = next(c for c in v.observations if c.observation.category == "manifest_element")
        assert c.classification == ObservationClass.REBUILD_NOISE
        assert c.rule == "manifest_reference_inlined"
        # A different literal is not the same value.
        other = _diff(
            manifest_tree=self._tree_change("@7F130332", "evil.provider", "app.provider", None)
        )
        assert not verify_expectations(other, []).passed
        # An unresolved (configuration-dependent) reference is never assumed equal.
        unresolved = _diff(manifest_tree=self._tree_change("@7F130332", "app.provider", None, None))
        assert not verify_expectations(unresolved, []).passed

    def test_partial_baseline_is_usable_but_partial(self) -> None:
        base = noise_baseline(SHA)
        base.entries[0].result = SemanticResult.UNDETERMINED
        base.entries[0].diff_failures = ["diff status is partial, not complete"]
        chk = base.check(SHA, SIM_TOOLCHAIN)
        assert chk.status == BaselineStatus.PARTIAL and chk.usable and chk.content_aware
        from apkforge.diff.expectations import Observation

        base.entries[0].unexpected = [Observation(category="file", kind="added", identifier="x")]
        assert base.check(SHA, SIM_TOOLCHAIN).status == BaselineStatus.NOT_EQUIVALENT
