"""Regression tests for Phase B Step 5 (verifier robustness, DEX normalization,
enabled-default normalization, direct-boot-aware comparison, and ARSC-based
resource rename pairing).

Covers:
1. DEX normalized instruction hashing: table-index-shift stability, real
   semantic-difference detection, and determinism on real corpus APKs.
2. ComponentDiffer: `enabled` missing-vs-explicit-true normalization across
   all four component types (Android treats an absent `android:enabled` as
   enabled=true by default).
3. ComponentDiffer: `directBootAware` comparison for activities (an
   inspected-but-previously-uncompared security-relevant field).
4. FileDiffer: ARSC resource-identity rename pairing for paths that differ
   in content (re-encoding) but resolve to the same canonical resource.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from androguard.core.dex import Operand

from apkforge.diff.components import ComponentDiffer
from apkforge.diff.files import FileDiffer
from apkforge.diff.models import ChangeType
from apkforge.inspection.dex import DEXInspector, _hash_method_code, _normalize_instruction
from apkforge.inspection.models import (
    ActivityInfo,
    BroadcastReceiverInfo,
    ContentProviderInfo,
    InspectionResult,
    ManifestInspection,
    ServiceInfo,
)
from apkforge.intake import AndroidPackage, FileCategory, InputFormat, PackageFile, PackageType

CORPUS_DIR = Path(__file__).resolve().parent.parent / "corpus"
OPENLINK_APK = CORPUS_DIR / "de.audioattack.openlink_28.apk"


# ---------------------------------------------------------------------------
# Fakes mimicking Androguard's Instruction/Code/BytecodeContainer surfaces,
# used to exercise the pure normalization logic without parsing a real DEX.
# ---------------------------------------------------------------------------


class _FakeInstruction:
    def __init__(self, name: str, operands: list[tuple]) -> None:
        self._name = name
        self._operands = operands

    def get_name(self) -> str:
        return self._name

    def get_operands(self, idx: int = 0) -> list[tuple]:
        return self._operands

    def get_output(self, idx: int = 0) -> str:
        return self._name


class _FakeBC:
    def __init__(self, instructions: list) -> None:
        self._instructions = instructions

    def get_instructions(self) -> list:
        return self._instructions


class _FakeCode:
    def __init__(self, instructions: list) -> None:
        self._bc = _FakeBC(instructions)

    def get_bc(self) -> _FakeBC:
        return self._bc

    def get_tries_size(self) -> int:
        """No try/catch blocks (see test_phase_b_closeout for handler coverage)."""
        return 0


# Kind.METH resolves via Operand.KIND (256) + Kind.METH (0) == 256.
_KIND_METH = 256


# ---------------------------------------------------------------------------
# 1. DEX normalized instruction hashing
# ---------------------------------------------------------------------------


class TestDEXNormalizedHashing:
    def test_table_index_shift_does_not_change_normalized_instruction(self) -> None:
        """Same resolved method reference, different raw pool index -> identical."""
        ins_a = _FakeInstruction(
            "invoke-virtual", [(Operand.REGISTER, 0), (_KIND_METH, 5, "Lcom/example/Foo;->bar()V")]
        )
        ins_b = _FakeInstruction(
            "invoke-virtual", [(Operand.REGISTER, 0), (_KIND_METH, 9999, "Lcom/example/Foo;->bar()V")]
        )
        assert _normalize_instruction(ins_a) == _normalize_instruction(ins_b)

    def test_different_resolved_reference_changes_normalized_instruction(self) -> None:
        """A genuinely different method reference must still differ."""
        ins_a = _FakeInstruction(
            "invoke-virtual", [(Operand.REGISTER, 0), (_KIND_METH, 5, "Lcom/example/Foo;->bar()V")]
        )
        ins_b = _FakeInstruction(
            "invoke-virtual", [(Operand.REGISTER, 0), (_KIND_METH, 5, "Lcom/example/Foo;->baz()V")]
        )
        assert _normalize_instruction(ins_a) != _normalize_instruction(ins_b)

    def test_different_literal_changes_normalized_instruction(self) -> None:
        """Different constants must remain different."""
        ins_a = _FakeInstruction("const/4", [(Operand.REGISTER, 0), (Operand.LITERAL, 1)])
        ins_b = _FakeInstruction("const/4", [(Operand.REGISTER, 0), (Operand.LITERAL, 2)])
        assert _normalize_instruction(ins_a) != _normalize_instruction(ins_b)

    def test_different_opcode_changes_normalized_instruction(self) -> None:
        """Different instructions must remain different even with identical operands."""
        ins_a = _FakeInstruction("goto", [(Operand.OFFSET, 4)])
        ins_b = _FakeInstruction("goto/16", [(Operand.OFFSET, 4)])
        assert _normalize_instruction(ins_a) != _normalize_instruction(ins_b)

    def test_hash_method_code_stable_across_table_index_shift(self) -> None:
        """A full method's hash is unaffected by a table-index-only shift."""
        code_a = _FakeCode(
            [
                _FakeInstruction(
                    "invoke-virtual", [(Operand.REGISTER, 1), (_KIND_METH, 5, "Lcom/example/Foo;->bar()V")]
                ),
                _FakeInstruction("return-void", []),
            ]
        )
        code_b = _FakeCode(
            [
                _FakeInstruction(
                    "invoke-virtual", [(Operand.REGISTER, 1), (_KIND_METH, 777, "Lcom/example/Foo;->bar()V")]
                ),
                _FakeInstruction("return-void", []),
            ]
        )
        hash_a = _hash_method_code(code_a)
        hash_b = _hash_method_code(code_b)
        assert hash_a is not None
        assert hash_a == hash_b

    def test_hash_method_code_changes_for_real_semantic_difference(self) -> None:
        """A genuinely different constant changes the method hash."""
        code_a = _FakeCode([_FakeInstruction("const/4", [(Operand.REGISTER, 0), (Operand.LITERAL, 1)])])
        code_b = _FakeCode([_FakeInstruction("const/4", [(Operand.REGISTER, 0), (Operand.LITERAL, 2)])])
        assert _hash_method_code(code_a) != _hash_method_code(code_b)

    def test_unresolved_kind_falls_back_to_raw_index_deterministically(self) -> None:
        """An operand kind Androguard cannot resolve symbolically still normalizes deterministically."""
        ins = _FakeInstruction("invoke-polymorphic", [(_KIND_METH, 42, None)])
        rep1 = _normalize_instruction(ins)
        rep2 = _normalize_instruction(ins)
        assert rep1 == rep2
        assert rep1 == ("invoke-polymorphic", (("sym_unresolved", 0, 42),))

    @pytest.mark.skipif(not OPENLINK_APK.is_file(), reason="corpus APK not available")
    def test_dex_inspector_hashes_are_deterministic_on_real_apk(self) -> None:
        """Hashing the same real-world DEX twice yields identical method hashes."""
        insp1, _ = DEXInspector().inspect(OPENLINK_APK)
        insp2, _ = DEXInspector().inspect(OPENLINK_APK)

        def _hashes(insp):
            out = {}
            for df in insp.dex_files:
                if not df.inventory:
                    continue
                for m in df.inventory.methods:
                    out[(m.class_name, m.name)] = m.code_hash
            return out

        h1, h2 = _hashes(insp1), _hashes(insp2)
        assert h1 == h2
        assert any(v is not None for v in h1.values())
        # Methods without code (abstract/native/interface) hash to None.
        assert any(v is None for v in h1.values())


# ---------------------------------------------------------------------------
# 2. ComponentDiffer: enabled missing-vs-explicit-true normalization
# ---------------------------------------------------------------------------


class TestEnabledDefaultNormalization:
    """Android treats an absent android:enabled as enabled=True by default."""

    def test_activity_missing_to_explicit_true_is_unchanged(self) -> None:
        a = ActivityInfo(name="com.example.Main", enabled=None)
        b = ActivityInfo(name="com.example.Main", enabled=True)
        insp_a = InspectionResult(manifest=ManifestInspection(activities=[a]))
        insp_b = InspectionResult(manifest=ManifestInspection(activities=[b]))
        diff = ComponentDiffer().diff(insp_a, insp_b)
        assert diff.activities[0].change_type == ChangeType.UNCHANGED

    def test_activity_explicit_true_to_missing_is_unchanged(self) -> None:
        a = ActivityInfo(name="com.example.Main", enabled=True)
        b = ActivityInfo(name="com.example.Main", enabled=None)
        insp_a = InspectionResult(manifest=ManifestInspection(activities=[a]))
        insp_b = InspectionResult(manifest=ManifestInspection(activities=[b]))
        diff = ComponentDiffer().diff(insp_a, insp_b)
        assert diff.activities[0].change_type == ChangeType.UNCHANGED

    def test_activity_missing_to_false_is_modified(self) -> None:
        a = ActivityInfo(name="com.example.Main", enabled=None)
        b = ActivityInfo(name="com.example.Main", enabled=False)
        insp_a = InspectionResult(manifest=ManifestInspection(activities=[a]))
        insp_b = InspectionResult(manifest=ManifestInspection(activities=[b]))
        diff = ComponentDiffer().diff(insp_a, insp_b)
        assert diff.activities[0].change_type == ChangeType.MODIFIED

    def test_activity_false_to_missing_is_modified(self) -> None:
        a = ActivityInfo(name="com.example.Main", enabled=False)
        b = ActivityInfo(name="com.example.Main", enabled=None)
        insp_a = InspectionResult(manifest=ManifestInspection(activities=[a]))
        insp_b = InspectionResult(manifest=ManifestInspection(activities=[b]))
        diff = ComponentDiffer().diff(insp_a, insp_b)
        assert diff.activities[0].change_type == ChangeType.MODIFIED

    def test_service_true_to_false_is_modified(self) -> None:
        a = ServiceInfo(name="com.example.Svc", enabled=True)
        b = ServiceInfo(name="com.example.Svc", enabled=False)
        insp_a = InspectionResult(manifest=ManifestInspection(services=[a]))
        insp_b = InspectionResult(manifest=ManifestInspection(services=[b]))
        diff = ComponentDiffer().diff(insp_a, insp_b)
        assert diff.services[0].change_type == ChangeType.MODIFIED

    def test_service_false_to_true_is_modified(self) -> None:
        a = ServiceInfo(name="com.example.Svc", enabled=False)
        b = ServiceInfo(name="com.example.Svc", enabled=True)
        insp_a = InspectionResult(manifest=ManifestInspection(services=[a]))
        insp_b = InspectionResult(manifest=ManifestInspection(services=[b]))
        diff = ComponentDiffer().diff(insp_a, insp_b)
        assert diff.services[0].change_type == ChangeType.MODIFIED

    def test_service_missing_to_true_is_unchanged(self) -> None:
        a = ServiceInfo(name="com.example.Svc", enabled=None)
        b = ServiceInfo(name="com.example.Svc", enabled=True)
        insp_a = InspectionResult(manifest=ManifestInspection(services=[a]))
        insp_b = InspectionResult(manifest=ManifestInspection(services=[b]))
        diff = ComponentDiffer().diff(insp_a, insp_b)
        assert diff.services[0].change_type == ChangeType.UNCHANGED

    def test_receiver_missing_to_false_is_modified(self) -> None:
        a = BroadcastReceiverInfo(name="com.example.Rec", enabled=None)
        b = BroadcastReceiverInfo(name="com.example.Rec", enabled=False)
        insp_a = InspectionResult(manifest=ManifestInspection(receivers=[a]))
        insp_b = InspectionResult(manifest=ManifestInspection(receivers=[b]))
        diff = ComponentDiffer().diff(insp_a, insp_b)
        assert diff.receivers[0].change_type == ChangeType.MODIFIED

    def test_receiver_false_to_missing_is_modified(self) -> None:
        a = BroadcastReceiverInfo(name="com.example.Rec", enabled=False)
        b = BroadcastReceiverInfo(name="com.example.Rec", enabled=None)
        insp_a = InspectionResult(manifest=ManifestInspection(receivers=[a]))
        insp_b = InspectionResult(manifest=ManifestInspection(receivers=[b]))
        diff = ComponentDiffer().diff(insp_a, insp_b)
        assert diff.receivers[0].change_type == ChangeType.MODIFIED

    def test_receiver_missing_to_true_is_unchanged(self) -> None:
        a = BroadcastReceiverInfo(name="com.example.Rec", enabled=None)
        b = BroadcastReceiverInfo(name="com.example.Rec", enabled=True)
        insp_a = InspectionResult(manifest=ManifestInspection(receivers=[a]))
        insp_b = InspectionResult(manifest=ManifestInspection(receivers=[b]))
        diff = ComponentDiffer().diff(insp_a, insp_b)
        assert diff.receivers[0].change_type == ChangeType.UNCHANGED

    def test_provider_missing_to_false_is_modified(self) -> None:
        a = ContentProviderInfo(name="com.example.Prov", enabled=None)
        b = ContentProviderInfo(name="com.example.Prov", enabled=False)
        insp_a = InspectionResult(manifest=ManifestInspection(providers=[a]))
        insp_b = InspectionResult(manifest=ManifestInspection(providers=[b]))
        diff = ComponentDiffer().diff(insp_a, insp_b)
        assert diff.providers[0].change_type == ChangeType.MODIFIED

    def test_provider_missing_to_true_is_unchanged(self) -> None:
        a = ContentProviderInfo(name="com.example.Prov", enabled=None)
        b = ContentProviderInfo(name="com.example.Prov", enabled=True)
        insp_a = InspectionResult(manifest=ManifestInspection(providers=[a]))
        insp_b = InspectionResult(manifest=ManifestInspection(providers=[b]))
        diff = ComponentDiffer().diff(insp_a, insp_b)
        assert diff.providers[0].change_type == ChangeType.UNCHANGED


# ---------------------------------------------------------------------------
# 3. ComponentDiffer: directBootAware comparison (sibling attribute audit)
# ---------------------------------------------------------------------------


class TestDirectBootAwareComparison:
    def test_activity_direct_boot_aware_change_is_detected(self) -> None:
        a = ActivityInfo(name="com.example.Main", direct_boot_aware=False)
        b = ActivityInfo(name="com.example.Main", direct_boot_aware=True)
        insp_a = InspectionResult(manifest=ManifestInspection(activities=[a]))
        insp_b = InspectionResult(manifest=ManifestInspection(activities=[b]))
        diff = ComponentDiffer().diff(insp_a, insp_b)
        change = diff.activities[0]
        assert change.change_type == ChangeType.MODIFIED
        assert change.details["direct_boot_aware_before"] is False
        assert change.details["direct_boot_aware_after"] is True

    def test_activity_direct_boot_aware_unchanged(self) -> None:
        a = ActivityInfo(name="com.example.Main", direct_boot_aware=True)
        b = ActivityInfo(name="com.example.Main", direct_boot_aware=True)
        insp_a = InspectionResult(manifest=ManifestInspection(activities=[a]))
        insp_b = InspectionResult(manifest=ManifestInspection(activities=[b]))
        diff = ComponentDiffer().diff(insp_a, insp_b)
        assert diff.activities[0].change_type == ChangeType.UNCHANGED


# ---------------------------------------------------------------------------
# 4. FileDiffer: ARSC resource-identity rename pairing
# ---------------------------------------------------------------------------


def _make_pkg(input_path: Path, files: list[PackageFile]) -> AndroidPackage:
    return AndroidPackage(
        input_path=input_path,
        package_type=PackageType.APK,
        input_format=InputFormat.SINGLE_APK,
        files=files,
    )


class TestResourceIdentityRenamePairing:
    def test_resource_identity_pairs_differently_encoded_bytes(self, tmp_path: Path, monkeypatch) -> None:
        """Obfuscated path -> canonical path, same resource identity, different bytes -> RENAMED."""
        apk_a = tmp_path / "a.apk"
        apk_a.write_bytes(b"placeholder-a")
        apk_b = tmp_path / "b.apk"
        apk_b.write_bytes(b"placeholder-b")

        entry_a = PackageFile(
            path="res/bX.xml", size=100, compressed_size=100, category=FileCategory.RESOURCE, sha256="old_encoding"
        )
        entry_b = PackageFile(
            path="res/drawable/ic_call_answer.xml",
            size=120,
            compressed_size=120,
            category=FileCategory.RESOURCE,
            sha256="new_encoding",
        )

        insp_a = InspectionResult(input_path=apk_a, package=_make_pkg(apk_a, [entry_a]))
        insp_b = InspectionResult(input_path=apk_b, package=_make_pkg(apk_b, [entry_b]))

        def fake_identity_map(path: Path) -> dict[str, str]:
            if path == apk_a:
                return {"res/bX.xml": "drawable/ic_call_answer/"}
            if path == apk_b:
                return {"res/drawable/ic_call_answer.xml": "drawable/ic_call_answer/"}
            return {}

        monkeypatch.setattr("apkforge.diff.files.build_resource_identity_map", fake_identity_map)

        diff = FileDiffer().diff(insp_a, insp_b)

        assert diff.total_renamed == 1
        assert diff.total_added == 0
        assert diff.total_removed == 0
        renamed = diff.entries[0]
        assert renamed.change_type == ChangeType.RENAMED
        assert renamed.old_path == "res/bX.xml"
        assert renamed.path == "res/drawable/ic_call_answer.xml"
        assert renamed.details["match_basis"] == "resource_identity"
        assert renamed.details["content_changed"] is True

    def test_genuinely_different_resources_stay_remove_and_add(self, tmp_path: Path, monkeypatch) -> None:
        """Different canonical identities on each side must never be paired."""
        apk_a = tmp_path / "a.apk"
        apk_a.write_bytes(b"placeholder-a")
        apk_b = tmp_path / "b.apk"
        apk_b.write_bytes(b"placeholder-b")

        entry_a = PackageFile(
            path="res/aa.xml", size=50, compressed_size=50, category=FileCategory.RESOURCE, sha256="hash_a"
        )
        entry_b = PackageFile(
            path="res/drawable/unrelated.xml",
            size=60,
            compressed_size=60,
            category=FileCategory.RESOURCE,
            sha256="hash_b",
        )

        insp_a = InspectionResult(input_path=apk_a, package=_make_pkg(apk_a, [entry_a]))
        insp_b = InspectionResult(input_path=apk_b, package=_make_pkg(apk_b, [entry_b]))

        def fake_identity_map(path: Path) -> dict[str, str]:
            if path == apk_a:
                return {"res/aa.xml": "drawable/icon_one/"}
            if path == apk_b:
                return {"res/drawable/unrelated.xml": "drawable/icon_two/"}
            return {}

        monkeypatch.setattr("apkforge.diff.files.build_resource_identity_map", fake_identity_map)

        diff = FileDiffer().diff(insp_a, insp_b)

        assert diff.total_renamed == 0
        assert diff.total_removed == 1
        assert diff.total_added == 1

    def test_ambiguous_identity_match_is_not_paired(self, tmp_path: Path, monkeypatch) -> None:
        """Multiple candidates sharing one identity on either side must not be guessed."""
        apk_a = tmp_path / "a.apk"
        apk_a.write_bytes(b"placeholder-a")
        apk_b = tmp_path / "b.apk"
        apk_b.write_bytes(b"placeholder-b")

        entry_a1 = PackageFile(
            path="res/aa.xml", size=50, compressed_size=50, category=FileCategory.RESOURCE, sha256="hash_a1"
        )
        entry_a2 = PackageFile(
            path="res/bb.xml", size=55, compressed_size=55, category=FileCategory.RESOURCE, sha256="hash_a2"
        )
        entry_b = PackageFile(
            path="res/drawable/icon.xml", size=60, compressed_size=60, category=FileCategory.RESOURCE, sha256="hash_b"
        )

        insp_a = InspectionResult(input_path=apk_a, package=_make_pkg(apk_a, [entry_a1, entry_a2]))
        insp_b = InspectionResult(input_path=apk_b, package=_make_pkg(apk_b, [entry_b]))

        def fake_identity_map(path: Path) -> dict[str, str]:
            if path == apk_a:
                return {"res/aa.xml": "drawable/icon/", "res/bb.xml": "drawable/icon/"}
            if path == apk_b:
                return {"res/drawable/icon.xml": "drawable/icon/"}
            return {}

        monkeypatch.setattr("apkforge.diff.files.build_resource_identity_map", fake_identity_map)

        diff = FileDiffer().diff(insp_a, insp_b)

        assert diff.total_renamed == 0
        assert diff.total_removed == 2
        assert diff.total_added == 1
