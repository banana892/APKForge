"""Phase H.1 integration: reference analysis of real synthetic APKs.

Every fixture in ``tests/fixtures/h1_apks.py`` is built into a real APK with the
existing BuildService (Apktool 3.0.3) and analysed by decoding that APK again.
Skipped when the build toolchain is unavailable.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from apkforge.builders import BuildService, ToolchainConfig
from apkforge.cli.main import app
from apkforge.reference import (
    AbsenceConclusion,
    AnalysisState,
    Component,
    FieldAccess,
    InvokeKind,
    MatchBasis,
    NativeResolution,
    ReferenceAnalysisResult,
    ReferenceAnalysisService,
    ReferenceKind,
    ResolutionStatus,
    StringUse,
)
from tests.fixtures.h1_apks import FIXTURES, PKG, build_fixture

pytestmark = pytest.mark.integration

A, B, C = f"{PKG}.A", f"{PKG}.B", f"{PKG}.C"


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


@pytest.fixture(scope="module")
def service(tmp_path_factory: pytest.TempPathFactory) -> BuildService:
    base = tmp_path_factory.mktemp("h1")
    svc = BuildService(
        ToolchainConfig.discover(framework_dir=base / "framework"), work_dir=base / "ws"
    )
    if not svc.check_toolchain().valid:
        pytest.skip("Build toolchain unavailable")
    return svc


@pytest.fixture(scope="module")
def apks(service: BuildService, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    work = tmp_path_factory.mktemp("h1-fixtures")
    return {fx.name: build_fixture(service, fx, work) for fx in FIXTURES}


@pytest.fixture(scope="module")
def results(service: BuildService, apks: dict[str, Path]) -> dict[str, ReferenceAnalysisResult]:
    analyzer = ReferenceAnalysisService(service, work_dir=service.work_dir)
    out = {}
    for name, apk in apks.items():
        before = _sha(apk)
        out[name] = analyzer.analyze(apk)
        assert _sha(apk) == before, f"{name}: APK modified"
        assert out[name].original_unchanged is True
        assert not out[name].errors, out[name].errors
    return out


def test_all_fixtures_are_real_apks(apks: dict[str, Path]) -> None:
    assert len(apks) == 14
    for apk in apks.values():
        with zipfile.ZipFile(apk) as z:
            assert "classes.dex" in z.namelist()
            assert "AndroidManifest.xml" in z.namelist()


def test_workspaces_are_removed(service: BuildService, results: dict) -> None:
    leftovers = list(service.work_dir.iterdir()) if service.work_dir.exists() else []
    assert leftovers == []


def test_f01_isolated(results: dict[str, ReferenceAnalysisResult]) -> None:
    r = results["f01_isolated"]
    ix = r.index()
    q = ix.find_class_references(B)
    assert q.evidence == []
    assert q.analysis_state is AnalysisState.COMPLETE
    assert q.absence_established
    assert ix.callers_of(B) == []
    assert r.analysis_state is AnalysisState.COMPLETE
    aa = ix.assess_absence(B)
    assert aa.conclusion is AbsenceConclusion.NO_REFERENCES_WITHIN_SCOPE
    assert aa.absence_established
    assert "does not establish runtime behaviour" in aa.statement


def test_f02_class_reference(results: dict[str, ReferenceAnalysisResult]) -> None:
    ix = results["f02_class_ref"].index()
    q = ix.find_class_references(B)
    assert [(e.source_class, e.instruction) for e in q.evidence] == [(A, "instance-of")]
    ev = q.evidence[0]
    assert ev.source_method == "isB(Ljava/lang/Object;)Z"
    assert ev.source_file == "smali/com/example/h1/A.smali" and ev.source_line
    assert ev.source_dex == "classes.dex"
    assert ix.callers_of(B) == [A]
    assert ix.assess_absence(B).conclusion is AbsenceConclusion.REFERENCES_OBSERVED


def test_f03_multiple_callers(results: dict[str, ReferenceAnalysisResult]) -> None:
    ix = results["f03_multiple_callers"].index()
    assert ix.callers_of(B) == [A, C]
    assert {e.instruction for e in ix.find_class_references(B).evidence} == {"check-cast"}


def test_f04_method_reference(results: dict[str, ReferenceAnalysisResult]) -> None:
    ix = results["f04_method_ref"].index()
    q = ix.find_method_references(B, "bar", "()V")
    assert len(q.evidence) == 1
    ev = q.evidence[0]
    assert (ev.source_class, ev.source_method) == (A, "foo()V")
    assert ev.invoke_kind is InvokeKind.STATIC
    assert ev.parameter_types == () and ev.return_type == "void"
    assert ix.find_method_references(B, "bar", "(I)V").evidence == []
    assert ix.find_method_references(B, "other").evidence == []


def test_f05_field_reference(results: dict[str, ReferenceAnalysisResult]) -> None:
    ix = results["f05_field_ref"].index()
    q = ix.find_field_references(B, "counter", "I")
    assert sorted(e.access_kind for e in q.evidence) == [FieldAccess.SGET, FieldAccess.SPUT]
    assert all(e.source_class == A and e.return_type == "int" for e in q.evidence)


def test_f06_constructor(results: dict[str, ReferenceAnalysisResult]) -> None:
    ix = results["f06_constructor"].index()
    ctor = ix.find_constructor_references(B, "()V")
    assert [(e.kind, e.invoke_kind) for e in ctor.evidence] == [
        (ReferenceKind.CONSTRUCTOR_REFERENCE, InvokeKind.DIRECT)
    ]
    assert ix.find_method_references(B, "<init>").evidence == ctor.evidence
    instrs = {e.instruction for e in ix.find_class_references(B).evidence}
    assert {"new-instance", "invoke-direct"} <= instrs


def test_f07_const_class(results: dict[str, ReferenceAnalysisResult]) -> None:
    ix = results["f07_const_class"].index()
    q = ix.find_const_class_references(B)
    assert [(e.source_class, e.kind) for e in q.evidence] == [
        (A, ReferenceKind.CONST_CLASS_REFERENCE)
    ]
    assert any(e.instruction == "const-class" for e in ix.find_type_references(B).evidence)


def test_f08_string_is_not_a_class_reference(results: dict[str, ReferenceAnalysisResult]) -> None:
    ix = results["f08_string"].index()
    s = ix.find_string_references(B)
    assert len(s.evidence) == 1
    assert s.evidence[0].string_use is StringUse.POSSIBLE_CLASS_NAME
    assert ix.find_class_references(B).evidence == []
    assert ix.find_type_references(B).evidence == []
    aa = ix.assess_absence(B)
    assert aa.conclusion is AbsenceConclusion.ONLY_INDIRECT_EVIDENCE
    assert not aa.absence_established
    assert [e.kind for e in aa.indirect_evidence] == [ReferenceKind.STRING_REFERENCE]


def test_f09_reflection(results: dict[str, ReferenceAnalysisResult]) -> None:
    r = results["f09_reflection"]
    ix = r.index()
    hits = ix.find_reflection_evidence(B).evidence
    forname = [e for e in hits if e.reflection_api == "java.lang.Class.forName"]
    assert len(forname) == 1 and forname[0].resolution is ResolutionStatus.TARGET_IDENTIFIED
    string = ix.find_string_references(B).evidence[0]
    assert string.string_use is StringUse.POSSIBLE_REFLECTION_TARGET
    assert string.evidence_id in forname[0].associated_evidence
    # Class.newInstance() on the traced Class object resolves to B as well
    assert any(e.reflection_api == "java.lang.Class.newInstance" for e in hits)
    unknown = [e for e in r.reflection if e.resolution is ResolutionStatus.TARGET_UNKNOWN]
    assert [e.source_method for e in unknown] == [
        "loadDynamic(Ljava/lang/String;)Ljava/lang/Class;"
    ]
    # the dex is fully analysed, but unresolved reflection keeps absence unproven (spec §17)
    assert r.component_state(Component.DEX) is AnalysisState.COMPLETE
    assert r.component_state(Component.REFLECTION) is AnalysisState.PARTIAL
    q = ix.find_class_references(C)
    assert q.evidence == [] and not q.absence_established
    aa = ix.assess_absence(C)
    assert aa.conclusion is AbsenceConclusion.ABSENCE_NOT_ESTABLISHED
    assert "reflection analysis is PARTIAL" in aa.reasons
    assert ix.assess_absence(B).conclusion is AbsenceConclusion.ONLY_INDIRECT_EVIDENCE


def test_f10_native_method(results: dict[str, ReferenceAnalysisResult]) -> None:
    r = results["f10_native_method"]
    q = r.index().find_native_dependencies(B)
    assert [(e.kind, e.member_name) for e in q.evidence] == [
        (ReferenceKind.NATIVE_METHOD, "nativeCall")
    ]
    assert q.evidence[0].native_resolution is NativeResolution.UNKNOWN
    assert "Java_com_example_h1_B_nativeCall" in q.evidence[0].confidence_basis
    assert r.component_state(Component.NATIVE_CODE) is AnalysisState.NOT_ANALYZED
    aa = r.index().assess_absence(C)
    assert not aa.absence_established


def test_f11_load_library(results: dict[str, ReferenceAnalysisResult]) -> None:
    r = results["f11_load_library"]
    loads = [e for e in r.native if e.kind is ReferenceKind.NATIVE_LIBRARY_LOAD]
    assert len(loads) == 1
    ev = loads[0]
    assert (ev.library_name, ev.native_resolution) == ("h1native", NativeResolution.IDENTIFIED)
    assert (ev.source_class, ev.source_method) == (A, "<clinit>()V")
    assert "lib/arm64-v8a/libh1native.so" in ev.confidence_basis
    assert r.bundled_native_libraries == ["lib/arm64-v8a/libh1native.so"]
    assert r.component_state(Component.NATIVE_INDICATORS) is AnalysisState.COMPLETE
    assert r.component_state(Component.NATIVE_CODE) is AnalysisState.NOT_ANALYZED


def test_f12_manifest(results: dict[str, ReferenceAnalysisResult]) -> None:
    ix = results["f12_manifest"].index()
    b = ix.find_manifest_references(B).evidence
    assert [(e.instruction, e.context, e.match_basis) for e in b] == [
        ("service", "android:name", MatchBasis.CLASS_ATTRIBUTE)
    ]
    assert b[0].xml_location == "application#0/service[name=.B]"
    assert [e.instruction for e in ix.find_manifest_references(C).evidence] == ["receiver"]
    a = {(e.instruction, e.context) for e in ix.find_manifest_references(A).evidence}
    assert a == {("activity", "android:name"), ("activity-alias", "android:targetActivity")}
    assert ix.assess_absence(B).conclusion is AbsenceConclusion.REFERENCES_OBSERVED


def test_f13_resource(results: dict[str, ReferenceAnalysisResult]) -> None:
    ix = results["f13_resource"].index()
    b = ix.find_resource_references(B).evidence
    assert [(e.source_file, e.match_basis) for e in b] == [
        ("res/layout/main.xml", MatchBasis.XML_ELEMENT_NAME)
    ]
    assert b[0].source_line == 4 and b[0].xml_location == "/LinearLayout[1]/com.example.h1.B[1]"
    c = ix.find_resource_references(C).evidence
    assert [(e.source_file, e.match_basis) for e in c] == [
        ("assets/config.txt", MatchBasis.EMBEDDED_TOKEN)
    ]
    assert ix.assess_absence(B).conclusion is AbsenceConclusion.REFERENCES_OBSERVED
    # a textual asset mention is indirect evidence only
    assert ix.assess_absence(C).conclusion is AbsenceConclusion.ONLY_INDIRECT_EVIDENCE


def test_f14_incomplete_resources(results: dict[str, ReferenceAnalysisResult]) -> None:
    r = results["f14_incomplete"]
    assert [s.component for s in r.components[0].subcomponents] == [
        "dex:classes.dex",
        "dex:classes2.dex",
    ]
    assert r.component_state(Component.DEX) is AnalysisState.COMPLETE
    assert r.component_state(Component.ASSETS) is AnalysisState.PARTIAL
    assert r.analysis_state is AnalysisState.PARTIAL
    aa = r.index().assess_absence(B)
    assert aa.conclusion is AbsenceConclusion.ABSENCE_NOT_ESTABLISHED
    assert not aa.absence_established
    assert "assets analysis is PARTIAL" in aa.reasons


def test_f14_missing_decoded_dex(
    service: BuildService, apks: dict[str, Path], tmp_path: Path
) -> None:
    """Simulate a decode that lost classes2.dex: DEX becomes PARTIAL, nothing is proven."""
    apk = apks["f14_incomplete"]
    ws, _ = service.prepare_workspace(work_dir=tmp_path)
    assert ws is not None and service.decode(apk, ws).passed
    shutil.rmtree(ws.decoded_dir / "smali_classes2")
    with zipfile.ZipFile(apk) as z:
        entries = z.namelist()
    r = ReferenceAnalysisService.analyze_decoded(ws.decoded_dir, apk_entries=entries)
    sub = {s.component: s.state for s in r.components[0].subcomponents}
    assert sub == {"dex:classes.dex": AnalysisState.COMPLETE, "dex:classes2.dex": "UNKNOWN"}
    assert r.component_state(Component.DEX) is AnalysisState.PARTIAL
    ix = r.index()
    for target in (B, C):
        q = ix.find_class_references(target)
        assert q.evidence == [] and q.analysis_state is AnalysisState.PARTIAL
        assert not q.absence_established
        assert not ix.assess_absence(target).absence_established


def test_deterministic_results(
    service: BuildService, apks: dict[str, Path], results: dict[str, ReferenceAnalysisResult]
) -> None:
    analyzer = ReferenceAnalysisService(service, work_dir=service.work_dir)
    for name in ("f09_reflection", "f13_resource", "f14_incomplete"):
        again = analyzer.analyze(apks[name])
        assert again.to_json() == results[name].to_json()
        assert str(service.work_dir) not in again.to_json()
        assert str(apks[name].parent) not in again.to_json()


def test_json_roundtrip(results: dict[str, ReferenceAnalysisResult]) -> None:
    r = results["f09_reflection"]
    back = ReferenceAnalysisResult.model_validate_json(r.to_json())
    assert back.to_json() == r.to_json()
    assert back.index().callers_of(B) == r.index().callers_of(B)


def test_cli_json_is_ansi_free(
    apks: dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FORCE_COLOR", "3")
    apk = apks["f09_reflection"]
    before = _sha(apk)
    report = tmp_path / "r.md"
    res = CliRunner().invoke(
        app,
        [
            "references", str(apk), "--json", "--class", C, "--report", str(report),
            "--work-dir", str(tmp_path / "ws"),
        ],
    )  # fmt: skip
    assert res.exit_code == 0, res.output
    assert "\x1b" not in res.stdout
    data = json.loads(res.stdout)
    assert data["analysis_state"] == "PARTIAL"
    assert data["assessments"][0]["conclusion"] == "ABSENCE_NOT_ESTABLISHED"
    assert data["assessments"][0]["absence_established"] is False
    assert "references" not in data  # per-instruction list only with --all-evidence
    assert data["evidence_counts"]["REFLECTION_INDICATOR"] >= 2
    assert "ABSENCE_NOT_ESTABLISHED" in report.read_text()
    assert _sha(apk) == before

    full = CliRunner().invoke(
        app, ["references", str(apk), "--json", "--all-evidence", "--work-dir", str(tmp_path)]
    )
    assert full.exit_code == 0 and "\x1b" not in full.stdout
    assert json.loads(full.stdout)["references"]


def test_cli_skip_resources_not_analyzed(apks: dict[str, Path], tmp_path: Path) -> None:
    res = CliRunner().invoke(
        app,
        [
            "references", str(apks["f01_isolated"]), "--json", "--skip-resources",
            "-c", B, "--work-dir", str(tmp_path),
        ],
    )  # fmt: skip
    assert res.exit_code == 0, res.output
    data = json.loads(res.stdout)
    states = {c["component"]: c["state"] for c in data["components"]}
    assert states["resources"] == states["assets"] == "NOT_ANALYZED"
    assert data["analysis_state"] == "PARTIAL"
    assert data["assessments"][0]["conclusion"] == "ABSENCE_NOT_ESTABLISHED"
