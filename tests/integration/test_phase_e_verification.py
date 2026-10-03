"""Phase E integration: diff + verification on real APKs with the real toolchain.

Skipped when the toolchain, the corpus APKs or the committed Phase E noise baseline
(``tests/corpus/results/phase-e-noise-baseline.json``) are missing.

A  OpenLink no-op rebuild verified against its content fingerprint
B  C.5 modification: counts derived from the baseline (not hard-coded)
C  undeclared manifest change (<meta-data>) fails; declared one verifies
D  marker asset, E both C.5 + marker (combined security diff)
H  content-hash protection: accepted-noise path with different content fails
I  invalid APK, J invalid signature, K baseline from another toolchain
F  (APKFORGE_CORPUS_BUILD=1) no-op rebuild of every corpus APK verified
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from apkforge.builders import BuildService, ToolchainConfig, ensure_dev_keystore
from apkforge.builders.corpus import CorpusManifest, resolve_entries
from apkforge.builders.models import BuildOptions
from apkforge.builders.semantic_baseline import (
    BaselineStatus,
    NoopSemanticBaseline,
    SemanticResult,
    current_toolchain_identity,
)
from apkforge.diff.expectations import ObservationClass
from apkforge.modification.builtin import BootReceiverModifier, MarkerAssetModifier
from apkforge.modification.catalog import ModifierCatalog
from apkforge.modification.pipeline import ModificationPipeline, ModifierRequest, PipelineStatus
from apkforge.verification import CheckStatus, OverallStatus, verify_pair
from tests.integration.phase_e_modifiers import (
    DeclaredMetaDataModifier,
    UndeclaredMetaDataModifier,
)
from tests.integration.phase_e_support import rezip, tamper_first
from tests.integration.test_c5_openlink import BOOT, OPENLINK, PHASE_E_BASELINE, RECEIVER, _sha

pytestmark = pytest.mark.integration

CORPUS_DIR = OPENLINK.parent


@pytest.fixture(scope="module")
def service(tmp_path_factory: pytest.TempPathFactory) -> BuildService:
    base = tmp_path_factory.mktemp("phase-e")
    toolchain = ToolchainConfig.discover(framework_dir=base / "framework")
    if toolchain.keytool is None:
        pytest.skip("keytool not available")
    svc = BuildService(
        toolchain, ensure_dev_keystore(toolchain.keytool, base / "key"), work_dir=base / "work"
    )
    if not svc.check_toolchain().valid:
        pytest.skip("Build toolchain unavailable")
    return svc


@pytest.fixture(scope="module")
def baseline() -> NoopSemanticBaseline:
    if not OPENLINK.is_file() or not PHASE_E_BASELINE.is_file():
        pytest.skip("OpenLink or the Phase E noise baseline is missing")
    return NoopSemanticBaseline.model_validate_json(PHASE_E_BASELINE.read_text())


@pytest.fixture(scope="module")
def noop(service: BuildService, tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("noop") / "openlink.noop.apk"
    res = service.build_pipeline(OPENLINK, BuildOptions(output_apk=out, overwrite_output=True))
    assert res.success, res.failure_cause
    return out


def _signer(service: BuildService, apk: Path) -> str:
    """SHA-256 of the certificate *apk* is signed with (this module's throwaway key)."""
    ver = service.verify(apk).verification
    assert ver is not None and ver.certificate is not None and ver.certificate.sha256_digest
    return ver.certificate.sha256_digest


def _pipeline(service: BuildService) -> ModificationPipeline:
    return ModificationPipeline(
        service,
        ModifierCatalog(
            [
                BootReceiverModifier(),
                MarkerAssetModifier(),
                UndeclaredMetaDataModifier(),
                DeclaredMetaDataModifier(),
            ]
        ),
    )


def _run(service: BuildService, baseline: NoopSemanticBaseline, tmp: Path, *ids: str):  # type: ignore[no-untyped-def]
    before = _sha(OPENLINK)
    res = _pipeline(service).run(
        OPENLINK,
        [ModifierRequest(modifier_id=i) for i in ids],
        noop_baseline=baseline,
        work_dir=tmp,
    )
    assert res.original_preserved and _sha(OPENLINK) == before
    return res


def test_a_noop_verified(service: BuildService, baseline: NoopSemanticBaseline, noop: Path) -> None:
    report, _ = verify_pair(
        OPENLINK,
        noop,
        baseline=baseline,
        service=service,
        build_toolchain=current_toolchain_identity(service),
        expected_signer=_signer(service, noop),
    )
    m = report.verification
    assert m.overall == OverallStatus.VERIFIED, m.overall_reason
    assert report.baseline is not None and report.baseline.status == BaselineStatus.COMPATIBLE
    assert report.normalized["noise_by_assurance"].get("path_rule") is None


def test_b_c5_counts_derived_from_baseline(
    service: BuildService, baseline: NoopSemanticBaseline, tmp_path: Path
) -> None:
    res = _run(service, baseline, tmp_path, "c5.disable_boot_receiver")
    assert res.status == PipelineStatus.VERIFIED, res.failures
    # build, align, sign and APK verification all passed
    assert [(s.stage, s.status) for s in res.stages] == [
        (s, "PASS") for s in ("prepare", "decode", "build", "align", "sign", "verify")
    ]
    assert res.apk_verified is True
    v = res.verdict
    assert v is not None and res.verification_matrix is not None
    assert res.verification_matrix.overall == OverallStatus.VERIFIED
    plan = res.modifiers[0].plan
    assert plan is not None
    assert len(v.expected_observed) == len(plan.expected_changes) == 2
    planned = {c.observation.identifier for c in v.of(ObservationClass.PLANNED_ENTRY)}
    assert planned == {"AndroidManifest.xml"}
    fp = baseline.entry_for(_sha(OPENLINK)).fingerprint  # type: ignore[union-attr]
    assert fp is not None
    derived = sum(1 for a in fp.accepted if not (a.category == "file" and a.identifier in planned))
    assert len(v.of(ObservationClass.REBUILD_NOISE)) == derived
    assert not v.of(ObservationClass.UNEXPECTED) and not v.of(ObservationClass.UNKNOWN)
    sec = res.report.security if res.report else None
    assert sec is not None
    perms = sec.sections["permissions"].items
    assert [(i.change, i.subject, i.classification) for i in perms] == [
        ("removed", BOOT, "expected_modification")
    ]
    comps = sec.sections["components"].items
    assert [(i.subject, i.classification) for i in comps] == [
        (f"receiver {RECEIVER}", "expected_modification")
    ]


def test_c_undeclared_manifest_element_fails(
    service: BuildService, baseline: NoopSemanticBaseline, tmp_path: Path
) -> None:
    res = _run(service, baseline, tmp_path, "test.undeclared_meta_data")
    assert res.status == PipelineStatus.FAILED
    v = res.verdict
    assert v is not None
    unexpected = [c.observation for c in v.of(ObservationClass.UNEXPECTED)]
    assert [(o.category, o.kind) for o in unexpected] == [("manifest_element", "added")]
    assert "meta-data[name=apkforge.test.phase_e]" in unexpected[0].identifier
    assert res.verification_matrix is not None
    assert res.verification_matrix.overall == OverallStatus.FAILED


def test_c2_declared_manifest_element_verified(
    service: BuildService, baseline: NoopSemanticBaseline, tmp_path: Path
) -> None:
    res = _run(service, baseline, tmp_path, "test.declared_meta_data")
    assert res.status == PipelineStatus.UNVERIFIED  # the test modifier has no verify()
    m = res.verification_matrix
    assert m is not None
    assert m.status("expected_changes") == CheckStatus.PASSED
    assert m.status("unexpected_changes") == CheckStatus.PASSED
    assert m.status("modification") == CheckStatus.UNDETERMINED


def test_e_combined_modifiers(
    service: BuildService, baseline: NoopSemanticBaseline, tmp_path: Path
) -> None:
    res = _run(service, baseline, tmp_path, "c5.disable_boot_receiver", "test.marker_asset")
    assert res.status == PipelineStatus.VERIFIED, res.failures
    assert res.report is not None and res.report.security is not None
    sections = {k for k, s in res.report.security.sections.items() if s.items}
    assert {"permissions", "components", "certificate"} <= sections
    assert len(res.report.requested) == 3


def test_h_content_hash_protection(
    service: BuildService, baseline: NoopSemanticBaseline, noop: Path, tmp_path: Path
) -> None:
    fp = baseline.entry_for(_sha(OPENLINK)).fingerprint  # type: ignore[union-attr]
    assert fp is not None
    candidates = [
        a.identifier
        for a in fp.accepted
        if a.category == "file" and a.kind == "renamed" and a.identifier.endswith(".xml")
    ]
    target, data = tamper_first(noop, candidates)
    unsigned, aligned, signed = (tmp_path / n for n in ("u.apk", "a.apk", "s.apk"))
    rezip(noop, unsigned, {target: data})
    assert service.align(unsigned, aligned).passed and service.sign(aligned, signed).passed
    report, _ = verify_pair(
        OPENLINK,
        signed,
        baseline=baseline,
        service=service,
        build_toolchain=current_toolchain_identity(service),
        expected_signer=_signer(service, noop),
    )
    assert report.verification.checks["signature"].status == CheckStatus.PASSED
    assert report.verification.overall == OverallStatus.FAILED
    assert [u["identifier"] for u in report.unexpected] == [target]
    # J: the same content change without re-signing breaks the signature.
    report_j, _ = verify_pair(OPENLINK, unsigned, baseline=baseline, service=service)
    assert report_j.verification.checks["signature"].status == CheckStatus.FAILED
    assert report_j.verification.overall == OverallStatus.FAILED


def test_i_invalid_apk(service: BuildService, noop: Path, tmp_path: Path) -> None:
    broken = tmp_path / "broken.apk"
    broken.write_bytes(noop.read_bytes()[: noop.stat().st_size // 2])
    report, diff = verify_pair(OPENLINK, broken, service=service)
    assert diff is None
    assert report.verification.checks["structural"].status == CheckStatus.FAILED
    assert report.verification.overall == OverallStatus.FAILED


def test_k_other_toolchain_baseline_is_incompatible(
    service: BuildService, baseline: NoopSemanticBaseline, noop: Path
) -> None:
    current = current_toolchain_identity(service)
    assert current is not None
    other = current.model_copy(update={"apktool": "2.10.0", "build_tools": "34.0.0"})
    report, _ = verify_pair(
        OPENLINK, noop, baseline=baseline, service=service, build_toolchain=other
    )
    assert report.baseline is not None
    assert report.baseline.status == BaselineStatus.INCOMPATIBLE
    assert report.verification.overall != OverallStatus.VERIFIED
    assert report.normalized["counts"]["rebuild_noise"] == 0


@pytest.mark.skipif(
    os.environ.get("APKFORGE_CORPUS_BUILD") != "1", reason="set APKFORGE_CORPUS_BUILD=1"
)
def test_f_corpus_noop_rebuilds_verify(
    service: BuildService, baseline: NoopSemanticBaseline, tmp_path: Path
) -> None:
    manifest = CorpusManifest.load(CORPUS_DIR / "manifest.json")
    resolved, _ = resolve_entries(manifest, CORPUS_DIR)
    toolchain = current_toolchain_identity(service)
    outcomes = {}
    for r in resolved:
        assert r.path is not None
        entry = baseline.entry_for(r.entry.sha256)
        assert entry is not None, r.entry.id
        out = tmp_path / f"{r.entry.id}.apk"
        res = service.build_pipeline(
            r.path, BuildOptions(output_apk=out, overwrite_output=True, work_dir=tmp_path / "w")
        )
        assert res.success, (r.entry.id, res.failure_cause)
        report, _ = verify_pair(
            r.path,
            out,
            baseline=baseline,
            service=service,
            build_toolchain=toolchain,
            expected_signer=_signer(service, out),
        )
        outcomes[r.entry.id] = report.verification.overall
        # Known rebuild noise never produces an unexplained change.
        assert not report.unexpected, (r.entry.id, report.unexpected[:3])
        expected = (
            OverallStatus.VERIFIED
            if entry.result != SemanticResult.UNDETERMINED
            else OverallStatus.UNDETERMINED
        )
        assert report.verification.overall == expected, (
            r.entry.id,
            report.verification.overall_reason,
        )
    assert outcomes


def test_cli_verify_pair_json(baseline: NoopSemanticBaseline, tmp_path: Path) -> None:
    """``apkforge verify ORIGINAL MODIFIED`` with the default (CLI) service and key."""
    import json

    from typer.testing import CliRunner

    from apkforge.cli.main import _build_service, app

    svc = _build_service(tmp_path / "w")
    if not svc.check_toolchain().valid:
        pytest.skip("Build toolchain unavailable")
    out = tmp_path / "noop.apk"
    res = svc.build_pipeline(OPENLINK, BuildOptions(output_apk=out, overwrite_output=True))
    assert res.success, res.failure_cause
    cli = CliRunner(env={"FORCE_COLOR": "3"}).invoke(
        app,
        [
            "verify",
            str(OPENLINK),
            str(out),
            "--baseline",
            str(PHASE_E_BASELINE),
            "--built-locally",
            "--json",
            "--work-dir",
            str(tmp_path / "w"),
        ],
    )
    assert "\x1b[" not in cli.stdout
    data = json.loads(cli.stdout)
    assert data["verification"]["overall"] == "VERIFIED", data["verification"]["overall_reason"]
    assert cli.exit_code == 0
