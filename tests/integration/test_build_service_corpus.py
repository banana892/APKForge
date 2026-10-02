"""Integration tests: BuildService with the real Apktool / build-tools toolchain.

Skipped automatically when the toolchain or corpus is unavailable.

- Two small corpus APKs run by default (stage-by-stage assertions), plus the
  individually callable stage methods (Phase C.3) on the smallest APK.
- The full 9-APK no-op corpus runs when ``APKFORGE_CORPUS_BUILD=1`` (several minutes).
  ``build-tests/run_c2_corpus.py`` runs the same pipeline and records c2_results.json.

Framework and development key are provisioned into pytest temp directories so the
tests never touch the user's APKForge data directory.
"""

from __future__ import annotations

import os
import zipfile
from pathlib import Path

import pytest

from apkforge.builders import (
    BuildFailureCategory,
    BuildOptions,
    BuildResult,
    BuildService,
    BuildStage,
    SigningMode,
    StageResult,
    StageStatus,
    ToolchainConfig,
    ensure_dev_keystore,
)
from apkforge.builders.noop_integrity import compare_noop_rebuild

pytestmark = pytest.mark.integration

CORPUS_DIR = Path(__file__).resolve().parent.parent / "corpus"
CORPUS = sorted(CORPUS_DIR.glob("*.apk"))
SMALL = CORPUS_DIR / "com.oF2pks.applicationsinfo_19.apk"
OPENLINK = CORPUS_DIR / "de.audioattack.openlink_28.apk"


@pytest.fixture(scope="module")
def real_service(tmp_path_factory: pytest.TempPathFactory) -> BuildService:
    base = tmp_path_factory.mktemp("c2")
    toolchain = ToolchainConfig.discover(framework_dir=base / "framework")
    if toolchain.keytool is None:
        pytest.skip("keytool not available")
    signing = ensure_dev_keystore(toolchain.keytool, base / "dev-key")
    service = BuildService(toolchain, signing, work_dir=base / "work")
    check = service.check_toolchain()
    if not check.valid:
        pytest.skip(f"Build toolchain unavailable: {check.errors}")
    return service


def _stage_row(res: BuildResult) -> str:
    cells = " | ".join(f"{s.stage}={s.status}" for s in res.stages)
    return (
        f"{res.input_apk.name}: {cells} | {res.failure_category} | {res.failure_cause} "
        f"| evidence={res.failure_evidence} | log={res.log_file}"
    )


def _require(apk: Path) -> None:
    if not apk.is_file():
        pytest.skip(f"Corpus sample missing: {apk}")


def test_stage_by_stage_small_apk(real_service: BuildService) -> None:
    _require(SMALL)
    res = real_service.build_pipeline(SMALL, BuildOptions(keep_workspace_on_success=True))
    assert res.success, _stage_row(res)
    assert res.signing_mode == SigningMode.DEVELOPMENT and res.logs
    ws = res.workspace
    assert ws is not None

    by_stage = {s.stage: s for s in res.stages}
    assert list(by_stage) == list(BuildStage)
    assert all(s.status == StageStatus.PASS for s in res.stages), _stage_row(res)

    # decode
    assert (ws / "decoded" / "apktool.yml").is_file()
    assert (ws / "decoded" / "AndroidManifest.xml").is_file()
    assert "Apktool 3." in by_stage[BuildStage.DECODE].stdout
    # build
    assert zipfile.is_zipfile(ws / "build" / "unaligned.apk")
    # align
    assert "Verification succes" in by_stage[BuildStage.ALIGN].stdout
    # sign + verify
    v = res.verification
    assert v is not None and v.valid and v.zipalign_verified and v.signature_verified
    assert v.expected_signer_matched and v.zip_integrity_verified
    assert res.certificate and res.certificate.signer_count == 1
    assert res.certificate.subject_dn and "NOT FOR RELEASE" in res.certificate.subject_dn
    # input integrity
    assert res.input_unchanged is True

    integrity = compare_noop_rebuild(SMALL, ws / "signed" / "signed.apk")
    assert integrity["manifest"]["rebuilt_parseable"]
    assert integrity["manifest"]["identity_and_component_counts_match"]


def _ok(sr: StageResult) -> StageResult:
    assert sr.passed, (
        f"{sr.stage}: {sr.failure_category}: {sr.failure_cause} | evidence={sr.evidence} "
        f"| log={sr.log_file}"
    )
    return sr


def test_individual_stage_methods_real_toolchain(real_service: BuildService) -> None:
    """prepare_workspace -> decode -> build -> align -> sign -> verify, called one by one."""
    _require(SMALL)
    before = SMALL.read_bytes()

    ws, prep = real_service.prepare_workspace()
    _ok(prep)
    assert ws is not None

    dec = _ok(real_service.decode(SMALL, ws))
    assert dec.output_path == ws.decoded_dir and (ws.decoded_dir / "apktool.yml").is_file()
    assert "Apktool 3." in dec.stdout

    built = _ok(real_service.build(ws.decoded_dir, ws.unaligned_apk, workspace=ws))
    assert built.output_path == ws.unaligned_apk and zipfile.is_zipfile(ws.unaligned_apk)

    aligned = _ok(real_service.align(ws.unaligned_apk, ws.aligned_apk, workspace=ws))
    assert "Verification succes" in aligned.stdout

    # An aligned-but-unsigned APK must not verify.
    unsigned = real_service.verify(ws.aligned_apk, workspace=ws)
    assert unsigned.failure_category == BuildFailureCategory.VERIFICATION_FAILURE
    assert unsigned.verification and not unsigned.verification.signature_verified

    signed = _ok(real_service.sign(ws.aligned_apk, ws.signed_apk, workspace=ws))
    assert signed.certificate_sha256 and "Signing mode: development" in " ".join(signed.notes)

    ver = _ok(
        real_service.verify(
            ws.signed_apk, expected_certificate_sha256=signed.certificate_sha256, workspace=ws
        )
    )
    v = ver.verification
    assert v and v.valid and v.signature_verified and v.expected_signer_matched
    assert v.certificate and v.certificate.sha256_digest == signed.certificate_sha256
    assert "Verifies" in v.apksigner_output

    # A different expected signer must fail verification of the same APK.
    wrong = real_service.verify(ws.signed_apk, expected_certificate_sha256="00" * 32)
    assert wrong.failure_category == BuildFailureCategory.VERIFICATION_FAILURE

    assert SMALL.read_bytes() == before  # the original APK is never modified
    master = ws.master_log.read_text()
    for tag in ("[DECODE] completed", "[BUILD] completed", "[ALIGN] completed",
                "[SIGN] completed", "[VERIFY] passed"):  # fmt: skip
        assert tag in master, tag


def test_openlink_export_and_retention(real_service: BuildService, tmp_path: Path) -> None:
    _require(OPENLINK)
    out = tmp_path / "openlink-rebuilt.apk"
    res = real_service.build_pipeline(OPENLINK, BuildOptions(output_apk=out))
    assert res.success, _stage_row(res)
    assert res.output_apk == out and out.is_file()
    assert res.workspace is not None
    # default retention: intermediates removed, logs + metadata kept
    assert not (res.workspace / "decoded").exists()
    assert (res.workspace / "logs" / "build.log").is_file()
    assert (res.workspace / "metadata" / "result.json").is_file()


@pytest.mark.slow
@pytest.mark.skipif(
    os.environ.get("APKFORGE_CORPUS_BUILD") != "1", reason="set APKFORGE_CORPUS_BUILD=1"
)
@pytest.mark.parametrize("apk", CORPUS, ids=[p.stem for p in CORPUS])
def test_corpus_noop_rebuild(real_service: BuildService, apk: Path) -> None:
    res = real_service.build_pipeline(apk, BuildOptions())
    assert res.success, _stage_row(res)
    assert res.failure_category == BuildFailureCategory.SUCCESS
    assert res.input_unchanged is True
    assert res.output_apk is not None
    integrity = compare_noop_rebuild(apk, res.output_apk)
    assert integrity["native_libs"]["all_identical"], integrity["native_libs"]
    assert integrity["manifest"]["rebuilt_parseable"]
