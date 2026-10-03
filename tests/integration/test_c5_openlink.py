"""Phase C.5 integration: the real OpenLink APK through the controlled modification pipeline.

Real C.1/C.2/C.3 toolchain, real BuildService, real DiffEngine. Skipped when the
toolchain, the OpenLink corpus APK or the committed semantic no-op baseline is missing.

Since Phase E a modification is VERIFIED only against a content-aware (schema 2)
baseline (``phase-e-noise-baseline.json``); the C.5 schema-1 baseline is still used to
check that the recorded C.5 no-op classification is reproducible.
"""

from __future__ import annotations

import hashlib
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

import pytest

from apkforge.builders import BuildService, ToolchainConfig, ensure_dev_keystore
from apkforge.builders.semantic_baseline import (
    NoopSemanticBaseline,
    SemanticResult,
    run_semantic_noop,
)
from apkforge.diff.expectations import ObservationClass
from apkforge.modification.controlled import ModificationStatus, run_disable_boot_receiver

pytestmark = pytest.mark.integration

CORPUS_DIR = Path(__file__).resolve().parent.parent / "corpus"
OPENLINK = CORPUS_DIR / "de.audioattack.openlink_28.apk"
OPENLINK_SHA256 = "3d28923f08bd7173"  # prefix; full hash is checked against the manifest
NOOP_BASELINE = CORPUS_DIR / "results" / "c5-semantic-noop-baseline.json"
PHASE_E_BASELINE = CORPUS_DIR / "results" / "phase-e-noise-baseline.json"
BOOT = "android.permission.RECEIVE_BOOT_COMPLETED"
RECEIVER = "de.audioattack.openlink.conf.PackageChangeBroadcastReceiver"
OTHER_RECEIVER = "androidx.profileinstaller.ProfileInstallReceiver"
ANDROID = "{http://schemas.android.com/apk/res/android}"


@pytest.fixture(scope="module")
def real_service(tmp_path_factory: pytest.TempPathFactory) -> BuildService:
    base = tmp_path_factory.mktemp("c5")
    toolchain = ToolchainConfig.discover(framework_dir=base / "framework")
    if toolchain.keytool is None:
        pytest.skip("keytool not available")
    signing = ensure_dev_keystore(toolchain.keytool, base / "dev-key")
    service = BuildService(toolchain, signing, work_dir=base / "work")
    check = service.check_toolchain()
    if not check.valid:
        pytest.skip(f"Build toolchain unavailable: {check.errors}")
    return service


@pytest.fixture(scope="module")
def noop_baseline() -> NoopSemanticBaseline:
    if not OPENLINK.is_file():
        pytest.skip(f"Corpus sample missing: {OPENLINK}")
    if not NOOP_BASELINE.is_file():
        pytest.skip("C.5 semantic no-op baseline not generated")
    return NoopSemanticBaseline.model_validate_json(NOOP_BASELINE.read_text())


@pytest.fixture(scope="module")
def noise_baseline() -> NoopSemanticBaseline:
    """Phase E content-aware baseline (schema 2)."""
    if not OPENLINK.is_file():
        pytest.skip(f"Corpus sample missing: {OPENLINK}")
    if not PHASE_E_BASELINE.is_file():
        pytest.skip("Phase E noise baseline not generated")
    return NoopSemanticBaseline.model_validate_json(PHASE_E_BASELINE.read_text())


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _binary_manifest(apk: Path) -> ET.Element:
    from androguard.core.axml import AXMLPrinter

    with zipfile.ZipFile(apk) as z:
        xml = AXMLPrinter(z.read("AndroidManifest.xml")).get_xml()
    return ET.fromstring(xml)


def test_openlink_noop_reproduces_semantic_baseline(
    real_service: BuildService, noop_baseline: NoopSemanticBaseline, tmp_path: Path
) -> None:
    """The committed no-op classification for OpenLink is reproducible."""
    recorded = noop_baseline.entry_for(_sha(OPENLINK))
    assert recorded is not None and recorded.result == SemanticResult.EQUIVALENT
    fresh = run_semantic_noop(real_service, OPENLINK, entry_id=recorded.id, work_dir=tmp_path)
    assert fresh.result == recorded.result, fresh.unexpected
    assert fresh.noise_rule_counts == recorded.noise_rule_counts
    assert fresh.input_unchanged is True


def test_openlink_disable_boot_receiver(
    real_service: BuildService, noise_baseline: NoopSemanticBaseline, tmp_path: Path
) -> None:
    sha_before = _sha(OPENLINK)
    assert sha_before.startswith(OPENLINK_SHA256)
    out = tmp_path / "openlink-c5.apk"

    res = run_disable_boot_receiver(
        real_service,
        OPENLINK,
        noop_baseline=noise_baseline,
        work_dir=tmp_path / "work",
        output_apk=out,
    )
    assert res.status == ModificationStatus.VERIFIED, res.failures

    # Plan: target derived from the manifest, unrelated receiver left alone.
    plan = res.plan
    assert plan is not None and plan.receiver == RECEIVER
    assert all(p.satisfied for p in plan.preconditions)
    assert res.apply is not None and res.apply.applied and res.apply.matches_plan
    assert {e.element for e in res.apply.observed_edits} == {
        f"manifest/uses-permission[name={BOOT}]",
        f"manifest/application[0]/receiver[name={RECEIVER}]",
    }

    # Every BuildService stage passed; the APK verifies with the expected signer.
    assert [(s.stage, s.status) for s in res.stages] == [
        (s, "PASS") for s in ("prepare", "decode", "build", "align", "sign", "verify")
    ]
    ver = res.verification or {}
    assert ver.get("valid") and ver.get("zipalign_verified") and ver.get("signature_verified")
    assert ver.get("expected_signer_matched") and ver.get("zip_integrity_verified")

    # Expected vs actual: exactly the two planned changes plus baseline noise.
    v = res.verdict
    assert v is not None and v.passed, v.failures if v else None
    assert sorted(
        (c.observation.category, c.observation.identifier)
        for c in v.of(ObservationClass.EXPECTED_MODIFICATION)
    ) == [("component", RECEIVER), ("uses_permission", BOOT)]
    assert not v.of(ObservationClass.UNEXPECTED) and not v.of(ObservationClass.UNKNOWN)
    allowed = set(res.noise_floor["allowed_noise_rules"] or [])
    assert set(v.noise_rule_counts) <= allowed

    # Independent look at the artifact's binary manifest.
    assert out.is_file() and _sha(out) == res.output_sha256
    root = _binary_manifest(out)
    perms = {e.get(f"{ANDROID}name") for e in root.iter("uses-permission")}
    assert BOOT not in perms and perms  # other permissions are still there
    receivers = {e.get(f"{ANDROID}name"): e for e in root.iter("receiver")}
    assert receivers[RECEIVER].get(f"{ANDROID}enabled") == "false"
    assert receivers[OTHER_RECEIVER].get(f"{ANDROID}enabled") == "true"
    actions = [a.get(f"{ANDROID}name") for a in receivers[RECEIVER].iter("action")]
    assert actions == [
        "android.intent.action.BOOT_COMPLETED",
        "android.intent.action.MY_PACKAGE_REPLACED",
    ]

    # Original preserved; workspace removed.
    assert res.original_preserved and _sha(OPENLINK) == sha_before == res.original_sha256_after
    assert res.workspace is not None and not Path(res.workspace).exists()
