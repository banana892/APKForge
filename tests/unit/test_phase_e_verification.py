"""Phase E6: verification checks, matrix, report, CLI."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from apkforge.builders.models import BuildVerificationResult, CertificateInfo
from apkforge.cli.main import app
from apkforge.diff.expectations import ExpectedChange, verify_expectations
from apkforge.diff.models import (
    ChangeType,
    ComparatorResult,
    ComparisonStatus,
    FileDiff,
    FileEntryDiff,
    PermissionDiff,
)
from apkforge.diff.security import build_security_diff
from apkforge.verification import (
    CheckStatus,
    OverallStatus,
    VerificationCheck,
    VerificationMatrix,
    build_matrix,
    build_report,
    render_markdown,
    signature_check,
    structural_check,
    verify_pair,
)
from apkforge.verification.pair import check_baseline, classify
from tests.fixtures import create_synthetic_apk
from tests.unit.test_c5_expectations import (
    SIM_TOOLCHAIN,
    _diff,
    _rebuild_noise_files,
    noise_baseline,
)

SHA = "a" * 64
PASS = VerificationCheck(name="x", status=CheckStatus.PASSED, summary="ok")


def _row(name: str, status: CheckStatus = CheckStatus.PASSED) -> VerificationCheck:
    return VerificationCheck(name=name, status=status, summary=str(status))


def _matrix(diff=None, expected=None, *, baseline=None, structural=None, signature=None):  # type: ignore[no-untyped-def]
    diff = diff or _diff()
    expected = expected or []
    base = baseline or noise_baseline(SHA)
    chk = check_baseline(base, SHA, SIM_TOOLCHAIN)
    verdict = classify(diff, expected, base, chk, sha256=SHA, expected_signer="ab" * 32)
    return build_matrix(
        structural=structural or _row("structural"),
        signature=signature or _row("signature"),
        baseline=chk,
        diff=diff,
        verdict=verdict,
        security=build_security_diff(diff, verdict),
        expected=expected,
        modification=_row("modification"),
    ), verdict


class TestMatrix:
    def test_clean_noop_is_verified(self) -> None:
        d = _diff()
        d.comparisons["resource_table"] = ComparatorResult(
            comparator="resource_table", status=ComparisonStatus.NOT_COMPARABLE, complete=False
        )
        m, _ = _matrix(d)
        assert m.overall == OverallStatus.VERIFIED, m.overall_reason
        # resources.arsc is not comparable semantically, but byte-identical to the no-op
        assert m.checks["semantic_diff"].details["covered_by_content_identity"] == [
            "resource_table"
        ]

    def test_section_24_example_is_representable(self) -> None:
        m = VerificationMatrix()
        for name, st in (
            ("structural", CheckStatus.PASSED),
            ("signature", CheckStatus.PASSED),
            ("modification", CheckStatus.PASSED),
            ("expected_changes", CheckStatus.PASSED),
            ("unexpected_changes", CheckStatus.FAILED),
            ("semantic_diff", CheckStatus.PARTIAL),
            ("security_diff", CheckStatus.PARTIAL),
        ):
            m.checks[name] = _row(name, st)
        m.finalize()
        assert m.overall == OverallStatus.FAILED
        assert m.status("semantic_diff") == CheckStatus.PARTIAL

    def test_undeclared_manifest_change_fails(self) -> None:
        """Negative A: an undeclared permission removal is an unexpected change."""
        m, _ = _matrix(_diff(permissions=PermissionDiff(removed=["android.permission.X"])))
        assert m.overall == OverallStatus.FAILED
        assert m.status("unexpected_changes") == CheckStatus.FAILED
        assert m.status("security_diff") == CheckStatus.FAILED  # unexpected permission change

    def test_undeclared_file_fails(self) -> None:
        """Negative B."""
        extra = FileEntryDiff(
            path="assets/x.bin",
            change_type=ChangeType.ADDED,
            category="asset",
            size_after=1,
            sha256_after="1" * 64,
        )
        m, _ = _matrix(_diff(files=FileDiff(entries=[*_rebuild_noise_files(), extra])))
        assert m.overall == OverallStatus.FAILED
        assert "assets/x.bin" in " ".join(m.checks["unexpected_changes"].evidence)

    def test_missing_expected_change_fails(self) -> None:
        """Negative C."""
        exp = [
            ExpectedChange(
                category="uses_permission", kind="removed", identifier="android.permission.X"
            )
        ]
        m, _ = _matrix(expected=exp)
        assert m.overall == OverallStatus.FAILED
        assert m.status("expected_changes") == CheckStatus.FAILED

    def test_structural_and_signature_failures(self) -> None:
        """Negatives D and E."""
        m, _ = _matrix(structural=_row("structural", CheckStatus.FAILED))
        assert m.overall == OverallStatus.FAILED and "structural" in m.overall_reason
        m, _ = _matrix(signature=_row("signature", CheckStatus.FAILED))
        assert m.overall == OverallStatus.FAILED and "signature" in m.overall_reason

    def test_unsupported_comparison_is_undetermined(self) -> None:
        """Negative F: a comparator that cannot complete is never reported unchanged."""
        d = _diff()
        d.comparisons["dex"] = ComparatorResult(
            comparator="dex",
            status=ComparisonStatus.UNDETERMINED,
            complete=False,
            reason="inspector failed",
        )
        m, _ = _matrix(d)
        assert m.overall == OverallStatus.UNDETERMINED
        assert m.status("semantic_diff") == CheckStatus.UNDETERMINED

    def test_partial_comparator_is_partial(self) -> None:
        d = _diff()
        d.comparisons["strings"] = ComparatorResult(
            comparator="strings", status=ComparisonStatus.PARTIAL, complete=False
        )
        m, _ = _matrix(d)
        assert m.status("semantic_diff") == CheckStatus.PARTIAL
        assert m.overall == OverallStatus.UNDETERMINED

    def test_legacy_baseline_cannot_verify(self) -> None:
        from apkforge.builders.semantic_baseline import (
            NoopSemanticBaseline,
            NoopSemanticEntry,
            SemanticResult,
        )

        legacy = NoopSemanticBaseline(
            schema_version=1,
            entries=[
                NoopSemanticEntry(
                    id="x",
                    filename="x",
                    sha256=SHA,
                    build_success=True,
                    result=SemanticResult.EQUIVALENT,
                    noise_rule_counts=dict(verify_expectations(_diff(), []).noise_rule_counts),
                )
            ],
        )
        m, v = _matrix(baseline=legacy)
        assert v.mode == "path_rules"
        assert m.status("noise_baseline") == CheckStatus.PARTIAL
        assert m.status("unexpected_changes") == CheckStatus.PARTIAL
        assert m.overall == OverallStatus.UNDETERMINED

    def test_no_checks_is_undetermined(self) -> None:
        assert VerificationMatrix().finalize().overall == OverallStatus.UNDETERMINED


class TestChecks:
    def test_signature_check(self) -> None:
        good = BuildVerificationResult(
            valid=True,
            zipalign_verified=True,
            signature_verified=True,
            expected_signer_matched=True,
            zip_integrity_verified=True,
            manifest_present=True,
            certificate=CertificateInfo(signer_count=1, sha256_digest="ab" * 32, v2_scheme=True),
            expected_certificate_sha256="ab" * 32,
        )
        assert signature_check(good).status == CheckStatus.PASSED
        bad = BuildVerificationResult(
            signature_verified=False,
            zipalign_verified=True,
            zip_integrity_verified=True,
            errors=["does not verify"],
        )
        assert signature_check(bad).status == CheckStatus.FAILED
        other = BuildVerificationResult(
            signature_verified=True,
            zipalign_verified=True,
            zip_integrity_verified=True,
            expected_signer_matched=False,
        )
        assert signature_check(other).status == CheckStatus.FAILED
        assert signature_check(None).status == CheckStatus.UNDETERMINED  # never assumed valid

    @pytest.mark.parametrize(
        ("entries", "fragment"),
        [
            ({"classes.dex": b"dex\n035\x00"}, "AndroidManifest.xml missing"),
            ({"AndroidManifest.xml": b"<manifest/>"}, "AndroidManifest.xml"),
        ],
    )
    def test_structural_failures(
        self, tmp_path: Path, entries: dict[str, bytes], fragment: str
    ) -> None:
        p = tmp_path / "x.apk"
        with zipfile.ZipFile(p, "w") as z:
            for k, v in entries.items():
                z.writestr(k, v)
        c = structural_check(p)
        assert c.status == CheckStatus.FAILED and fragment in c.summary

    def test_structural_bad_dex_magic_and_truncated(self, tmp_path: Path) -> None:
        p = create_synthetic_apk(tmp_path / "a.apk", extra_files={"classes2.dex": b"nope"})
        c = structural_check(p)
        assert "classes2.dex: not a DEX file" in c.summary
        t = tmp_path / "t.apk"
        t.write_bytes(p.read_bytes()[: p.stat().st_size // 2])
        assert structural_check(t).status == CheckStatus.FAILED


class TestReport:
    def test_sections_and_schema(self) -> None:
        m, v = _matrix(_diff(permissions=PermissionDiff(removed=["android.permission.X"])))
        d = _diff(permissions=PermissionDiff(removed=["android.permission.X"]))
        r = build_report(
            diff=d,
            verdict=v,
            security=build_security_diff(d, v),
            matrix=m,
            baseline=None,
            toolchain=SIM_TOOLCHAIN,
            expected=[],
            original=Path("/home/user/secret/orig.apk"),
        )
        data = json.loads(r.model_dump_json())
        assert data["schema_version"] == 1 and data["kind"] == "apkforge.verification_report"
        assert "/home/user" not in r.model_dump_json()
        assert data["unexpected"][0]["identifier"] == "android.permission.X"
        md = render_markdown(r)
        for section in (
            "RAW DIFF",
            "NORMALIZED DIFF",
            "SEMANTIC DIFF",
            "SECURITY-RELEVANT DIFF",
            "EXPECTED CHANGES",
            "ACTUAL CHANGES",
            "UNEXPECTED CHANGES",
            "UNKNOWN / UNDETERMINED",
            "VERIFICATION",
            "LIMITATIONS",
            "Observed fact",
            "Inference",
            "Risk assessment",
            "Unknown",
        ):
            assert section in md, section
        assert "does not prove an APK is malware-free" in md


class TestPair:
    def test_pair_without_toolchain_or_baseline(self, tmp_path: Path) -> None:
        a = create_synthetic_apk(tmp_path / "a.apk")
        report, diff = verify_pair(a, a)
        # Synthetic APKs have text manifests: structurally invalid, never verified.
        assert report.verification.overall == OverallStatus.FAILED
        assert report.verification.checks["signature"].status == CheckStatus.UNDETERMINED
        assert diff is None


class TestCLI:
    def test_verify_json_has_no_ansi_even_with_force_color(self, tmp_path: Path) -> None:
        a = create_synthetic_apk(tmp_path / "a.apk")
        res = CliRunner(env={"FORCE_COLOR": "3"}).invoke(app, ["verify", str(a), "--json"])
        assert "\x1b[" not in res.stdout
        data = json.loads(res.stdout)
        assert data["overall"] in ("FAILED", "UNDETERMINED")
        assert res.exit_code in (1, 3)

    def test_diff_json_has_no_ansi_and_new_fields(self, tmp_path: Path) -> None:
        a = create_synthetic_apk(tmp_path / "a.apk")
        b = create_synthetic_apk(tmp_path / "b.apk", native_abis=["x86"])
        res = CliRunner(env={"FORCE_COLOR": "3"}).invoke(app, ["diff", str(a), str(b), "--json"])
        assert "\x1b[" not in res.stdout
        data = json.loads(res.stdout)
        assert data["schema_version"] == 2
        assert data["raw"]["counts"]["added"] == 1
        assert data["comparisons"]["manifest_tree"]["status"] == "undetermined"

    def test_diff_security_and_baseline_json(self, tmp_path: Path) -> None:
        a = create_synthetic_apk(tmp_path / "a.apk")
        b = create_synthetic_apk(tmp_path / "b.apk", native_abis=["x86"])
        bl = tmp_path / "baseline.json"
        bl.write_text(noise_baseline(SHA).model_dump_json())
        res = CliRunner().invoke(
            app, ["diff", str(a), str(b), "--json", "--security", "--baseline", str(bl)]
        )
        data = json.loads(res.stdout)
        assert set(data) == {"diff", "baseline", "normalized", "security"}
        assert data["baseline"]["status"] == "NO_ENTRY"  # baseline is for another APK
        subjects = [i["subject"] for i in data["security"]["sections"]["native_libraries"]["items"]]
        assert "lib/x86/libsample.so" in subjects


def test_signature_check_redacts_local_paths(tmp_path: Path) -> None:
    from types import SimpleNamespace

    from apkforge.verification import signature_check_with_service

    apk = tmp_path / "deep" / "x.apk"
    svc = SimpleNamespace(
        check_toolchain=lambda: SimpleNamespace(valid=True, errors=[]),
        verify=lambda p, **_: SimpleNamespace(
            verification=None, failure_cause=f"APK to verify is not a ZIP/APK archive: {apk}"
        ),
    )
    c = signature_check_with_service(svc, apk)
    assert c.status == CheckStatus.UNDETERMINED
    assert str(tmp_path) not in c.summary and "x.apk" in c.summary
