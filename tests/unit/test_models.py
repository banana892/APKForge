"""Unit tests — Core models."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from apkforge.core.models import (
    AnalysisResult,
    AnalysisStatus,
    APKInput,
    Confidence,
    DiffChangeType,
    DiffEntry,
    DiffResult,
    Evidence,
    Finding,
    ModificationPlan,
    ModificationStep,
    ModificationStepStatus,
    Report,
    Severity,
    VerificationResult,
)


class TestAPKInput:
    """Tests for the APKInput model."""

    @pytest.mark.unit()
    def test_valid_apk_input(self, tmp_path: Path) -> None:
        apk = tmp_path / "test.apk"
        apk.write_bytes(b"PK")
        obj = APKInput(path=apk)
        assert obj.path == apk.resolve()
        assert obj.sha256 is None

    @pytest.mark.unit()
    def test_valid_sha256_accepted(self, tmp_path: Path) -> None:
        apk = tmp_path / "test.apk"
        apk.write_bytes(b"PK")
        digest = "a" * 64
        obj = APKInput(path=apk, sha256=digest)
        assert obj.sha256 == digest

    @pytest.mark.unit()
    def test_sha256_normalised_to_lowercase(self, tmp_path: Path) -> None:
        apk = tmp_path / "test.apk"
        apk.write_bytes(b"PK")
        obj = APKInput(path=apk, sha256="A" * 64)
        assert obj.sha256 == "a" * 64

    @pytest.mark.unit()
    def test_invalid_sha256_length_rejected(self, tmp_path: Path) -> None:
        apk = tmp_path / "test.apk"
        apk.write_bytes(b"PK")
        with pytest.raises(ValidationError):
            APKInput(path=apk, sha256="abc123")

    @pytest.mark.unit()
    def test_non_hex_sha256_rejected(self, tmp_path: Path) -> None:
        apk = tmp_path / "test.apk"
        apk.write_bytes(b"PK")
        with pytest.raises(ValidationError):
            APKInput(path=apk, sha256="z" * 64)

    @pytest.mark.unit()
    def test_string_path_resolved(self, tmp_path: Path) -> None:
        apk = tmp_path / "test.apk"
        apk.write_bytes(b"PK")
        obj = APKInput(path=str(apk))  # type: ignore[arg-type]
        assert obj.path == apk.resolve()

    @pytest.mark.unit()
    def test_label_accepted(self, tmp_path: Path) -> None:
        apk = tmp_path / "test.apk"
        apk.write_bytes(b"PK")
        obj = APKInput(path=apk, label="original")
        assert obj.label == "original"

    @pytest.mark.unit()
    def test_compute_sha256(self, tmp_path: Path) -> None:
        apk = tmp_path / "real.apk"
        apk.write_bytes(b"hello world")
        obj = APKInput(path=apk)
        digest = obj.compute_sha256()
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)

    @pytest.mark.unit()
    def test_frozen_model(self, tmp_path: Path) -> None:
        apk = tmp_path / "test.apk"
        apk.write_bytes(b"PK")
        obj = APKInput(path=apk)
        with pytest.raises((TypeError, ValidationError)):
            obj.sha256 = "x" * 64  # pyright: ignore


class TestAnalysisStatus:
    """Tests for the AnalysisStatus enum."""

    @pytest.mark.unit()
    def test_status_values(self) -> None:
        assert AnalysisStatus.COMPLETE.value == "complete"
        assert AnalysisStatus.PARTIAL.value == "partial"
        assert AnalysisStatus.FAILED.value == "failed"

    @pytest.mark.unit()
    def test_failed_is_not_clean(self) -> None:
        """Security invariant: FAILED status must never be 'clean'."""
        members = set(AnalysisStatus)
        assert AnalysisStatus.FAILED in members
        assert AnalysisStatus.PARTIAL in members
        assert len(members) == 3  # COMPLETE, PARTIAL, FAILED are distinct


class TestSeverityAndConfidence:
    @pytest.mark.unit()
    def test_severity_values(self) -> None:
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFORMATIONAL.value == "informational"

    @pytest.mark.unit()
    def test_confidence_values(self) -> None:
        assert Confidence.CONFIRMED.value == "confirmed"
        assert Confidence.HIGH.value == "high"
        assert Confidence.SPECULATIVE.value == "speculative"


class TestEvidence:
    @pytest.mark.unit()
    def test_minimal_evidence(self) -> None:
        ev = Evidence(description="Found suspicious string")
        assert ev.description == "Found suspicious string"
        assert ev.location is None
        assert ev.snippet is None
        assert ev.references == []

    @pytest.mark.unit()
    def test_full_evidence(self) -> None:
        ev = Evidence(
            description="Test",
            location="classes.dex:0x1234",
            snippet="invoke-virtual {v0}, Ljava/net/URL;->openConnection()V",
            references=["CWE-319"],
        )
        assert ev.location == "classes.dex:0x1234"

    @pytest.mark.unit()
    def test_snippet_length_limit(self) -> None:
        with pytest.raises(ValidationError):
            Evidence(description="test", snippet="x" * 5000)


class TestFinding:
    @pytest.mark.unit()
    def test_valid_finding(self) -> None:
        f = Finding(
            finding_id="NET-001",
            title="Cleartext HTTP",
            description="App uses cleartext HTTP.",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
        )
        assert f.finding_id == "NET-001"
        assert f.severity == Severity.HIGH

    @pytest.mark.unit()
    def test_finding_id_pattern_enforced(self) -> None:
        with pytest.raises(ValidationError):
            Finding(
                finding_id="invalid id with spaces",
                title="test",
                description="test",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
            )

    @pytest.mark.unit()
    def test_finding_with_evidence(self) -> None:
        ev = Evidence(description="HTTP endpoint found", location="strings.xml")
        f = Finding(
            finding_id="NET-001",
            title="Cleartext HTTP",
            description=".",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            evidence=[ev],
        )
        assert len(f.evidence) == 1
        assert f.evidence[0].location == "strings.xml"


class TestAnalysisResult:
    @pytest.mark.unit()
    def test_complete_result(self) -> None:
        r = AnalysisResult(module_name="test.module", status=AnalysisStatus.COMPLETE)
        assert r.findings == []
        assert r.errors == []

    @pytest.mark.unit()
    def test_failed_result_gets_default_error(self) -> None:
        r = AnalysisResult(module_name="test.module", status=AnalysisStatus.FAILED)
        assert len(r.errors) >= 1

    @pytest.mark.unit()
    def test_failed_result_with_explicit_error(self) -> None:
        r = AnalysisResult(
            module_name="test.module",
            status=AnalysisStatus.FAILED,
            errors=["DEX parsing failed"],
        )
        assert "DEX parsing failed" in r.errors


class TestDiffModels:
    @pytest.mark.unit()
    def test_diff_entry(self) -> None:
        entry = DiffEntry(path="classes.dex", change_type=DiffChangeType.MODIFIED)
        assert entry.change_type == DiffChangeType.MODIFIED

    @pytest.mark.unit()
    def test_diff_result(self, tmp_path: Path) -> None:
        a = tmp_path / "a.apk"
        b = tmp_path / "b.apk"
        a.write_bytes(b"PK")
        b.write_bytes(b"PK")
        dr = DiffResult(
            original=APKInput(path=a),
            modified=APKInput(path=b),
            status=AnalysisStatus.COMPLETE,
        )
        assert dr.entries == []


class TestModificationModels:
    @pytest.mark.unit()
    def test_modification_step_defaults(self) -> None:
        step = ModificationStep(step_id="PATCH-001", description="Remove tracker SDK")
        assert step.status == ModificationStepStatus.PENDING

    @pytest.mark.unit()
    def test_modification_plan(self, tmp_path: Path) -> None:
        apk = tmp_path / "test.apk"
        apk.write_bytes(b"PK")
        plan = ModificationPlan(
            plan_id="plan-001",
            source_apk=APKInput(path=apk),
        )
        assert plan.is_empty


class TestVerificationResult:
    @pytest.mark.unit()
    def test_failed_verification(self) -> None:
        vr = VerificationResult(
            status=AnalysisStatus.FAILED,
            checks_failed=["signature"],
        )
        assert vr.status == AnalysisStatus.FAILED
        assert "signature" in vr.checks_failed


class TestReport:
    @pytest.mark.unit()
    def test_empty_report_status_unchanged(self, tmp_path: Path) -> None:
        apk = tmp_path / "test.apk"
        apk.write_bytes(b"PK")
        r = Report(
            report_id="r-001",
            apk=APKInput(path=apk),
        )
        # No analysis results → overall_status stays at the default (FAILED)
        assert r.overall_status == AnalysisStatus.FAILED

    @pytest.mark.unit()
    def test_report_overall_status_complete(self, tmp_path: Path) -> None:
        apk = tmp_path / "test.apk"
        apk.write_bytes(b"PK")
        r = Report(
            report_id="r-002",
            apk=APKInput(path=apk),
            analysis_results=[
                AnalysisResult(module_name="mod.a", status=AnalysisStatus.COMPLETE),
                AnalysisResult(module_name="mod.b", status=AnalysisStatus.COMPLETE),
            ],
        )
        assert r.overall_status == AnalysisStatus.COMPLETE

    @pytest.mark.unit()
    def test_report_overall_status_degrades_to_partial(self, tmp_path: Path) -> None:
        apk = tmp_path / "test.apk"
        apk.write_bytes(b"PK")
        r = Report(
            report_id="r-003",
            apk=APKInput(path=apk),
            analysis_results=[
                AnalysisResult(module_name="mod.a", status=AnalysisStatus.COMPLETE),
                AnalysisResult(module_name="mod.b", status=AnalysisStatus.PARTIAL),
            ],
        )
        assert r.overall_status == AnalysisStatus.PARTIAL

    @pytest.mark.unit()
    def test_report_overall_status_degrades_to_failed(self, tmp_path: Path) -> None:
        apk = tmp_path / "test.apk"
        apk.write_bytes(b"PK")
        r = Report(
            report_id="r-004",
            apk=APKInput(path=apk),
            analysis_results=[
                AnalysisResult(module_name="mod.a", status=AnalysisStatus.COMPLETE),
                AnalysisResult(module_name="mod.b", status=AnalysisStatus.FAILED),
            ],
        )
        assert r.overall_status == AnalysisStatus.FAILED

    @pytest.mark.unit()
    def test_all_findings_sorted_by_severity(self, tmp_path: Path) -> None:
        apk = tmp_path / "test.apk"
        apk.write_bytes(b"PK")
        low = Finding(
            finding_id="L-001",
            title="Low",
            description=".",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
        )
        critical = Finding(
            finding_id="C-001",
            title="Critical",
            description=".",
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
        )
        r = Report(
            report_id="r-005",
            apk=APKInput(path=apk),
            analysis_results=[
                AnalysisResult(
                    module_name="mod.a",
                    status=AnalysisStatus.COMPLETE,
                    findings=[low, critical],
                ),
            ],
        )
        findings = r.all_findings
        assert findings[0].severity == Severity.CRITICAL
        assert findings[1].severity == Severity.LOW
