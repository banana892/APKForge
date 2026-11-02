"""``apkforge scan``: verdicts, exit codes, input collection and the CLI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from typer.testing import CliRunner

from apkforge.cli.main import app
from apkforge.core.models import AnalysisStatus, Confidence, Severity
from apkforge.security.models import SecurityFinding, SecurityResult
from apkforge.security.scan import ScanRecord, collect_apks, exit_code, judge, scan_apk
from tests.fixtures import create_synthetic_apk

if TYPE_CHECKING:
    import pytest


def _finding(fid: str, severity: Severity) -> SecurityFinding:
    return SecurityFinding(id=fid, category="c", title=f"t {fid}", description="d",
                           severity=severity, confidence=Confidence.HIGH)  # fmt: skip


def _result(*findings: SecurityFinding, status: AnalysisStatus = AnalysisStatus.COMPLETE
            ) -> SecurityResult:  # fmt: skip
    return SecurityResult(status=status, package_name="com.x", findings=list(findings))


def _judge(result: SecurityResult, fail_on: Severity | None = Severity.HIGH) -> ScanRecord:
    return judge(Path("a.apk"), result, min_severity=Severity.MEDIUM, fail_on=fail_on)


def test_verdicts(tmp_path: Path) -> None:
    low, med = _finding("L", Severity.LOW), _finding("M", Severity.MEDIUM)
    high, crit = _finding("H", Severity.HIGH), _finding("C", Severity.CRITICAL)
    assert _judge(_result(low, med)).verdict == "pass"
    assert _judge(_result(low, high)).verdict == "fail"
    assert _judge(_result(crit)).verdict == "fail"  # above the threshold fails too
    assert _judge(_result(crit), fail_on=None).verdict == "pass"
    assert _judge(_result(med), fail_on=Severity.MEDIUM).verdict == "fail"
    # an analysis that did not complete never passes: no findings proves nothing
    assert _judge(_result(status=AnalysisStatus.PARTIAL)).verdict == "incomplete"
    assert _judge(_result(status=AnalysisStatus.FAILED)).verdict == "error"
    assert _judge(_result(high, status=AnalysisStatus.PARTIAL)).verdict == "fail"


def test_findings_are_filtered_and_sorted_but_all_counted() -> None:
    record = _judge(_result(_finding("L", Severity.LOW), _finding("M", Severity.MEDIUM),
                            _finding("H", Severity.HIGH)))  # fmt: skip
    assert [f.id for f in record.findings] == ["H", "M"]  # most severe first, LOW hidden
    assert record.counts == {"high": 1, "medium": 1, "low": 1}
    assert record.worst_severity == Severity.HIGH


def test_an_exception_becomes_an_error_record() -> None:
    def boom(path: Path) -> SecurityResult:
        raise RuntimeError("corrupt")

    record = scan_apk(Path("x.apk"), boom, min_severity=Severity.MEDIUM, fail_on=Severity.HIGH)
    assert record.verdict == "error" and record.error == "RuntimeError: corrupt"


def test_exit_code_precedence() -> None:
    def rec(v: str) -> ScanRecord:
        return ScanRecord(path="p", verdict=v)  # type: ignore[arg-type]

    assert exit_code([rec("pass"), rec("pass")]) == 0
    assert exit_code([rec("pass"), rec("fail")]) == 1
    assert exit_code([rec("fail"), rec("incomplete")]) == 2  # unchecked APKs outrank a fail
    assert exit_code([rec("error")]) == 2


def test_collect_apks(tmp_path: Path) -> None:
    (tmp_path / "d" / "sub").mkdir(parents=True)
    for name in ("d/a.apk", "d/sub/b.XAPK", "d/sub/c.apks", "d/notes.txt", "single.bin"):
        (tmp_path / name).write_bytes(b"x")
    got = collect_apks([tmp_path / "d", tmp_path / "single.bin", tmp_path / "d" / "a.apk"])
    names = [p.relative_to(tmp_path).as_posix() for p in got]
    assert names == ["d/a.apk", "d/sub/b.XAPK", "d/sub/c.apks", "single.bin"]


def test_cli_scan_real_engine(tmp_path: Path) -> None:
    create_synthetic_apk(tmp_path / "apks" / "good.apk")
    (tmp_path / "apks" / "broken.apk").write_bytes(b"not a zip")
    res = CliRunner().invoke(app, ["scan", str(tmp_path / "apks"), "--json"])
    out = json.loads(res.stdout)
    verdicts = {r["path"].rsplit("/", 1)[1]: (r["verdict"], r["status"]) for r in out["apks"]}
    # the synthetic APK has no real DEX code: PARTIAL analysis, so it cannot pass
    assert verdicts == {"broken.apk": ("error", "failed"), "good.apk": ("incomplete", "partial")}
    assert res.exit_code == out["exit_code"] == 2


def test_cli_scan_gate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from apkforge.security.engine import SecurityEngine

    apk = create_synthetic_apk(tmp_path / "a.apk")
    found: list[SecurityFinding] = []
    monkeypatch.setattr(SecurityEngine, "analyze", lambda self, path: _result(*found))
    runner = CliRunner()
    res = runner.invoke(app, ["scan", str(apk)])
    assert res.exit_code == 0 and "1 scanned: 1 pass (fail on high+, exit 0)" in res.stdout

    found.append(_finding("SEC-X", Severity.HIGH))
    res = runner.invoke(app, ["scan", str(apk)])
    assert res.exit_code == 1 and "SEC-X" in res.stdout and "1 fail" in res.stdout
    assert runner.invoke(app, ["scan", str(apk), "--fail-on", "critical"]).exit_code == 0
    assert runner.invoke(app, ["scan", str(apk), "--fail-on", "none"]).exit_code == 0
    out = json.loads(runner.invoke(app, ["scan", str(apk), "--json"]).stdout)
    assert out["apks"][0]["findings"][0]["id"] == "SEC-X" and out["exit_code"] == 1

    assert runner.invoke(app, ["scan", str(apk), "--fail-on", "severe"]).exit_code == 2
    empty = tmp_path / "empty"
    empty.mkdir()
    res = runner.invoke(app, ["scan", str(empty)])
    assert res.exit_code == 2 and "No APK files found" in res.output
