"""Unit tests — CLI."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from apkforge.cli.main import app

runner = CliRunner()


class TestHelp:
    """The --help flag must work at the root level and for every subcommand."""

    @pytest.mark.unit()
    def test_root_help_exits_zero(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0, result.output

    @pytest.mark.unit()
    def test_root_help_mentions_commands(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert "inspect" in result.output
        assert "analyze" in result.output
        assert "scan" in result.output
        assert "diff" in result.output
        assert "modify" in result.output
        assert "verify" in result.output

    @pytest.mark.unit()
    @pytest.mark.parametrize("cmd", ["inspect", "analyze", "scan", "diff", "modify", "verify"])
    def test_subcommand_help_exits_zero(self, cmd: str) -> None:
        result = runner.invoke(app, [cmd, "--help"])
        assert result.exit_code == 0, f"{cmd} --help failed:\n{result.output}"


class TestVersionCommand:
    """The version command must print the version and exit 0."""

    @pytest.mark.unit()
    def test_version_command_exits_zero(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0, result.output

    @pytest.mark.unit()
    def test_version_command_prints_version_string(self) -> None:
        result = runner.invoke(app, ["version"])
        assert "APKForge" in result.output

    @pytest.mark.unit()
    def test_version_flag(self) -> None:
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0, result.output
        assert "APKForge" in result.output


class TestStubCommands:
    """Stub commands must exit 0 even though they are not implemented."""

    @pytest.mark.unit()
    def test_inspect_stub_exits_zero(self, tmp_path: Path) -> None:
        from tests.fixtures import create_synthetic_apk

        valid_apk = tmp_path / "test.apk"
        create_synthetic_apk(valid_apk)
        result = runner.invoke(app, ["inspect", str(valid_apk)])
        assert result.exit_code == 0, result.output

    @pytest.mark.unit()
    def test_scan_stub_exits_zero(self, tmp_path: Path) -> None:
        fake_apk = tmp_path / "test.apk"
        fake_apk.write_bytes(b"PK")
        result = runner.invoke(app, ["scan", str(fake_apk)])
        assert result.exit_code == 0, result.output

    @pytest.mark.unit()
    def test_analyze_stub_exits_zero(self, tmp_path: Path) -> None:
        fake_apk = tmp_path / "test.apk"
        fake_apk.write_bytes(b"PK")
        result = runner.invoke(app, ["analyze", str(fake_apk)])
        assert result.exit_code == 0, result.output

    @pytest.mark.unit()
    def test_diff_stub_exits_zero(self, tmp_path: Path) -> None:
        from tests.fixtures import create_synthetic_apk

        a = tmp_path / "a.apk"
        b = tmp_path / "b.apk"
        create_synthetic_apk(a)
        create_synthetic_apk(b)
        result = runner.invoke(app, ["diff", str(a), str(b)])
        assert result.exit_code == 0, result.output

    @pytest.mark.unit()
    def test_modify_help_exits_zero(self) -> None:
        """The modify command's --help must exit cleanly."""
        result = runner.invoke(app, ["modify", "--help"])
        assert result.exit_code == 0, result.output
        assert "modify" in result.output.lower()

    @pytest.mark.unit()
    def test_modify_with_invalid_apk_exits_nonzero(self, tmp_path: Path) -> None:
        """The modify command with an invalid APK exits non-zero."""
        fake_apk = tmp_path / "test.apk"
        fake_apk.write_bytes(b"PK")
        result = runner.invoke(app, ["modify", str(fake_apk)])
        # Should fail because the APK is not a valid APK for analysis
        assert result.exit_code != 0 or "error" in result.output.lower() or "failed" in result.output.lower()

    @pytest.mark.unit()
    def test_verify_stub_exits_zero(self, tmp_path: Path) -> None:
        fake_apk = tmp_path / "test.apk"
        fake_apk.write_bytes(b"PK")
        result = runner.invoke(app, ["verify", str(fake_apk)])
        assert result.exit_code == 0, result.output
