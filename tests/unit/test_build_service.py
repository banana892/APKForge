"""Unit tests for BuildService (Phases C.2/C.3) and its components.

External tools are simulated by :class:`FakeToolRunner`, so these tests run
without Java, Apktool or the Android SDK. Real-tool coverage lives in
``tests/integration/test_build_service_corpus.py``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import stat
import sys
import threading
import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest

from apkforge.builders import (
    BuildFailureCategory,
    BuildOptions,
    BuildService,
    BuildStage,
    BuildWorkspace,
    CommandResult,
    CommandRunner,
    SigningConfig,
    StageStatus,
    ToolchainConfig,
    classify_stage_failure,
    ensure_dev_keystore,
    validate_toolchain,
)
from apkforge.builders.runner import EXEC_ERROR_RETURNCODE, MASK, TIMEOUT_RETURNCODE
from apkforge.builders.signing import SECRET_ENV_VAR
from apkforge.builders.toolchain import FRAMEWORK_MARKER, ensure_framework
from apkforge.core.exceptions import WorkspaceError

PASSWORD = "unit-test-secret-Zq81"
FAKE_CERT_DER = b"fake-certificate-der"
FAKE_CERT_SHA256 = hashlib.sha256(FAKE_CERT_DER).hexdigest()

Handler = Callable[[list[str], dict[str, str]], CommandResult | None]


def _cr(argv: list[str], rc: int = 0, out: str = "", err: str = "", **kw: object) -> CommandResult:
    return CommandResult(argv, rc, out, err, 0.01, "t0", "t1", **kw)  # type: ignore[arg-type]


def _arg_after(argv: list[str], flag: str) -> str:
    return argv[argv.index(flag) + 1]


class FakeToolRunner:
    """Simulates java/keytool/apktool/zipalign/apksigner by argv shape."""

    def __init__(self, tc: ToolchainConfig) -> None:
        self.tc = tc
        self.calls: list[tuple[list[str], dict[str, str]]] = []
        self.overrides: dict[str, Handler] = {}
        self.verify_digest = FAKE_CERT_SHA256

    def _action(self, argv: list[str]) -> str:
        prog = argv[0]
        if prog == str(self.tc.java) and "-jar" in argv:
            rest = argv[argv.index("-jar") + 2 :]
            return "apktool:" + (rest[0] if rest else "")
        if prog == str(self.tc.java):
            return "java:version"
        if prog == str(self.tc.keytool):
            return "keytool:" + argv[1]
        if prog == str(self.tc.zipalign):
            if len(argv) == 1:
                return "zipalign:usage"
            return "zipalign:check" if "-c" in argv else "zipalign:align"
        if prog == str(self.tc.apksigner):
            return "apksigner:" + argv[1]
        return "unknown"

    def run(
        self,
        argv: list[str],
        *,
        cwd: Path | None = None,
        env_overrides: dict[str, str] | None = None,
        timeout: int | None = None,
        log_path: Path | None = None,
        mask_strings: list[str] | None = None,
    ) -> CommandResult:
        argv = [str(a) for a in argv]
        env = dict(env_overrides or {})
        self.calls.append((argv, env))
        action = self._action(argv)
        handler = self.overrides.get(action)
        res = handler(argv, env) if handler else None
        if res is None:
            res = self._default(action, argv, env)
        if log_path is not None:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text(res.to_log_text(), encoding="utf-8")
        return res

    def _default(self, action: str, argv: list[str], env: dict[str, str]) -> CommandResult:
        if action == "java:version":
            return _cr(argv, err='openjdk version "25.0.4.1" 2025-10-21')
        if action == "apktool:--version":
            return _cr(argv, out="3.0.3\n")
        if action == "apktool:if":
            fw = Path(_arg_after(argv, "-p"))
            fw.mkdir(parents=True, exist_ok=True)
            (fw / "1.apk").write_bytes(b"framework")
            return _cr(argv, out=f"I: Framework installed to: {fw / '1.apk'}\n")
        if action == "apktool:d":
            out = Path(_arg_after(argv, "-o"))
            out.mkdir(parents=True)
            (out / "AndroidManifest.xml").write_text("<manifest/>")
            (out / "apktool.yml").write_text("version: 3.0.3\n")
            return _cr(
                argv, out="I: Using Apktool 3.0.3\nI: Loading resource table from file: fw/1.apk\n"
            )
        if action == "apktool:b":
            out = Path(_arg_after(argv, "-o"))
            with zipfile.ZipFile(out, "w") as z:
                z.writestr("AndroidManifest.xml", b"\x03\x00manifest")
                z.writestr("classes.dex", b"dex\n035")
            return _cr(argv, out=f"I: Built apk into: {out}\n")
        if action == "zipalign:usage":
            return _cr(
                argv,
                rc=2,
                err="Zip alignment utility\nCopyright (C) 2009 The Android Open Source Project\n",
            )
        if action == "zipalign:align":
            shutil.copyfile(argv[-2], argv[-1])
            return _cr(argv)
        if action == "zipalign:check":
            return _cr(
                argv, out=f"Verifying alignment of {argv[-1]} (4)...\nVerification succesful\n"
            )
        if action == "apksigner:--version":
            return _cr(argv, out="0.9\n")
        if action == "apksigner:sign":
            assert env.get(SECRET_ENV_VAR) == PASSWORD, "password must arrive via env, not argv"
            shutil.copyfile(argv[-1], _arg_after(argv, "--out"))
            return _cr(argv)
        if action == "apksigner:verify":
            return _cr(
                argv,
                out=(
                    "Verifies\n"
                    "Verified using v1 scheme (JAR signing): true\n"
                    "Verified using v2 scheme (APK Signature Scheme v2): true\n"
                    "Verified using v3 scheme (APK Signature Scheme v3): true\n"
                    "Verified using v3.1 scheme (APK Signature Scheme v3.1): false\n"
                    "Number of signers: 1\n"
                    "Signer #1 certificate DN: CN=APKForge Development Key - NOT FOR RELEASE\n"
                    f"Signer #1 certificate SHA-256 digest: {self.verify_digest}\n"
                    "WARNING: META-INF/a.version not protected by signature. Unauthorized ...\n"
                ),
                err="WARNING: A restricted method in java.lang.System has been called\n",
            )
        if action == "keytool:-exportcert":
            pem = base64.b64encode(FAKE_CERT_DER).decode()
            return _cr(argv, out=f"-----BEGIN CERTIFICATE-----\n{pem}\n-----END CERTIFICATE-----\n")
        if action == "keytool:-genkeypair":
            Path(_arg_after(argv, "-keystore")).write_bytes(b"p12")
            return _cr(argv)
        return _cr(argv, rc=1, err=f"FakeToolRunner: unhandled {action}")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def fake_sdk(tmp_path: Path) -> Path:
    sdk = tmp_path / "sdk"
    for v in ("34.0.0", "35.0.0"):
        bt = sdk / "build-tools" / v
        bt.mkdir(parents=True)
        (bt / "zipalign").write_text("#!fake")
        (bt / "apksigner").write_text("#!fake")
    for p in ("android-34", "android-35"):
        plat = sdk / "platforms" / p
        plat.mkdir(parents=True)
        (plat / "android.jar").write_bytes(p.encode())
    return sdk


@pytest.fixture()
def toolchain(tmp_path: Path, fake_sdk: Path) -> ToolchainConfig:
    jdk = tmp_path / "jdk" / "bin"
    jdk.mkdir(parents=True)
    for t in ("java", "keytool"):
        (jdk / t).write_text("#!fake")
    (tmp_path / "apktool_3.0.3.jar").write_bytes(b"jar")
    return ToolchainConfig.discover(
        java=jdk / "java",
        apktool=tmp_path / "apktool_3.0.3.jar",
        android_sdk=fake_sdk,
        framework_dir=tmp_path / "framework",
        environ={"PATH": ""},
    )


@pytest.fixture()
def signing(tmp_path: Path) -> SigningConfig:
    ks = tmp_path / "keys" / "dev.p12"
    ks.parent.mkdir()
    ks.write_bytes(b"p12")
    pw = tmp_path / "keys" / "dev.password"
    pw.write_text(PASSWORD + "\n")
    return SigningConfig(keystore=ks, alias="apkforge-dev", password_file=pw, development_key=True)


@pytest.fixture()
def input_apk(tmp_path: Path) -> Path:
    apk = tmp_path / "in" / "sample.apk"
    apk.parent.mkdir()
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("AndroidManifest.xml", b"\x03\x00original")
        z.writestr("lib/arm64-v8a/libx.so", b"\x7fELF")
    return apk


@pytest.fixture()
def runner(toolchain: ToolchainConfig) -> FakeToolRunner:
    return FakeToolRunner(toolchain)


@pytest.fixture()
def service(
    toolchain: ToolchainConfig, signing: SigningConfig, runner: FakeToolRunner, tmp_path: Path
) -> BuildService:
    return BuildService(toolchain, signing, runner=runner, work_dir=tmp_path / "work")  # type: ignore[arg-type]


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# CommandRunner (real subprocesses, Python only)
# ---------------------------------------------------------------------------


class TestCommandRunner:
    def test_success_and_log(self, tmp_path: Path) -> None:
        log = tmp_path / "x.log"
        res = CommandRunner().run(
            [sys.executable, "-c", "print('hello')"], log_path=log, cwd=tmp_path
        )
        assert res.ok and res.returncode == 0 and "hello" in res.stdout
        assert res.cwd == str(tmp_path) and res.start_time and res.end_time
        text = log.read_text()
        assert "EXIT CODE: 0" in text and "hello" in text and "DURATION:" in text

    def test_secrets_masked_everywhere(self, tmp_path: Path) -> None:
        log = tmp_path / "m.log"
        res = CommandRunner().run(
            [
                sys.executable,
                "-c",
                f"import os,sys; print('{PASSWORD}'); print(os.environ['S'], file=sys.stderr)",
            ],
            env_overrides={"S": "env-secret-value"},
            mask_strings=[PASSWORD],
            log_path=log,
        )
        blob = json.dumps([res.argv, res.stdout, res.stderr]) + log.read_text()
        assert PASSWORD not in blob and "env-secret-value" not in blob
        assert MASK in res.stdout and MASK in res.stderr
        assert res.env_overrides == ["S"]

    def test_timeout_keeps_partial_output(self) -> None:
        res = CommandRunner().run(
            [sys.executable, "-c", "import time; print('started', flush=True); time.sleep(30)"],
            timeout=2,
        )
        assert res.timed_out and res.returncode == TIMEOUT_RETURNCODE and not res.ok
        assert "started" in res.stdout
        assert "timed out" in res.stderr
        assert res.duration_seconds < 20

    def test_exec_error(self, tmp_path: Path) -> None:
        res = CommandRunner().run([tmp_path / "does-not-exist"])
        assert res.exec_error and res.returncode == EXEC_ERROR_RETURNCODE and not res.ok

    def test_stdin_is_closed(self) -> None:
        res = CommandRunner().run(
            [sys.executable, "-c", "import sys; print(repr(sys.stdin.read()))"], timeout=10
        )
        assert res.ok and res.stdout.strip() == "''"


# ---------------------------------------------------------------------------
# BuildWorkspace
# ---------------------------------------------------------------------------


class TestWorkspace:
    def test_layout_and_private_input_copy(self, tmp_path: Path, input_apk: Path) -> None:
        before = _sha(input_apk)
        ws = BuildWorkspace.create(tmp_path / "w")
        for d in ("input", "build", "aligned", "signed", "logs", "metadata"):
            assert (ws.root / d).is_dir()
        copy = ws.import_input(input_apk)
        assert copy.parent == ws.input_dir and _sha(copy) == before
        assert not os.access(copy, os.W_OK) or os.geteuid() == 0
        assert _sha(input_apk) == before
        assert ws.stage_log("build") != ws.master_log

    def test_unique_and_no_reuse(self, tmp_path: Path) -> None:
        a, b = BuildWorkspace.create(tmp_path), BuildWorkspace.create(tmp_path)
        assert a.root != b.root and a.build_id != b.build_id
        with pytest.raises(FileExistsError):
            BuildWorkspace.create(tmp_path, a.build_id)

    def test_traversal_guard(self, tmp_path: Path) -> None:
        ws = BuildWorkspace.create(tmp_path)
        assert ws.subpath("decoded", "res") == ws.root / "decoded" / "res"
        with pytest.raises(WorkspaceError):
            ws.subpath("..", "escape")
        with pytest.raises(WorkspaceError):
            ws.subpath("/etc/passwd")

    @pytest.mark.parametrize(
        ("success", "keep", "exported", "expect_gone", "expect_kept"),
        [
            (
                True,
                False,
                False,
                ["input", "decoded", "build", "aligned"],
                ["logs", "metadata", "signed"],
            ),
            (
                True,
                False,
                True,
                ["input", "decoded", "build", "aligned", "signed"],
                ["logs", "metadata"],
            ),
            (True, True, True, [], ["input", "decoded", "build", "aligned", "signed", "logs"]),
            (False, False, False, [], ["input", "decoded", "build", "aligned", "signed", "logs"]),
        ],
    )
    def test_retention(
        self, tmp_path: Path, input_apk: Path, success: bool, keep: bool, exported: bool,
        expect_gone: list[str], expect_kept: list[str],
    ) -> None:  # fmt: skip
        ws = BuildWorkspace.create(tmp_path)
        ws.import_input(input_apk)
        ws.decoded_dir.mkdir()
        ws.apply_retention(success=success, keep=keep, exported=exported)
        for d in expect_gone:
            assert not (ws.root / d).exists(), d
        for d in expect_kept:
            assert (ws.root / d).exists(), d


# ---------------------------------------------------------------------------
# Toolchain configuration, discovery, validation, framework
# ---------------------------------------------------------------------------


class TestToolchain:
    def test_discover_prefers_latest_sdk_components(
        self, toolchain: ToolchainConfig, fake_sdk: Path
    ) -> None:
        assert toolchain.build_tools == fake_sdk / "build-tools" / "35.0.0"
        assert toolchain.zipalign == fake_sdk / "build-tools" / "35.0.0" / "zipalign"
        assert toolchain.apksigner == fake_sdk / "build-tools" / "35.0.0" / "apksigner"
        assert toolchain.android_platform == fake_sdk / "platforms" / "android-35" / "android.jar"
        assert toolchain.platform_name == "android-35" and toolchain.platform_api == 35
        assert toolchain.keytool == toolchain.java.parent / "keytool"  # type: ignore[union-attr]

    def test_discover_env_pins_and_defaults(self, tmp_path: Path, fake_sdk: Path) -> None:
        jar = tmp_path / "apktool.jar"
        jar.write_bytes(b"jar")
        env = {
            "PATH": "",
            "ANDROID_HOME": str(fake_sdk),
            "APKFORGE_BUILD_TOOLS_VERSION": "34.0.0",
            "APKFORGE_ANDROID_PLATFORM": "android-34",
            "APKFORGE_APKTOOL": str(jar),
            "APKFORGE_JAVA": str(tmp_path / "java"),
            "XDG_DATA_HOME": str(tmp_path / "xdg"),
        }
        cfg = ToolchainConfig.discover(environ=env)
        assert cfg.build_tools_version == "34.0.0" and cfg.platform_name == "android-34"
        assert cfg.apktool_command() == [str(tmp_path / "java"), "-jar", str(jar)]
        assert (
            cfg.framework_dir == tmp_path / "xdg" / "apkforge" / "apktool-framework" / "android-34"
        )

    def test_discover_executable_apktool(self, tmp_path: Path) -> None:
        exe = tmp_path / "apktool"
        exe.write_text("#!/bin/sh")
        cfg = ToolchainConfig.discover(
            apktool=exe, android_sdk=tmp_path / "none", environ={"PATH": ""}
        )
        assert cfg.apktool_command() == [str(exe)]

    def test_validate_reports_every_missing_tool(self, tmp_path: Path) -> None:
        cfg = ToolchainConfig(framework_dir=tmp_path / "fw")
        res = validate_toolchain(cfg, runner=FakeToolRunner(cfg))  # type: ignore[arg-type]
        assert not res.valid and res.unavailable_only
        assert res.failure_category == BuildFailureCategory.TOOL_UNAVAILABLE
        for name in (
            "java",
            "keytool",
            "apktool",
            "android_sdk",
            "build_tools",
            "android_platform",
            "zipalign",
            "apksigner",
        ):
            assert res.tools[name].status == "MISSING", name
            assert any(e.startswith(f"{name}:") for e in res.errors), name

    def test_validate_reports_versions(self, toolchain: ToolchainConfig) -> None:
        res = validate_toolchain(toolchain, runner=FakeToolRunner(toolchain))  # type: ignore[arg-type]
        assert res.valid, res.errors
        t = res.tools
        assert t["java"].version == "25.0.4.1"
        assert t["apktool"].version == "3.0.3"
        assert t["build_tools"].version == "35.0.0" and t["zipalign"].version == "35.0.0"
        assert t["android_platform"].version == "android-35"
        assert t["apksigner"].version == "0.9"
        assert t["apktool_framework"].status == "NOT_INSTALLED"

    def test_validate_rejects_apktool_2(self, toolchain: ToolchainConfig) -> None:
        fake = FakeToolRunner(toolchain)
        fake.overrides["apktool:--version"] = lambda a, e: _cr(a, out="2.10.0\n")
        res = validate_toolchain(toolchain, runner=fake)  # type: ignore[arg-type]
        assert not res.valid and res.tools["apktool"].status == "UNSUPPORTED"
        assert "3.0.3" in res.tools["apktool"].notes

    def test_validate_broken_tool(self, toolchain: ToolchainConfig) -> None:
        fake = FakeToolRunner(toolchain)
        fake.overrides["apksigner:--version"] = lambda a, e: _cr(a, rc=1, err="boom")
        res = validate_toolchain(toolchain, runner=fake)  # type: ignore[arg-type]
        assert not res.valid and res.tools["apksigner"].status == "BROKEN"

    def test_missing_platform_is_framework_failure(self, toolchain: ToolchainConfig) -> None:
        toolchain.android_platform = None
        res = validate_toolchain(toolchain, runner=FakeToolRunner(toolchain))  # type: ignore[arg-type]
        assert not res.valid and res.framework_only
        assert res.failure_category == BuildFailureCategory.FRAMEWORK_FAILURE

    def test_old_platform_warns(self, toolchain: ToolchainConfig, fake_sdk: Path) -> None:
        toolchain.android_platform = fake_sdk / "platforms" / "android-34" / "android.jar"
        res = validate_toolchain(toolchain, runner=FakeToolRunner(toolchain))  # type: ignore[arg-type]
        assert res.valid and any("android-34" in w for w in res.warnings)

    def test_framework_provisioning_is_idempotent_and_tracks_source(
        self, toolchain: ToolchainConfig
    ) -> None:
        fake = FakeToolRunner(toolchain)
        ok, res, _ = ensure_framework(toolchain, fake)  # type: ignore[arg-type]
        assert ok and res is not None
        fw = toolchain.framework_dir
        assert fw is not None and (fw / "1.apk").exists()
        marker = json.loads((fw / FRAMEWORK_MARKER).read_text())
        assert marker["platform"] == "android-35" and marker["source"] == str(
            toolchain.android_platform
        )

        n = len(fake.calls)
        ok, res, msg = ensure_framework(toolchain, fake)  # type: ignore[arg-type]
        assert ok and res is None and len(fake.calls) == n and "current" in msg

        toolchain.android_platform.write_bytes(b"different platform")  # type: ignore[union-attr]
        ok, res, _ = ensure_framework(toolchain, fake)  # type: ignore[arg-type]
        assert ok and res is not None and len(fake.calls) == n + 1


# ---------------------------------------------------------------------------
# Signing configuration
# ---------------------------------------------------------------------------


class TestSigning:
    def test_validate(self, tmp_path: Path, signing: SigningConfig) -> None:
        assert signing.validate() == []
        assert any(
            "Keystore not found" in e
            for e in SigningConfig(tmp_path / "x.p12", "a", password_env="P").validate()
        )
        assert any(
            "No password source" in e for e in SigningConfig(signing.keystore, "a").validate()
        )
        assert any(
            "not set" in e
            for e in SigningConfig(signing.keystore, "a", password_env="P").validate(environ={})
        )
        assert any(
            "alias" in e
            for e in SigningConfig(
                signing.keystore, "", password_file=signing.password_file
            ).validate()
        )

    def test_resolve_password_and_describe(self, signing: SigningConfig) -> None:
        assert signing.resolve_password() == PASSWORD
        env_cfg = SigningConfig(signing.keystore, "a", password_env="MY_PW")
        assert env_cfg.resolve_password(environ={"MY_PW": "pw2"}) == "pw2"
        assert PASSWORD not in signing.describe() and PASSWORD not in repr(signing)

    def test_from_env(self, tmp_path: Path) -> None:
        assert SigningConfig.from_env(environ={}) is None
        cfg = SigningConfig.from_env(
            environ={
                "APKFORGE_SIGNING_KEYSTORE": str(tmp_path / "k.p12"),
                "APKFORGE_SIGNING_ALIAS": "rel",
                "APKFORGE_SIGNING_PASSWORD_ENV": "KS_PW",
            }
        )
        assert cfg is not None and cfg.alias == "rel" and cfg.password_env == "KS_PW"
        assert not cfg.development_key

    def test_dev_keystore_generation_keeps_secret_off_argv(
        self, tmp_path: Path, toolchain: ToolchainConfig
    ) -> None:
        fake = FakeToolRunner(toolchain)
        cfg = ensure_dev_keystore(toolchain.keytool, tmp_path / "dev", runner=fake)  # type: ignore[arg-type]
        assert cfg.development_key and cfg.keystore.is_file() and cfg.password_file is not None
        assert stat.S_IMODE(cfg.password_file.stat().st_mode) == 0o600
        assert stat.S_IMODE((tmp_path / "dev").stat().st_mode) == 0o700
        password = cfg.resolve_password()
        assert len(password) >= 32
        argv, env = fake.calls[-1]
        assert password not in " ".join(argv) and env[SECRET_ENV_VAR] == password
        assert "-storepass:env" in argv
        # second call reuses the existing key
        assert ensure_dev_keystore(toolchain.keytool, tmp_path / "dev", runner=fake) == cfg  # type: ignore[arg-type]
        assert len(fake.calls) == 1

    @pytest.mark.skipif(shutil.which("keytool") is None, reason="keytool not installed")
    def test_dev_keystore_with_real_keytool(self, tmp_path: Path) -> None:
        cfg = ensure_dev_keystore(Path(shutil.which("keytool")), tmp_path / "dev")  # type: ignore[arg-type]
        assert cfg.validate() == []


# ---------------------------------------------------------------------------
# Failure classification
# ---------------------------------------------------------------------------


class TestClassification:
    def test_c1_missing_app_attribute_is_resource_failure(self) -> None:
        out = "W: res/color/m3_list_item_background_color_selector.xml:3: error: attribute state_swiped (aka eu.siacs.conversations:state_swiped) not found.\nerror: failed linking file resources.\n"  # noqa: E501 - verbatim tool output
        d = classify_stage_failure(BuildStage.BUILD, _cr(["apktool"], rc=1, out=out))
        assert d.category == BuildFailureCategory.RESOURCE_FAILURE and d.classified
        assert d.evidence and "state_swiped" in d.evidence

    @pytest.mark.parametrize(
        "line",
        [
            "W: AndroidManifest.xml:175: error: attribute android:allow not found.",
            "W: res/values-v35/styles.xml:8: error: style attribute 'android:attr/windowOptOutEdgeToEdgeEnforcement' not found.",  # noqa: E501 - verbatim tool output
        ],
    )
    def test_c1b_missing_android_attribute_is_framework_failure(self, line: str) -> None:
        d = classify_stage_failure(
            BuildStage.BUILD,
            _cr(["apktool"], rc=1, out=line + "\nerror: failed linking references.\n"),
        )
        assert d.category == BuildFailureCategory.FRAMEWORK_FAILURE

    def test_framework_path_in_info_output_is_not_a_framework_failure(self) -> None:
        # Apktool always prints the framework path; that alone must not mean FRAMEWORK_FAILURE.
        out = "I: Loading resource table from file: /home/u/.local/share/apkforge/apktool-framework/android-35/1.apk\n"  # noqa: E501 - verbatim tool output
        d = classify_stage_failure(
            BuildStage.DECODE,
            _cr(["apktool"], rc=1, out=out, err="Exception in thread main: something odd\n"),
        )
        assert d.category == BuildFailureCategory.DECODE_FAILURE and not d.classified
        assert d.evidence == "Exception in thread main: something odd"

    def test_decode_resource_failure(self) -> None:
        d = classify_stage_failure(
            BuildStage.DECODE,
            _cr(
                ["apktool"],
                rc=1,
                err="brut.androlib.res.decoder.ARSCDecoder$Foo: AndrolibException: bad chunk",
            ),
        )
        assert d.category == BuildFailureCategory.RESOURCE_FAILURE

    def test_timeout_and_exec_error(self) -> None:
        t = classify_stage_failure(
            BuildStage.BUILD, _cr(["x"], rc=TIMEOUT_RETURNCODE, out="I: Smaling...", timed_out=True)
        )
        assert t.category == BuildFailureCategory.TIMEOUT and t.evidence == "I: Smaling..."
        e = classify_stage_failure(
            BuildStage.DECODE, _cr(["x"], rc=-1, exec_error="FileNotFoundError: x")
        )
        assert e.category == BuildFailureCategory.TOOLCHAIN_FAILURE

    def test_java_too_old_is_toolchain_failure(self) -> None:
        d = classify_stage_failure(
            BuildStage.DECODE,
            _cr(["java"], rc=1, err="java.lang.UnsupportedClassVersionError: brut/apktool/Main"),
        )
        assert d.category == BuildFailureCategory.TOOLCHAIN_FAILURE

    @pytest.mark.parametrize(
        ("stage", "category"),
        [
            (BuildStage.ALIGN, BuildFailureCategory.ALIGNMENT_FAILURE),
            (BuildStage.SIGN, BuildFailureCategory.SIGNING_FAILURE),
            (BuildStage.VERIFY, BuildFailureCategory.VERIFICATION_FAILURE),
            (BuildStage.BUILD, BuildFailureCategory.BUILD_FAILURE),
        ],
    )
    def test_unknown_errors_fall_back_to_stage_category(
        self, stage: BuildStage, category: BuildFailureCategory
    ) -> None:
        d = classify_stage_failure(
            stage,
            _cr(
                ["x"],
                rc=3,
                err="WARNING: A restricted method in java.lang.System has been called\nmystery\n",
            ),
        )
        assert d.category == category and not d.classified
        assert d.evidence == "mystery"  # JVM noise is never used as evidence


# ---------------------------------------------------------------------------
# BuildService pipeline (fake tools)
# ---------------------------------------------------------------------------


def _all_text_under(root: Path) -> str:
    return "".join(
        p.read_text(errors="replace")
        for p in root.rglob("*")
        if p.is_file() and p.suffix in (".log", ".json")
    )


class TestBuildService:
    def test_success_pipeline(
        self, service: BuildService, input_apk: Path, tmp_path: Path, runner: FakeToolRunner
    ) -> None:
        before = _sha(input_apk)
        out = tmp_path / "out" / "rebuilt.apk"
        res = service.build_pipeline(input_apk, BuildOptions(output_apk=out))
        assert res.success, res.to_dict()
        assert [s.stage for s in res.stages] == list(BuildStage)
        assert all(s.status == StageStatus.PASS for s in res.stages)
        assert res.failure_category == BuildFailureCategory.SUCCESS
        assert res.output_apk == out.resolve() and out.is_file()
        assert res.input_sha256 == before and res.input_unchanged and _sha(input_apk) == before
        v = res.verification
        assert (
            v
            and v.valid
            and v.zipalign_verified
            and v.signature_verified
            and v.expected_signer_matched
        )
        assert (
            res.certificate
            and res.certificate.sha256_digest == FAKE_CERT_SHA256
            and res.certificate.signer_count == 1
        )
        assert any("not covered by the v1 signature" in w for w in res.warnings)
        # tools only ever saw the private copy, never the original path
        assert all(str(input_apk) not in " ".join(argv) for argv, _ in runner.calls)

    def test_logs_and_metadata(self, service: BuildService, input_apk: Path) -> None:
        res = service.build_pipeline(input_apk, BuildOptions(keep_workspace_on_success=True))
        assert res.workspace and res.log_file
        master = res.log_file.read_text()
        done = {BuildStage.PREPARE: "workspace ready", BuildStage.VERIFY: "passed"}
        for stage in BuildStage:
            assert f"[{stage.upper()}] starting" in master, stage
            assert f"[{stage.upper()}] {done.get(stage, 'completed')} (" in master, stage
        for s in res.stages:
            assert s.log_file and s.log_file.is_file(), s.stage
            assert s.log_file != res.log_file
        stored = json.loads((res.workspace / "metadata" / "result.json").read_text())
        assert stored["success"] and stored["build_id"] == res.build_id
        assert "EXIT CODE" in (res.workspace / "logs" / "stage-decode.log").read_text()

    def test_password_never_leaks(
        self, service: BuildService, input_apk: Path, runner: FakeToolRunner
    ) -> None:
        res = service.build_pipeline(input_apk, BuildOptions(keep_workspace_on_success=True))
        assert res.success and res.workspace
        assert PASSWORD not in _all_text_under(res.workspace)
        assert PASSWORD not in json.dumps(res.to_dict())
        assert all(PASSWORD not in " ".join(argv) for argv, _ in runner.calls)
        sign_argv = next(a for a, _ in runner.calls if a[1:2] == ["sign"])
        assert f"env:{SECRET_ENV_VAR}" in sign_argv

    def test_build_failure_skips_later_stages_and_keeps_workspace(
        self, service: BuildService, runner: FakeToolRunner, input_apk: Path
    ) -> None:
        runner.overrides["apktool:b"] = lambda a, e: _cr(
            a,
            rc=1,
            out="W: res/color/x.xml:3: error: attribute state_dragged (aka org.schabi.newpipe:state_dragged) not found.\n",  # noqa: E501 - verbatim tool output
        )
        res = service.build_pipeline(input_apk)
        assert not res.success and res.output_apk is None
        assert res.failure_stage == BuildStage.BUILD
        assert res.failure_category == BuildFailureCategory.RESOURCE_FAILURE
        assert res.failure_evidence and "state_dragged" in res.failure_evidence
        statuses = {s.stage: s.status for s in res.stages}
        assert statuses[BuildStage.DECODE] == StageStatus.PASS
        assert [statuses[s] for s in (BuildStage.ALIGN, BuildStage.SIGN, BuildStage.VERIFY)] == [
            StageStatus.SKIPPED
        ] * 3
        assert res.workspace and (res.workspace / "decoded" / "apktool.yml").exists()
        assert "state_dragged" in (res.workspace / "logs" / "stage-build.log").read_text()
        assert res.input_unchanged

    def test_zipalign_check_failure_with_exit_zero(
        self, service: BuildService, runner: FakeToolRunner, input_apk: Path
    ) -> None:
        runner.overrides["zipalign:check"] = lambda a, e: _cr(
            a, out="Verifying alignment...\nVerification FAILED\n"
        )
        res = service.build_pipeline(input_apk)
        assert res.failure_stage == BuildStage.ALIGN
        assert res.failure_category == BuildFailureCategory.ALIGNMENT_FAILURE

    def test_signing_failure(
        self, service: BuildService, runner: FakeToolRunner, input_apk: Path
    ) -> None:
        runner.overrides["apksigner:sign"] = lambda a, e: _cr(
            a, rc=1, err="Failed to load signer: wrong password"
        )
        res = service.build_pipeline(input_apk)
        assert (
            res.failure_stage == BuildStage.SIGN
            and res.failure_category == BuildFailureCategory.SIGNING_FAILURE
        )

    def test_unexpected_signer_fails_verification(
        self, service: BuildService, runner: FakeToolRunner, input_apk: Path
    ) -> None:
        runner.verify_digest = "00" * 32
        res = service.build_pipeline(input_apk)
        assert not res.success
        assert res.failure_stage == BuildStage.VERIFY
        assert res.failure_category == BuildFailureCategory.VERIFICATION_FAILURE
        assert (
            res.verification
            and res.verification.signature_verified
            and not res.verification.expected_signer_matched
        )
        assert "Signer mismatch" in res.failure_cause

    def test_apksigner_exit_zero_without_verifies_fails(
        self, service: BuildService, runner: FakeToolRunner, input_apk: Path
    ) -> None:
        runner.overrides["apksigner:verify"] = lambda a, e: _cr(
            a, out="DOES NOT VERIFY\nERROR: JAR signer CERT.RSA\n"
        )
        res = service.build_pipeline(input_apk)
        assert res.failure_category == BuildFailureCategory.VERIFICATION_FAILURE

    def test_decode_timeout(
        self, service: BuildService, runner: FakeToolRunner, input_apk: Path
    ) -> None:
        runner.overrides["apktool:d"] = lambda a, e: _cr(
            a, rc=TIMEOUT_RETURNCODE, out="I: Decoding...", timed_out=True
        )
        res = service.build_pipeline(input_apk)
        assert (
            res.failure_stage == BuildStage.DECODE
            and res.failure_category == BuildFailureCategory.TIMEOUT
        )

    def test_refuses_to_overwrite_input(
        self, service: BuildService, input_apk: Path, runner: FakeToolRunner
    ) -> None:
        before = _sha(input_apk)
        res = service.build_pipeline(
            input_apk, BuildOptions(output_apk=input_apk, overwrite_output=True)
        )
        assert res.failure_stage == BuildStage.PREPARE
        assert res.failure_category == BuildFailureCategory.CONFIGURATION_FAILURE
        assert _sha(input_apk) == before and not runner.calls

    def test_refuses_existing_output_without_overwrite(
        self, service: BuildService, input_apk: Path, tmp_path: Path
    ) -> None:
        out = tmp_path / "exists.apk"
        out.write_bytes(b"keep me")
        res = service.build_pipeline(input_apk, BuildOptions(output_apk=out))
        assert (
            res.failure_category == BuildFailureCategory.CONFIGURATION_FAILURE
            and out.read_bytes() == b"keep me"
        )
        assert service.build_pipeline(
            input_apk, BuildOptions(output_apk=out, overwrite_output=True)
        ).success

    @pytest.mark.parametrize("kind", ["missing", "not-zip"])
    def test_invalid_input(self, service: BuildService, tmp_path: Path, kind: str) -> None:
        p = tmp_path / "bad.apk"
        if kind == "not-zip":
            p.write_text("not an apk")
        res = service.build_pipeline(p)
        assert (
            res.failure_stage == BuildStage.PREPARE
            and res.failure_category == BuildFailureCategory.INPUT_FAILURE
        )
        assert res.workspace is None

    def test_invalid_toolchain(
        self, signing: SigningConfig, input_apk: Path, tmp_path: Path
    ) -> None:
        cfg = ToolchainConfig()
        svc = BuildService(cfg, signing, runner=FakeToolRunner(cfg), work_dir=tmp_path / "w")  # type: ignore[arg-type]
        res = svc.build_pipeline(input_apk)
        assert res.failure_category == BuildFailureCategory.TOOL_UNAVAILABLE and res.errors
        assert not (tmp_path / "w").exists()

    def test_invalid_signing(
        self, toolchain: ToolchainConfig, runner: FakeToolRunner, input_apk: Path, tmp_path: Path
    ) -> None:
        bad = SigningConfig(tmp_path / "missing.p12", "a", password_env="NOPE")
        svc = BuildService(toolchain, bad, runner=runner, work_dir=tmp_path / "w")  # type: ignore[arg-type]
        res = svc.build_pipeline(input_apk)
        assert res.failure_category == BuildFailureCategory.CONFIGURATION_FAILURE

    def test_framework_install_failure(
        self, service: BuildService, runner: FakeToolRunner, input_apk: Path
    ) -> None:
        runner.overrides["apktool:if"] = lambda a, e: _cr(
            a, rc=1, err="Could not install framework"
        )
        res = service.build_pipeline(input_apk)
        assert res.failure_stage == BuildStage.PREPARE
        assert res.failure_category == BuildFailureCategory.FRAMEWORK_FAILURE
        assert res.workspace is not None

    def test_empty_password_file_is_configuration_failure(
        self, service: BuildService, signing: SigningConfig, input_apk: Path
    ) -> None:
        assert signing.password_file is not None
        signing.password_file.write_text("")
        res = service.build_pipeline(input_apk)
        assert res.failure_stage == BuildStage.PREPARE
        assert res.failure_category == BuildFailureCategory.CONFIGURATION_FAILURE

    def test_internal_stage_error_is_reported_not_raised(
        self, service: BuildService, runner: FakeToolRunner, input_apk: Path
    ) -> None:
        def boom(a: list[str], e: dict[str, str]) -> CommandResult:
            raise OSError("disk full")

        runner.overrides["zipalign:align"] = boom
        res = service.build_pipeline(input_apk)
        assert not res.success and res.failure_stage == BuildStage.ALIGN
        assert res.failure_category == BuildFailureCategory.UNEXPECTED_FAILURE
        assert "OSError: disk full" in res.failure_cause  # original error preserved
        assert "Traceback" in (res.workspace / "logs" / "stage-align.log").read_text()  # type: ignore[operator]
        assert res.workspace and (res.workspace / "metadata" / "result.json").is_file()

    def test_unwritable_framework_dir_is_framework_failure(
        self, service: BuildService, toolchain: ToolchainConfig, input_apk: Path, tmp_path: Path
    ) -> None:
        blocker = tmp_path / "blocker"
        blocker.write_text("a file, not a directory")
        toolchain.framework_dir = blocker / "fw"
        res = service.build_pipeline(input_apk)
        assert res.failure_stage == BuildStage.PREPARE
        assert res.failure_category == BuildFailureCategory.FRAMEWORK_FAILURE
        assert res.workspace and (res.workspace / "metadata" / "result.json").is_file()

    def test_concurrent_builds_are_isolated(self, service: BuildService, input_apk: Path) -> None:
        results = []
        threads = [
            threading.Thread(
                target=lambda: results.append(
                    service.build_pipeline(input_apk, BuildOptions(keep_workspace_on_success=True))
                )
            )
            for _ in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(results) == 4 and all(r.success for r in results)
        assert len({r.workspace for r in results}) == 4


# ---------------------------------------------------------------------------
# Phase C.3: individually callable stages, failure categories, path safety
# ---------------------------------------------------------------------------


def _actions(runner: FakeToolRunner) -> list[str]:
    return [runner._action(argv) for argv, _ in runner.calls]


@pytest.fixture()
def ws(service: BuildService) -> BuildWorkspace:
    workspace, sr = service.prepare_workspace()
    assert workspace is not None and sr.passed, sr.to_dict()
    return workspace


@pytest.fixture()
def decoded(service: BuildService, ws: BuildWorkspace, input_apk: Path) -> Path:
    sr = service.decode(input_apk, ws)
    assert sr.passed, sr.to_dict()
    return ws.decoded_dir


def _unaligned(tmp_path: Path) -> Path:
    apk = tmp_path / "stage-in" / "unaligned.apk"
    apk.parent.mkdir(exist_ok=True)
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("AndroidManifest.xml", b"\x03\x00manifest")
    return apk


class TestWorkspaceSafety:
    @pytest.mark.parametrize("bad", ["../escape", "a/b", "/abs", "..", ".hidden", "x" * 200, ""])
    def test_rejects_unsafe_build_ids(self, tmp_path: Path, bad: str) -> None:
        base = tmp_path / "base"
        if bad == "":
            # empty means "generate one"; must still produce a safe id
            assert BuildWorkspace.create(base, bad).root.parent == base.resolve()
            return
        with pytest.raises(WorkspaceError):
            BuildWorkspace.create(base, bad)
        assert not (tmp_path / "escape").exists() and not Path("/abs").exists()

    def test_problems_and_reimport(self, tmp_path: Path, input_apk: Path) -> None:
        w = BuildWorkspace.create(tmp_path)
        assert w.problems() == []
        w.import_input(input_apk)
        w.import_input(input_apk)  # read-only copy from a previous attempt is replaced
        shutil.rmtree(w.aligned_dir)
        assert any("aligned" in p for p in w.problems())


class TestToolAvailability:
    def test_unavailable_lists_missing_tools(self, toolchain: ToolchainConfig) -> None:
        assert toolchain.unavailable("java", "apktool", "zipalign", "apksigner", "keytool") == []
        toolchain.zipalign = None
        toolchain.apksigner = toolchain.apksigner.parent / "nope"  # type: ignore[union-attr]
        assert toolchain.unavailable("zipalign", "apksigner") == ["zipalign", "apksigner"]

    def test_java_not_required_for_executable_apktool(self, toolchain: ToolchainConfig) -> None:
        toolchain.java = None
        assert toolchain.unavailable("java", "apktool") == ["java"]
        toolchain.apktool = toolchain.keytool  # any existing non-jar executable
        assert toolchain.unavailable("java", "apktool") == []

    def test_broken_plus_missing_is_toolchain_failure(self, toolchain: ToolchainConfig) -> None:
        toolchain.zipalign = None
        fake = FakeToolRunner(toolchain)
        fake.overrides["apksigner:--version"] = lambda a, e: _cr(a, rc=1, err="boom")
        res = validate_toolchain(toolchain, runner=fake)  # type: ignore[arg-type]
        assert not res.unavailable_only
        assert res.failure_category == BuildFailureCategory.TOOLCHAIN_FAILURE


class TestPrepareWorkspace:
    def test_creates_unique_layout(self, service: BuildService, tmp_path: Path) -> None:
        a, sra = service.prepare_workspace()
        b, _ = service.prepare_workspace()
        assert a and b and a.root != b.root and sra.output_path == a.root
        assert a.root.parent == (tmp_path / "work").resolve()
        assert sra.events[0] == "[PREPARE] starting" and "workspace created" in sra.events[1]
        assert sra.log_file and sra.log_file.is_file()

    def test_unusable_base_is_workspace_failure(
        self, service: BuildService, tmp_path: Path
    ) -> None:
        blocker = tmp_path / "file"
        blocker.write_text("not a dir")
        w, sr = service.prepare_workspace(work_dir=blocker / "sub")
        assert w is None and sr.failure_category == BuildFailureCategory.WORKSPACE_FAILURE
        w, sr = service.prepare_workspace(build_id="../../etc")
        assert w is None and sr.failure_category == BuildFailureCategory.WORKSPACE_FAILURE


class TestDecodeStage:
    def test_success(
        self, service: BuildService, ws: BuildWorkspace, input_apk: Path, runner: FakeToolRunner
    ) -> None:
        before = _sha(input_apk)
        sr = service.decode(input_apk, ws)
        assert sr.passed and sr.output_path == ws.decoded_dir
        assert (ws.decoded_dir / "apktool.yml").is_file()
        assert ws.input_apk and _sha(ws.input_apk) == before == _sha(input_apk)
        argv = next(a for a, _ in runner.calls if "d" in a and "-o" in a)
        assert str(input_apk) not in argv and str(ws.input_apk) in argv
        assert sr.events[0] == "[DECODE] starting" and sr.events[-1].startswith(
            "[DECODE] completed"
        )
        assert "EXIT CODE: 0" in sr.log_file.read_text()  # type: ignore[union-attr]

    @pytest.mark.parametrize("kind", ["missing", "not-zip", "directory"])
    def test_input_failure(
        self, service: BuildService, ws: BuildWorkspace, tmp_path: Path, kind: str,
        runner: FakeToolRunner,
    ) -> None:  # fmt: skip
        p = tmp_path / "bad.apk"
        if kind == "not-zip":
            p.write_text("nope")
        elif kind == "directory":
            p.mkdir()
        n = len(runner.calls)
        sr = service.decode(p, ws)
        assert sr.failure_category == BuildFailureCategory.INPUT_FAILURE
        assert len(runner.calls) == n and not ws.decoded_dir.exists()

    def test_tool_unavailable(
        self, service: BuildService, ws: BuildWorkspace, input_apk: Path, runner: FakeToolRunner
    ) -> None:
        service.toolchain.apktool = None
        sr = service.decode(input_apk, ws)
        assert sr.failure_category == BuildFailureCategory.TOOL_UNAVAILABLE
        assert "apktool" in sr.failure_cause and not runner.calls

    def test_decode_failure_records_command(
        self, service: BuildService, ws: BuildWorkspace, input_apk: Path, runner: FakeToolRunner
    ) -> None:
        runner.overrides["apktool:d"] = lambda a, e: _cr(a, rc=1, err="brut.common.Weird: boom")
        sr = service.decode(input_apk, ws)
        assert sr.failure_category == BuildFailureCategory.DECODE_FAILURE
        assert sr.exit_code == 1 and "boom" in sr.stderr and sr.evidence
        assert sr.failed_command and sr.failed_command[-1] == str(ws.input_apk)

    def test_exit_zero_without_output_is_output_missing(
        self, service: BuildService, ws: BuildWorkspace, input_apk: Path, runner: FakeToolRunner
    ) -> None:
        runner.overrides["apktool:d"] = lambda a, e: _cr(a, out="I: Using Apktool 3.0.3\n")
        sr = service.decode(input_apk, ws)
        assert not sr.passed and sr.failure_category == BuildFailureCategory.OUTPUT_MISSING

    def test_stale_decoded_output_is_refused(
        self, service: BuildService, ws: BuildWorkspace, input_apk: Path
    ) -> None:
        assert service.decode(input_apk, ws).passed
        sr = service.decode(input_apk, ws)
        assert sr.failure_category == BuildFailureCategory.WORKSPACE_FAILURE

    def test_symlink_in_decoded_tree_is_rejected(
        self, service: BuildService, ws: BuildWorkspace, input_apk: Path, runner: FakeToolRunner
    ) -> None:
        def decode_with_link(a: list[str], e: dict[str, str]) -> CommandResult:
            out = Path(_arg_after(a, "-o"))
            out.mkdir(parents=True)
            (out / "AndroidManifest.xml").write_text("<manifest/>")
            (out / "apktool.yml").write_text("version: 3.0.3\n")
            (out / "evil").symlink_to("/etc")
            return _cr(a)

        runner.overrides["apktool:d"] = decode_with_link
        sr = service.decode(input_apk, ws)
        assert sr.failure_category == BuildFailureCategory.DECODE_FAILURE
        assert "symlink" in sr.failure_cause


class TestBuildStage:
    def test_success(self, service: BuildService, decoded: Path, tmp_path: Path) -> None:
        out = tmp_path / "o" / "unaligned.apk"
        sr = service.build(decoded, out)
        assert sr.passed and sr.output_path == out and zipfile.is_zipfile(out)
        assert any("unsigned" in n for n in sr.notes)

    def test_not_a_project(self, service: BuildService, tmp_path: Path) -> None:
        (tmp_path / "empty").mkdir()
        sr = service.build(tmp_path / "empty", tmp_path / "o.apk")
        assert sr.failure_category == BuildFailureCategory.INPUT_FAILURE

    def test_exit_zero_without_apk_is_output_missing(
        self, service: BuildService, decoded: Path, tmp_path: Path, runner: FakeToolRunner
    ) -> None:
        runner.overrides["apktool:b"] = lambda a, e: _cr(a, out="I: Building apk file...\n")
        sr = service.build(decoded, tmp_path / "o.apk")
        assert not sr.passed and sr.failure_category == BuildFailureCategory.OUTPUT_MISSING
        assert sr.exit_code == 0 and sr.failed_command

    def test_non_zip_output_is_build_failure(
        self, service: BuildService, decoded: Path, tmp_path: Path, runner: FakeToolRunner
    ) -> None:
        def junk(a: list[str], e: dict[str, str]) -> CommandResult:
            Path(_arg_after(a, "-o")).write_text("not a zip")
            return _cr(a)

        runner.overrides["apktool:b"] = junk
        sr = service.build(decoded, tmp_path / "o.apk")
        assert sr.failure_category == BuildFailureCategory.BUILD_FAILURE

    def test_existing_output_is_never_silently_replaced(
        self, service: BuildService, decoded: Path, tmp_path: Path, runner: FakeToolRunner
    ) -> None:
        out = tmp_path / "o.apk"
        out.write_bytes(b"stale")
        sr = service.build(decoded, out)
        assert sr.failure_category == BuildFailureCategory.CONFIGURATION_FAILURE
        assert out.read_bytes() == b"stale"
        # With overwrite the stale file is removed first, so it can never pass as new output.
        runner.overrides["apktool:b"] = lambda a, e: _cr(a)
        sr = service.build(decoded, out, overwrite=True)
        assert sr.failure_category == BuildFailureCategory.OUTPUT_MISSING and not out.exists()

    def test_output_inside_project_refused(self, service: BuildService, decoded: Path) -> None:
        sr = service.build(decoded, decoded / "dist" / "x.apk")
        assert sr.failure_category == BuildFailureCategory.CONFIGURATION_FAILURE


class TestAlignStage:
    def test_success(self, service: BuildService, tmp_path: Path) -> None:
        src = _unaligned(tmp_path)
        before = _sha(src)
        sr = service.align(src, tmp_path / "aligned.apk")
        assert sr.passed and (tmp_path / "aligned.apk").is_file() and _sha(src) == before
        assert len(sr.commands) == 2 and "-c" in sr.commands[1]  # explicit alignment check

    def test_refuses_to_overwrite_input(
        self, service: BuildService, tmp_path: Path, runner: FakeToolRunner
    ) -> None:
        src = _unaligned(tmp_path)
        before = _sha(src)
        sr = service.align(src, src, overwrite=True)
        assert sr.failure_category == BuildFailureCategory.CONFIGURATION_FAILURE
        assert _sha(src) == before and not runner.calls

    def test_empty_output_is_output_missing(
        self, service: BuildService, tmp_path: Path, runner: FakeToolRunner
    ) -> None:
        def empty(a: list[str], e: dict[str, str]) -> CommandResult:
            Path(a[-1]).write_bytes(b"")
            return _cr(a)

        runner.overrides["zipalign:align"] = empty
        sr = service.align(_unaligned(tmp_path), tmp_path / "a.apk")
        assert sr.failure_category == BuildFailureCategory.OUTPUT_MISSING

    def test_tool_unavailable(self, service: BuildService, tmp_path: Path) -> None:
        service.toolchain.zipalign = tmp_path / "gone"
        sr = service.align(_unaligned(tmp_path), tmp_path / "a.apk")
        assert sr.failure_category == BuildFailureCategory.TOOL_UNAVAILABLE


class TestSignStage:
    def test_development_signing(
        self, service: BuildService, tmp_path: Path, runner: FakeToolRunner
    ) -> None:
        sr = service.sign(_unaligned(tmp_path), tmp_path / "s.apk")
        assert sr.passed and sr.certificate_sha256 == FAKE_CERT_SHA256
        assert any("Signing mode: development" in n for n in sr.notes)
        blob = json.dumps(sr.to_dict()) + sr.log_file.read_text() if sr.log_file else ""
        assert PASSWORD not in json.dumps(sr.to_dict()) and PASSWORD not in blob
        assert all(PASSWORD not in " ".join(a) for a, _ in runner.calls)

    def test_user_provided_signing_override(
        self, service: BuildService, signing: SigningConfig, tmp_path: Path
    ) -> None:
        user = SigningConfig(
            keystore=signing.keystore, alias="release", password_file=signing.password_file
        )
        sr = service.sign(_unaligned(tmp_path), tmp_path / "s.apk", user)
        assert sr.passed and any("Signing mode: user_provided" in n for n in sr.notes)
        assert "--ks-key-alias" in sr.commands[-1] and "release" in sr.commands[-1]

    def test_no_signing_config_stays_unsigned(
        self, toolchain: ToolchainConfig, runner: FakeToolRunner, tmp_path: Path
    ) -> None:
        svc = BuildService(toolchain, runner=runner, work_dir=tmp_path / "w")  # type: ignore[arg-type]
        out = tmp_path / "s.apk"
        sr = svc.sign(_unaligned(tmp_path), out)
        assert sr.failure_category == BuildFailureCategory.CONFIGURATION_FAILURE
        assert "unsigned" in sr.failure_cause and not out.exists() and not runner.calls

    def test_exit_zero_without_output_is_output_missing(
        self, service: BuildService, tmp_path: Path, runner: FakeToolRunner
    ) -> None:
        runner.overrides["apksigner:sign"] = lambda a, e: _cr(a)
        sr = service.sign(_unaligned(tmp_path), tmp_path / "s.apk")
        assert sr.failure_category == BuildFailureCategory.OUTPUT_MISSING
        assert sr.certificate_sha256 is None


class TestVerifyStage:
    def test_standalone_without_expected_signer(
        self, service: BuildService, tmp_path: Path
    ) -> None:
        sr = service.verify(_unaligned(tmp_path))
        v = sr.verification
        assert sr.passed and v and v.valid and v.expected_signer_matched is None
        assert v.certificate and v.certificate.sha256_digest == FAKE_CERT_SHA256
        assert "Verifies" in v.apksigner_output and v.apksigner_warnings
        assert sr.events[-1].startswith("[VERIFY] passed")

    def test_expected_signer_enforced(self, service: BuildService, tmp_path: Path) -> None:
        sr = service.verify(_unaligned(tmp_path), expected_certificate_sha256="ab" * 32)
        assert sr.failure_category == BuildFailureCategory.VERIFICATION_FAILURE
        assert sr.verification and sr.verification.expected_signer_matched is False

    def test_invalid_signature(
        self, service: BuildService, tmp_path: Path, runner: FakeToolRunner
    ) -> None:
        runner.overrides["apksigner:verify"] = lambda a, e: _cr(
            a, rc=1, out="DOES NOT VERIFY\nERROR: Missing META-INF/MANIFEST.MF\n"
        )
        sr = service.verify(_unaligned(tmp_path))
        v = sr.verification
        assert sr.failure_category == BuildFailureCategory.VERIFICATION_FAILURE
        assert v and not v.valid and not v.signature_verified and v.errors
        assert "DOES NOT VERIFY" in v.apksigner_output
        assert sr.failed_command and sr.failed_command[1] == "verify"

    def test_missing_apk_is_input_failure(self, service: BuildService, tmp_path: Path) -> None:
        sr = service.verify(tmp_path / "nope.apk")
        assert sr.failure_category == BuildFailureCategory.INPUT_FAILURE
        assert sr.verification is None  # nothing was verified, nothing is claimed


class TestUnexpectedErrors:
    def test_stage_method_never_raises(
        self, service: BuildService, decoded: Path, tmp_path: Path, runner: FakeToolRunner
    ) -> None:
        def boom(a: list[str], e: dict[str, str]) -> CommandResult:
            raise RuntimeError("kaboom")

        runner.overrides["apktool:b"] = boom
        sr = service.build(decoded, tmp_path / "o.apk")
        assert sr.failure_category == BuildFailureCategory.UNEXPECTED_FAILURE
        assert "RuntimeError: kaboom" in sr.failure_cause and not sr.classified

    def test_keyboard_interrupt_propagates(
        self, service: BuildService, tmp_path: Path, runner: FakeToolRunner
    ) -> None:
        def stop(a: list[str], e: dict[str, str]) -> CommandResult:
            raise KeyboardInterrupt

        runner.overrides["zipalign:align"] = stop
        with pytest.raises(KeyboardInterrupt):
            service.align(_unaligned(tmp_path), tmp_path / "a.apk")


class TestPipelineC3:
    def test_structured_logs_and_signing_mode(self, service: BuildService, input_apk: Path) -> None:
        res = service.build_pipeline(input_apk)
        assert res.success and res.signing_mode == "development"
        starts = [ln.split("]")[0] + "]" for ln in res.logs if ln.endswith("] starting")]
        assert starts == [f"[{s.upper()}]" for s in BuildStage]
        assert any(ln.startswith("[VERIFY] passed") for ln in res.logs)
        assert res.logs[-1].startswith("SUCCESS")
        d = json.loads(json.dumps(res.to_dict()))  # fully JSON-serializable
        assert d["signing_mode"] == "development" and d["failure_command"] is None
        assert d["stages"][-1]["verification"]["valid"] is True

    def test_user_provided_mode(
        self, toolchain: ToolchainConfig, signing: SigningConfig, runner: FakeToolRunner,
        input_apk: Path, tmp_path: Path,
    ) -> None:  # fmt: skip
        user = SigningConfig(signing.keystore, "rel", password_file=signing.password_file)
        svc = BuildService(toolchain, user, runner=runner, work_dir=tmp_path / "w")  # type: ignore[arg-type]
        assert svc.build_pipeline(input_apk).signing_mode == "user_provided"

    def test_stops_after_decode_failure(
        self, service: BuildService, runner: FakeToolRunner, input_apk: Path
    ) -> None:
        runner.overrides["apktool:d"] = lambda a, e: _cr(a, rc=1, err="decode exploded")
        res = service.build_pipeline(input_apk)
        assert not res.success and res.failure_stage == BuildStage.DECODE
        assert res.failure_category == BuildFailureCategory.DECODE_FAILURE
        assert res.signing_mode == "unsigned" and res.output_apk is None
        assert res.failure_command and "d" in res.failure_command
        acts = _actions(runner)
        assert "apktool:b" not in acts and "zipalign:align" not in acts
        assert "apksigner:sign" not in acts and "apksigner:verify" not in acts
        assert [s.status for s in res.stages[2:]] == [StageStatus.SKIPPED] * 4

    def test_build_output_missing_stops_pipeline(
        self, service: BuildService, runner: FakeToolRunner, input_apk: Path
    ) -> None:
        runner.overrides["apktool:b"] = lambda a, e: _cr(a)
        res = service.build_pipeline(input_apk)
        assert res.failure_stage == BuildStage.BUILD
        assert res.failure_category == BuildFailureCategory.OUTPUT_MISSING
        assert "zipalign:align" not in _actions(runner)

    def test_verification_failure_means_no_success(
        self, service: BuildService, runner: FakeToolRunner, input_apk: Path, tmp_path: Path
    ) -> None:
        out = tmp_path / "out.apk"
        runner.overrides["apksigner:verify"] = lambda a, e: _cr(a, rc=1, out="DOES NOT VERIFY\n")
        res = service.build_pipeline(input_apk, BuildOptions(output_apk=out))
        assert not res.success and res.failure_stage == BuildStage.VERIFY
        assert res.output_apk is None and not out.exists()  # an unverified APK is never exported

    def test_prepare_failure_skips_every_stage(self, service: BuildService, tmp_path: Path) -> None:
        res = service.build_pipeline(tmp_path / "missing.apk")
        assert res.failure_stage == BuildStage.PREPARE
        assert [s.status for s in res.stages] == [StageStatus.FAIL] + [StageStatus.SKIPPED] * 5
        assert res.logs and res.logs[-1].startswith("[PREPARE] FAILED INPUT_FAILURE")

    def test_pipeline_requires_signing(
        self, toolchain: ToolchainConfig, runner: FakeToolRunner, input_apk: Path, tmp_path: Path
    ) -> None:
        svc = BuildService(toolchain, runner=runner, work_dir=tmp_path / "w")  # type: ignore[arg-type]
        res = svc.build_pipeline(input_apk)
        assert res.failure_category == BuildFailureCategory.CONFIGURATION_FAILURE
        assert not (tmp_path / "w").exists()

    def test_composes_public_stage_methods(
        self, service: BuildService, input_apk: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        called: list[str] = []
        for name in ("decode", "build", "align", "sign", "verify"):
            orig = getattr(service, name)

            def spy(*a: object, _o: Callable[..., object] = orig, _n: str = name, **k: object):  # type: ignore[no-untyped-def]
                called.append(_n)
                return _o(*a, **k)

            monkeypatch.setattr(service, name, spy)
        assert service.build_pipeline(input_apk).success
        assert called == ["decode", "build", "align", "sign", "verify"]
