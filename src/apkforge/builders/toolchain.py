"""Toolchain configuration, discovery, validation and framework provisioning.

Configuration precedence (highest first):

1. explicit keyword arguments to :meth:`ToolchainConfig.discover`
2. ``APKFORGE_*`` environment variables
3. standard environment (``JAVA_HOME``, ``ANDROID_HOME``/``ANDROID_SDK_ROOT``)
4. the Android SDK layout (latest ``build-tools/*`` and ``platforms/*``);
   ``~/Android/Sdk`` (Android Studio's default) if no SDK variable is set
5. ``PATH``

No machine-specific path is hard-coded. The only repository-relative lookup is
``<checkout>/tools/apktool.jar``, used when running from a source checkout.

Apktool framework: Phase C.1b showed Apktool's bundled framework lacks API 35
attributes. BuildService therefore installs the configured platform
``android.jar`` into an APKForge-managed framework directory (not Apktool's
global one) and records a provenance marker, so every build provably uses the
framework of the configured platform.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from apkforge.builders.models import BuildFailureCategory
from apkforge.builders.runner import CommandResult, CommandRunner

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = [
    "MIN_APKTOOL_VERSION",
    "ToolDiagnostic",
    "ToolchainCheckResult",
    "ToolchainConfig",
    "default_data_dir",
    "ensure_framework",
    "framework_status",
    "validate_toolchain",
]

#: Minimum supported Apktool. 2.10.0 fails 2/9 corpus APKs (Phase C.1b).
MIN_APKTOOL_VERSION: tuple[int, int, int] = (3, 0, 3)
#: Lowest platform whose framework resolves the C.1b android:* attribute errors.
RECOMMENDED_MIN_PLATFORM_API = 35

FRAMEWORK_MARKER = "apkforge-framework.json"
FRAMEWORK_FILE = "1.apk"

_PROJECT_TOOLS_DIR = Path(__file__).resolve().parents[3] / "tools"


def default_data_dir(environ: Mapping[str, str] | None = None) -> Path:
    """APKForge per-user data directory (``$XDG_DATA_HOME/apkforge``)."""
    env = os.environ if environ is None else environ
    base = env.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "apkforge"


def _version_key(name: str) -> list[int]:
    return [
        int(p) if p.isdigit() else -1 for p in re.split(r"[.\-]", name.removeprefix("android-"))
    ]


def _parse_version(text: str) -> tuple[int, ...] | None:
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text)
    return tuple(int(g) for g in m.groups()) if m else None


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class ToolchainConfig:
    """Paths to every external tool BuildService uses."""

    java: Path | None = None
    keytool: Path | None = None
    apktool: Path | None = None  # a .jar (run with ``java -jar``) or an executable
    zipalign: Path | None = None
    apksigner: Path | None = None
    android_sdk: Path | None = None
    android_platform: Path | None = None  # platforms/android-NN/android.jar
    build_tools: Path | None = None  # build-tools/X.Y.Z
    framework_dir: Path | None = None  # APKForge-managed Apktool framework dir

    def apktool_command(self) -> list[str]:
        """Argv prefix that launches Apktool."""
        if self.apktool is None:
            return []
        if self.apktool.suffix == ".jar":
            return [str(self.java or "java"), "-jar", str(self.apktool)]
        return [str(self.apktool)]

    @property
    def platform_name(self) -> str | None:
        return self.android_platform.parent.name if self.android_platform else None

    @property
    def platform_api(self) -> int | None:
        name = self.platform_name or ""
        m = re.fullmatch(r"android-(\d+)", name)
        return int(m.group(1)) if m else None

    @property
    def build_tools_version(self) -> str | None:
        return self.build_tools.name if self.build_tools else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "java": str(self.java) if self.java else None,
            "keytool": str(self.keytool) if self.keytool else None,
            "apktool": str(self.apktool) if self.apktool else None,
            "zipalign": str(self.zipalign) if self.zipalign else None,
            "apksigner": str(self.apksigner) if self.apksigner else None,
            "android_sdk": str(self.android_sdk) if self.android_sdk else None,
            "android_platform": str(self.android_platform) if self.android_platform else None,
            "platform_name": self.platform_name,
            "build_tools": str(self.build_tools) if self.build_tools else None,
            "build_tools_version": self.build_tools_version,
            "framework_dir": str(self.framework_dir) if self.framework_dir else None,
        }

    @classmethod
    def discover(
        cls,
        *,
        java: Path | str | None = None,
        keytool: Path | str | None = None,
        apktool: Path | str | None = None,
        zipalign: Path | str | None = None,
        apksigner: Path | str | None = None,
        android_sdk: Path | str | None = None,
        android_platform: str | None = None,
        build_tools_version: str | None = None,
        framework_dir: Path | str | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> ToolchainConfig:
        """Resolve tool locations. Missing tools are left ``None`` for validation to report."""
        env = os.environ if environ is None else environ
        path_env = env.get("PATH")

        def _which(name: str) -> Path | None:
            w = shutil.which(name, path=path_env)
            return Path(w).resolve() if w else None

        def _pick(explicit: Path | str | None, env_key: str) -> Path | None:
            val = explicit or env.get(env_key)
            return Path(val).expanduser().resolve() if val else None

        cfg = cls()

        # Java / keytool
        cfg.java = _pick(java, "APKFORGE_JAVA")
        if cfg.java is None and env.get("JAVA_HOME"):
            cand = Path(env["JAVA_HOME"]) / "bin" / "java"
            cfg.java = cand.resolve() if cand.exists() else None
        cfg.java = cfg.java or _which("java")
        cfg.keytool = _pick(keytool, "APKFORGE_KEYTOOL")
        if cfg.keytool is None and cfg.java is not None and (cfg.java.parent / "keytool").exists():
            cfg.keytool = cfg.java.parent / "keytool"
        cfg.keytool = cfg.keytool or _which("keytool")

        # Android SDK
        sdk = (
            android_sdk
            or env.get("APKFORGE_ANDROID_SDK")
            or env.get("ANDROID_HOME")
            or env.get("ANDROID_SDK_ROOT")
        )
        if not sdk:
            sdk = (
                Path.home() / "Android" / "Sdk"
            )  # Android Studio's default install location on Linux
        if Path(sdk).expanduser().is_dir():
            cfg.android_sdk = Path(sdk).expanduser().resolve()

        if cfg.android_sdk:
            bt_root = cfg.android_sdk / "build-tools"
            want_bt = build_tools_version or env.get("APKFORGE_BUILD_TOOLS_VERSION")
            if want_bt:
                cfg.build_tools = bt_root / want_bt if (bt_root / want_bt).is_dir() else None
            elif bt_root.is_dir():
                versions = sorted(
                    (d for d in bt_root.iterdir() if d.is_dir()), key=lambda d: _version_key(d.name)
                )
                cfg.build_tools = versions[-1] if versions else None

            plat_root = cfg.android_sdk / "platforms"
            want_plat = android_platform or env.get("APKFORGE_ANDROID_PLATFORM")
            if want_plat:
                jar = plat_root / want_plat / "android.jar"
                cfg.android_platform = jar if jar.exists() else None
            elif plat_root.is_dir():
                jars = sorted(
                    (
                        d / "android.jar"
                        for d in plat_root.iterdir()
                        if (d / "android.jar").exists()
                    ),
                    key=lambda j: _version_key(j.parent.name),
                )
                cfg.android_platform = jars[-1] if jars else None

        # zipalign / apksigner: explicit > env > SDK build-tools > PATH
        cfg.zipalign = _pick(zipalign, "APKFORGE_ZIPALIGN")
        if cfg.zipalign is None and cfg.build_tools and (cfg.build_tools / "zipalign").exists():
            cfg.zipalign = cfg.build_tools / "zipalign"
        cfg.zipalign = cfg.zipalign or _which("zipalign")

        cfg.apksigner = _pick(apksigner, "APKFORGE_APKSIGNER")
        if cfg.apksigner is None and cfg.build_tools and (cfg.build_tools / "apksigner").exists():
            cfg.apksigner = cfg.build_tools / "apksigner"
        cfg.apksigner = cfg.apksigner or _which("apksigner")

        # Apktool: explicit > env > source-checkout tools/apktool.jar > PATH
        cfg.apktool = _pick(apktool, "APKFORGE_APKTOOL")
        if cfg.apktool is None and (_PROJECT_TOOLS_DIR / "apktool.jar").exists():
            cfg.apktool = (_PROJECT_TOOLS_DIR / "apktool.jar").resolve()
        cfg.apktool = cfg.apktool or _which("apktool")

        # Framework dir: explicit > env > <data dir>/apktool-framework/<platform>
        cfg.framework_dir = _pick(framework_dir, "APKFORGE_APKTOOL_FRAMEWORK_DIR")
        if cfg.framework_dir is None:
            cfg.framework_dir = (
                default_data_dir(env) / "apktool-framework" / (cfg.platform_name or "unknown")
            )

        return cfg


@dataclass
class ToolDiagnostic:
    """Diagnostic for one toolchain component."""

    name: str
    path: Path | None = None
    version: str | None = None
    status: str = "MISSING"  # FOUND | MISSING | BROKEN | UNSUPPORTED | INSTALLED | NOT_INSTALLED
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": str(self.path) if self.path else None,
            "version": self.version,
            "status": self.status,
            "notes": self.notes,
        }


@dataclass
class ToolchainCheckResult:
    """Result of :func:`validate_toolchain`."""

    valid: bool
    tools: dict[str, ToolDiagnostic] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    framework_only: bool = False  # all errors concern the Android platform/framework

    @property
    def failure_category(self) -> BuildFailureCategory:
        if self.valid:
            return BuildFailureCategory.SUCCESS
        return (
            BuildFailureCategory.FRAMEWORK_FAILURE
            if self.framework_only
            else BuildFailureCategory.TOOLCHAIN_FAILURE
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "tools": {k: v.to_dict() for k, v in self.tools.items()},
            "warnings": list(self.warnings),
            "errors": list(self.errors),
        }


def _check_exists(name: str, path: Path | None, hint: str) -> ToolDiagnostic:
    diag = ToolDiagnostic(name=name, path=path)
    if path is None or not path.exists():
        diag.notes = f"Not found. {hint}"
    else:
        diag.status = "FOUND"
    return diag


def validate_toolchain(
    config: ToolchainConfig, runner: CommandRunner | None = None
) -> ToolchainCheckResult:
    """Check every tool is present, runnable and of a supported version."""
    run = (runner or CommandRunner(default_timeout=60)).run
    tools: dict[str, ToolDiagnostic] = {}
    errors: list[str] = []
    framework_errors: list[str] = []
    warnings: list[str] = []

    def _fail(diag: ToolDiagnostic, msg: str, *, framework: bool = False) -> None:
        (framework_errors if framework else errors).append(f"{diag.name}: {msg}")

    # Java
    d = _check_exists("java", config.java, "Set APKFORGE_JAVA or JAVA_HOME, or put java on PATH.")
    if d.status == "FOUND":
        res = run([str(config.java), "-version"], timeout=30)
        text = res.stderr + "\n" + res.stdout
        m = re.search(r'version "([^"]+)"', text)
        if res.ok and m:
            d.version = m.group(1)
        else:
            d.status, d.notes = "BROKEN", f"`java -version` failed (exit {res.returncode})."
    if d.status != "FOUND":
        _fail(d, d.notes)
    tools["java"] = d

    # keytool (development key provisioning and expected-signer digest)
    d = _check_exists("keytool", config.keytool, "Set APKFORGE_KEYTOOL or use a full JDK.")
    if d.status != "FOUND":
        _fail(d, d.notes)
    tools["keytool"] = d

    # Apktool
    d = _check_exists("apktool", config.apktool, "Set APKFORGE_APKTOOL to an Apktool >= 3.0.3 jar.")
    if d.status == "FOUND":
        res = run([*config.apktool_command(), "--version"], timeout=60)
        ver = _parse_version(res.stdout + res.stderr)
        if not res.ok or ver is None:
            d.status, d.notes = (
                "BROKEN",
                f"`apktool --version` failed (exit {res.returncode}): {res.stderr.strip()[-200:]}",
            )
        else:
            d.version = ".".join(map(str, ver))
            if ver < MIN_APKTOOL_VERSION:
                d.status = "UNSUPPORTED"
                d.notes = (
                    f"Apktool {d.version} is below the supported minimum "
                    f"{'.'.join(map(str, MIN_APKTOOL_VERSION))}; Phase C.1b showed 2.10.0 fails "
                    "resource reconstruction for resource-shrunk APKs."
                )
    if d.status != "FOUND":
        _fail(d, d.notes)
    tools["apktool"] = d

    # Android SDK, build-tools
    d = _check_exists(
        "android_sdk", config.android_sdk, "Set APKFORGE_ANDROID_SDK or ANDROID_HOME."
    )
    if d.status != "FOUND":
        _fail(d, d.notes)
    tools["android_sdk"] = d

    d = _check_exists(
        "build_tools", config.build_tools, "Install Android SDK build-tools (35.0.0 validated)."
    )
    d.version = config.build_tools_version
    if d.status != "FOUND":
        _fail(d, d.notes)
    tools["build_tools"] = d

    # Platform android.jar (source of the Apktool framework)
    d = _check_exists(
        "android_platform",
        config.android_platform,
        "Install an Android SDK platform (android-35 validated).",
    )
    d.version = config.platform_name
    if d.status == "FOUND":
        api = config.platform_api
        if api is not None and api < RECOMMENDED_MIN_PLATFORM_API:
            warnings.append(
                f"android_platform: {config.platform_name} is older than "
                f"android-{RECOMMENDED_MIN_PLATFORM_API}; "
                "apps targeting newer APIs may fail with missing android:* attributes (Phase C.1b)."
            )
    else:
        _fail(d, d.notes, framework=True)
    tools["android_platform"] = d

    # Apktool framework (provisioned on demand by BuildService)
    tools["apktool_framework"] = framework_status(config)

    # zipalign
    d = _check_exists(
        "zipalign", config.zipalign, "Set APKFORGE_ZIPALIGN or install SDK build-tools."
    )
    if d.status == "FOUND":
        res = run([str(config.zipalign)], timeout=30)  # prints usage; exit code is non-zero
        if "Zip alignment utility" in res.stdout + res.stderr:
            d.version = config.build_tools_version
        else:
            d.status, d.notes = (
                "BROKEN",
                f"zipalign did not print its usage banner (exit {res.returncode}).",
            )
    if d.status != "FOUND":
        _fail(d, d.notes)
    tools["zipalign"] = d

    # apksigner
    d = _check_exists(
        "apksigner", config.apksigner, "Set APKFORGE_APKSIGNER or install SDK build-tools."
    )
    if d.status == "FOUND":
        res = run([str(config.apksigner), "--version"], timeout=60)
        signer_ver = res.stdout.strip().splitlines()[-1] if res.stdout.strip() else ""
        if res.ok and signer_ver:
            d.version = signer_ver
            d.notes = (
                f"build-tools {config.build_tools_version}" if config.build_tools_version else ""
            )
        else:
            d.status, d.notes = "BROKEN", f"`apksigner --version` failed (exit {res.returncode})."
    if d.status != "FOUND":
        _fail(d, d.notes)
    tools["apksigner"] = d

    all_errors = errors + framework_errors
    return ToolchainCheckResult(
        valid=not all_errors,
        tools=tools,
        warnings=warnings,
        errors=all_errors,
        framework_only=bool(framework_errors) and not errors,
    )


# ---------------------------------------------------------------------------
# Apktool framework provisioning
# ---------------------------------------------------------------------------


def _read_marker(framework_dir: Path) -> dict[str, Any] | None:
    try:
        data = json.loads((framework_dir / FRAMEWORK_MARKER).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def framework_status(config: ToolchainConfig) -> ToolDiagnostic:
    """Report whether the managed framework matches the configured platform."""
    d = ToolDiagnostic(
        name="apktool_framework", path=config.framework_dir, version=config.platform_name
    )
    if config.framework_dir is None or config.android_platform is None:
        d.status, d.notes = "NOT_INSTALLED", "No framework directory or platform configured."
        return d
    marker = _read_marker(config.framework_dir)
    if (
        marker
        and (config.framework_dir / FRAMEWORK_FILE).exists()
        and marker.get("source") == str(config.android_platform)
    ):
        d.status = "INSTALLED"
        sha = str(marker.get("source_sha256"))[:16]
        d.notes = f"Installed from {marker.get('source')} (sha256 {sha}…)."
    else:
        d.status = "NOT_INSTALLED"
        d.notes = f"Will be installed from {config.android_platform} on first build."
    return d


def ensure_framework(
    config: ToolchainConfig,
    runner: CommandRunner,
    *,
    log_path: Path | None = None,
) -> tuple[bool, CommandResult | None, str]:
    """Install ``android_platform`` as the Apktool framework if not already current.

    Installation happens in a temporary sibling directory and is moved into place
    atomically, so concurrent builds never observe a half-written framework.

    Returns ``(ok, command_result_or_None, message)``.
    """
    if (
        config.framework_dir is None
        or config.android_platform is None
        or not config.android_platform.exists()
    ):
        return (
            False,
            None,
            "Android platform android.jar is not configured; cannot provision Apktool framework.",
        )

    fw_dir = config.framework_dir
    source_sha = _sha256_file(config.android_platform)
    marker = _read_marker(fw_dir)
    if marker and marker.get("source_sha256") == source_sha and (fw_dir / FRAMEWORK_FILE).exists():
        return True, None, f"Apktool framework current ({config.platform_name}, {fw_dir})."

    fw_dir.parent.mkdir(parents=True, exist_ok=True)
    tmp_dir = Path(tempfile.mkdtemp(prefix=".fw-install-", dir=fw_dir.parent))
    try:
        res = runner.run(
            [*config.apktool_command(), "if", "-p", str(tmp_dir), str(config.android_platform)],
            log_path=log_path,
            timeout=300,
        )
        installed = tmp_dir / FRAMEWORK_FILE
        if not res.ok or not installed.exists():
            return (
                False,
                res,
                f"`apktool if` failed to install {config.android_platform} "
                f"(exit {res.returncode}).",
            )
        fw_dir.mkdir(parents=True, exist_ok=True)
        os.replace(installed, fw_dir / FRAMEWORK_FILE)
        new_marker = {
            "source": str(config.android_platform),
            "source_sha256": source_sha,
            "platform": config.platform_name,
            "apktool": str(config.apktool),
            "installed_at": datetime.datetime.now(datetime.UTC).isoformat(),
        }
        tmp_marker = tmp_dir / FRAMEWORK_MARKER
        tmp_marker.write_text(json.dumps(new_marker, indent=2), encoding="utf-8")
        os.replace(tmp_marker, fw_dir / FRAMEWORK_MARKER)
        return (
            True,
            res,
            f"Installed Apktool framework from {config.android_platform} into {fw_dir}.",
        )
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
