#!/usr/bin/env python3
"""APKForge Phase A — Corpus Validation Runner.

Exercises every APKForge analysis capability against each real APK in
tests/corpus/ and records PASS / PARTIAL / FAIL / NOT_APPLICABLE verdicts
with full diagnostic evidence.

Usage:
    python tests/corpus_runner.py

Output:
    tests/corpus_results.json   — Machine-readable results
    stdout                      — Human-readable summary
"""

from __future__ import annotations

import gc
import json
import sys
import time
import traceback
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path

# ---------------------------------------------------------------------------
# Ensure project is importable
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

CORPUS_DIR = PROJECT_ROOT / "tests" / "corpus"
RESULTS_FILE = PROJECT_ROOT / "tests" / "corpus_results.json"
LOCK_FILE = PROJECT_ROOT / "requirements" / "validation.lock"

# Disable noisy debug logs from androguard during batch runs
try:
    from loguru import logger
    logger.disable("androguard")
except Exception:
    pass



# ---------------------------------------------------------------------------
# Validation-environment identity
# ---------------------------------------------------------------------------


def _dist_version(name: str) -> str | None:
    from importlib import metadata

    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def environment_identity() -> dict:
    """Identify the Python validation environment that produced a corpus run.

    Recorded under ``meta.environment`` so a result can be matched to the
    locked environment (requirements/validation.lock) it was generated in.
    """
    import hashlib
    import platform

    env: dict = {
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "cryptography_version": _dist_version("cryptography"),
        "cryptography_bundled_openssl": None,
        "androguard_version": _dist_version("androguard"),
        "asn1crypto_version": _dist_version("asn1crypto"),
        "pydantic_version": _dist_version("pydantic"),
        "lock_file": str(LOCK_FILE.relative_to(PROJECT_ROOT)),
        "lock_sha256": None,
    }
    try:
        from cryptography.hazmat.backends.openssl.backend import backend

        env["cryptography_bundled_openssl"] = backend.openssl_version_text()
    except Exception as exc:  # recorded, never fatal to a corpus run
        env["cryptography_bundled_openssl"] = f"<unavailable: {exc}>"
    if LOCK_FILE.is_file():
        env["lock_sha256"] = hashlib.sha256(LOCK_FILE.read_bytes()).hexdigest()
    return env


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


class Verdict(StrEnum):
    PASS = "PASS"
    PARTIAL = "PARTIAL"
    FAIL = "FAIL"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass
class CapabilityResult:
    capability: str
    verdict: str = Verdict.FAIL
    duration_seconds: float = 0.0
    message: str = ""
    error: str = ""
    exception_type: str = ""
    traceback_snippet: str = ""
    data_summary: dict = field(default_factory=dict)
    likely_cause: str = ""
    blame: str = ""  # "apkforge" or "unsupported_structure" or ""


@dataclass
class APKResult:
    filename: str
    file_size_bytes: int = 0
    capabilities: list = field(default_factory=list)

    @property
    def pass_count(self) -> int:
        return sum(1 for c in self.capabilities if c["verdict"] == Verdict.PASS)

    @property
    def partial_count(self) -> int:
        return sum(1 for c in self.capabilities if c["verdict"] == Verdict.PARTIAL)

    @property
    def fail_count(self) -> int:
        return sum(1 for c in self.capabilities if c["verdict"] == Verdict.FAIL)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _timed(func):
    """Run func() returning (result, duration_seconds, exception_info)."""
    start = time.monotonic()
    exc_info = None
    result = None
    try:
        result = func()
    except Exception:
        exc_info = sys.exc_info()
    elapsed = time.monotonic() - start
    return result, elapsed, exc_info


def _exc_summary(exc_info) -> tuple[str, str, str]:
    """Return (exception_type, message, traceback_snippet) from exc_info."""
    if exc_info is None:
        return "", "", ""
    etype, evalue, etb = exc_info
    tb_lines = traceback.format_exception(etype, evalue, etb)
    # Keep last 15 lines of traceback for diagnostic value
    snippet = "".join(tb_lines[-15:])
    return etype.__name__, str(evalue), snippet


# ---------------------------------------------------------------------------
# Capability validators
# ---------------------------------------------------------------------------


def validate_intake(apk_path: Path) -> CapabilityResult:
    """Test 1: APK intake — format detection, hashing, metadata extraction."""
    from apkforge.intake import APKIntakeService
    from apkforge.core.models import AnalysisStatus

    cap = CapabilityResult(capability="intake")

    pkg, elapsed, exc = _timed(lambda: APKIntakeService().process(apk_path))
    cap.duration_seconds = elapsed

    if exc:
        etype, emsg, etb = _exc_summary(exc)
        cap.error = emsg
        cap.exception_type = etype
        cap.traceback_snippet = etb
        cap.likely_cause = "Exception during APK intake processing"
        cap.blame = "apkforge"
        return cap

    if pkg is None:
        cap.error = "APKIntakeService.process() returned None"
        cap.blame = "apkforge"
        return cap

    cap.data_summary = {
        "status": str(pkg.status),
        "package_type": str(pkg.package_type),
        "input_format": str(getattr(pkg, "input_format", "unknown")),
        "package_name": getattr(getattr(pkg, "identity", None), "package_name", None),
        "version_name": getattr(getattr(pkg, "identity", None), "version_name", None),
        "file_count": len(pkg.files) if pkg.files else 0,
        "dex_count": len(pkg.dex_files) if pkg.dex_files else 0,
        "certificate_count": len(pkg.certificates) if pkg.certificates else 0,
        "has_hashes": pkg.hashes is not None,
        "sha256": getattr(pkg.hashes, "sha256", None)[:16] + "..." if pkg.hashes and pkg.hashes.sha256 else None,
        "errors": pkg.errors[:3] if pkg.errors else [],
        "warnings": pkg.warnings[:3] if pkg.warnings else [],
    }

    if pkg.status == AnalysisStatus.FAILED:
        cap.verdict = Verdict.FAIL
        cap.error = f"Intake status FAILED: {pkg.errors}"
        cap.blame = "apkforge" if not pkg.errors else "unknown"
    elif pkg.status == AnalysisStatus.PARTIAL:
        cap.verdict = Verdict.PARTIAL
        cap.message = f"Intake partial: {pkg.warnings}"
    elif (pkg.identity and pkg.identity.package_name and
          pkg.hashes and pkg.files and len(pkg.files) > 0):
        cap.verdict = Verdict.PASS
        cap.message = (
            f"OK: {pkg.identity.package_name} "
            f"({len(pkg.files)} files, {len(pkg.dex_files or [])} DEX, "
            f"{len(pkg.certificates or [])} certs)"
        )
    else:
        cap.verdict = Verdict.PARTIAL
        missing = []
        if not pkg.identity or not pkg.identity.package_name:
            missing.append("package_name")
        if not pkg.hashes:
            missing.append("hashes")
        if not pkg.files:
            missing.append("files")
        cap.message = f"Intake completed but missing: {', '.join(missing)}"
        cap.blame = "apkforge"

    return cap


def validate_inspection(apk_path: Path) -> tuple[CapabilityResult, object]:
    """Test 2-8: Full inspection engine, returns (result, InspectionResult)."""
    from apkforge.inspection.engine import InspectionEngine
    from apkforge.core.models import AnalysisStatus

    cap = CapabilityResult(capability="inspection_full")

    insp, elapsed, exc = _timed(
        lambda: InspectionEngine().inspect(apk_path, keep_workspace=False)
    )
    cap.duration_seconds = elapsed

    if exc:
        etype, emsg, etb = _exc_summary(exc)
        cap.error = emsg
        cap.exception_type = etype
        cap.traceback_snippet = etb
        cap.likely_cause = "Exception during inspection engine"
        cap.blame = "apkforge"
        return cap, None

    if insp is None:
        cap.error = "InspectionEngine.inspect() returned None"
        cap.blame = "apkforge"
        return cap, None

    cap.data_summary = {
        "status": str(insp.status),
        "inspector_statuses": dict(insp.inspector_statuses),
        "inventory": {
            "total_files": insp.inventory.total_file_count,
            "dex_count": insp.inventory.dex_count,
            "native_libs": insp.inventory.native_library_count,
            "resources": insp.inventory.resource_count,
            "assets": insp.inventory.asset_count,
            "embedded_apks": insp.inventory.embedded_apk_count,
            "certificates": insp.inventory.certificate_count,
        },
        "has_manifest": insp.manifest is not None,
        "has_dex": insp.dex is not None,
        "has_native": insp.native is not None,
        "has_resources": insp.resources is not None,
        "has_assets": insp.assets is not None,
        "has_network": insp.network is not None,
        "has_embedded": insp.embedded is not None,
        "has_obfuscation": insp.obfuscation is not None,
        "errors": insp.errors[:5] if insp.errors else [],
        "warnings": insp.warnings[:5] if insp.warnings else [],
        "limitations": insp.limitations[:5] if insp.limitations else [],
    }

    if insp.status == AnalysisStatus.FAILED:
        cap.verdict = Verdict.FAIL
        cap.error = f"Inspection FAILED: {insp.errors[:3]}"
        cap.blame = "apkforge"
    elif insp.status == AnalysisStatus.PARTIAL:
        cap.verdict = Verdict.PARTIAL
        failed_inspectors = [
            k for k, v in insp.inspector_statuses.items()
            if v in ("failed", "error")
        ]
        cap.message = f"Inspection PARTIAL. Failed inspectors: {failed_inspectors}"
        cap.blame = "apkforge"
    elif insp.status == AnalysisStatus.COMPLETE:
        cap.verdict = Verdict.PASS
        cap.message = (
            f"OK: {insp.inventory.total_file_count} files, "
            f"{insp.inventory.dex_count} DEX, "
            f"{insp.inventory.native_library_count} native"
        )
    else:
        cap.verdict = Verdict.PARTIAL
        cap.message = f"Unexpected status: {insp.status}"

    return cap, insp


def validate_sub_inspector(insp, name: str, field_name: str,
                           check_fn) -> CapabilityResult:
    """Validate a specific sub-inspector result from the InspectionResult."""
    cap = CapabilityResult(capability=name)

    if insp is None:
        cap.verdict = Verdict.FAIL
        cap.error = "No InspectionResult available (upstream failure)"
        cap.blame = "apkforge"
        return cap

    sub_result = getattr(insp, field_name, None)
    inspector_status = insp.inspector_statuses.get(field_name, "unknown")

    if sub_result is None:
        if inspector_status in ("failed", "error"):
            cap.verdict = Verdict.FAIL
            cap.error = f"Inspector '{field_name}' failed"
            cap.blame = "apkforge"
        else:
            cap.verdict = Verdict.FAIL
            cap.error = f"Inspector '{field_name}' produced None result"
            cap.blame = "apkforge"
        return cap

    try:
        verdict, message, data = check_fn(sub_result)
        cap.verdict = verdict
        cap.message = message
        cap.data_summary = data
    except Exception:
        etype, emsg, etb = _exc_summary(sys.exc_info())
        cap.verdict = Verdict.FAIL
        cap.error = emsg
        cap.exception_type = etype
        cap.traceback_snippet = etb
        cap.blame = "apkforge"

    return cap


def _check_manifest(m) -> tuple[str, str, dict]:
    data = {
        "package_name": getattr(m, "package_name", None),
        "version_name": getattr(m, "version_name", None),
        "version_code": getattr(m, "version_code", None),
        "min_sdk": getattr(m, "min_sdk", None),
        "target_sdk": getattr(m, "target_sdk", None),
        "permissions_count": len(m.permissions) if getattr(m, "permissions", None) else 0,
        "activities_count": len(m.activities) if getattr(m, "activities", None) else 0,
        "services_count": len(m.services) if getattr(m, "services", None) else 0,
        "receivers_count": len(m.receivers) if getattr(m, "receivers", None) else 0,
        "providers_count": len(m.providers) if getattr(m, "providers", None) else 0,
        "has_application_info": getattr(m, "application", None) is not None,
    }
    if not data["package_name"]:
        return Verdict.FAIL, "No package name extracted from manifest", data
    if data["permissions_count"] == 0:
        # Some minimal apps genuinely have zero permissions
        msg = f"Manifest OK but 0 permissions (may be valid): {data['package_name']}"
        return Verdict.PASS, msg, data
    return (Verdict.PASS,
            f"OK: {data['package_name']}, {data['permissions_count']} perms, "
            f"{data['activities_count']} activities",
            data)


def _check_dex(d) -> tuple[str, str, dict]:
    dex_files = d.dex_files if getattr(d, "dex_files", None) else []
    total_classes = getattr(
        d, "total_classes", sum(getattr(f, "class_count", 0) for f in dex_files)
    )
    total_methods = getattr(
        d, "total_methods", sum(getattr(f, "method_count", 0) for f in dex_files)
    )
    total_strings = len(d.strings) if hasattr(d, "strings") and d.strings else 0
    data = {
        "dex_file_count": len(dex_files),
        "total_classes": total_classes,
        "total_methods": total_methods,
        "total_strings": total_strings,
    }
    if len(dex_files) == 0:
        return Verdict.FAIL, "No DEX files parsed", data
    if total_classes == 0:
        return Verdict.PARTIAL, "DEX files found but 0 classes extracted", data
    return (Verdict.PASS,
            f"OK: {len(dex_files)} DEX, {total_classes} classes, {total_methods} methods",
            data)


def _check_native(n) -> tuple[str, str, dict]:
    libs = n.libraries if n.libraries else []
    data = {
        "library_count": len(libs),
        "abis": list(set(lib.abi for lib in libs if lib.abi)) if libs else [],
    }
    if len(libs) == 0:
        # Some APKs legitimately have no native libs
        return Verdict.PASS, "No native libraries (may be valid for pure-Java apps)", data
    return Verdict.PASS, f"OK: {len(libs)} native libs, ABIs: {data['abis']}", data


def _check_resources(r) -> tuple[str, str, dict]:
    data = {
        "has_resources_arsc": r.has_resources_arsc if hasattr(r, "has_resources_arsc") else None,
        "resource_type_count": len(r.resource_types) if hasattr(r, "resource_types") and r.resource_types else 0,
        "total_resource_entries": r.total_entries if hasattr(r, "total_entries") else None,
    }
    return Verdict.PASS, f"Resources inspection completed", data


def _check_assets(a) -> tuple[str, str, dict]:
    entries = a.entries if hasattr(a, "entries") and a.entries else []
    data = {
        "asset_count": len(entries),
        "total_size": sum(e.size for e in entries if hasattr(e, "size") and e.size) if entries else 0,
    }
    return Verdict.PASS, f"OK: {len(entries)} assets catalogued", data


def _check_network(net) -> tuple[str, str, dict]:
    urls = net.urls if hasattr(net, "urls") and net.urls else []
    domains = net.domains if hasattr(net, "domains") and net.domains else []
    ips = net.ip_addresses if hasattr(net, "ip_addresses") and net.ip_addresses else []
    data = {
        "url_count": len(urls),
        "domain_count": len(domains),
        "ip_count": len(ips),
        "sample_domains": [d.domain if hasattr(d, "domain") else str(d) for d in domains[:5]],
    }
    return (Verdict.PASS,
            f"OK: {len(urls)} URLs, {len(domains)} domains, {len(ips)} IPs",
            data)


def validate_privacy(apk_path: Path, insp=None) -> CapabilityResult:
    """Test 8: Privacy engine."""
    from apkforge.privacy.engine import PrivacyEngine
    from apkforge.core.models import AnalysisStatus

    cap = CapabilityResult(capability="privacy")

    target = insp if insp is not None else apk_path
    priv, elapsed, exc = _timed(
        lambda: PrivacyEngine().analyze(target, keep_workspace=False)
    )
    cap.duration_seconds = elapsed

    if exc:
        etype, emsg, etb = _exc_summary(exc)
        cap.error = emsg
        cap.exception_type = etype
        cap.traceback_snippet = etb
        cap.likely_cause = "Exception during privacy analysis"
        cap.blame = "apkforge"
        return cap

    if priv is None:
        cap.error = "PrivacyEngine.analyze() returned None"
        cap.blame = "apkforge"
        return cap

    perms = priv.permissions
    trackers = priv.trackers
    advertising = priv.advertising
    analytics = priv.analytics
    telemetry = priv.telemetry
    endpoints = priv.endpoints
    data_col = priv.data_collection

    total_sdks = (
        (advertising.total_advertising_sdks if advertising else 0)
        + (analytics.total_analytics_sdks if analytics else 0)
        + (trackers.total_trackers if trackers else 0)
        + (telemetry.total_telemetry_sdks if telemetry else 0)
    )

    cap.data_summary = {
        "status": str(priv.status),
        "package_name": priv.package_name,
        "declared_permissions": len(perms.declared_permissions) if perms else 0,
        "categorized_permission_groups": len(perms.categorized_permissions) if perms and perms.categorized_permissions else 0,
        "usage_details_count": len(perms.usage_details) if perms and perms.usage_details else 0,
        "total_detected_sdks": total_sdks,
        "tracker_count": trackers.total_trackers if trackers else 0,
        "advertising_count": advertising.total_advertising_sdks if advertising else 0,
        "analytics_count": analytics.total_analytics_sdks if analytics else 0,
        "telemetry_count": telemetry.total_telemetry_sdks if telemetry else 0,
        "endpoint_count": endpoints.total_endpoints if endpoints else 0,
        "data_capabilities_count": len(data_col.capabilities) if data_col and data_col.capabilities else 0,
        "findings_count": len(priv.findings) if priv.findings else 0,
        "errors": priv.errors[:3] if priv.errors else [],
        "warnings": priv.warnings[:3] if priv.warnings else [],
    }

    if priv.status == AnalysisStatus.FAILED:
        cap.verdict = Verdict.FAIL
        cap.error = f"Privacy analysis FAILED: {priv.errors[:3]}"
        cap.blame = "apkforge"
    elif priv.status == AnalysisStatus.PARTIAL:
        cap.verdict = Verdict.PARTIAL
        cap.message = f"Privacy analysis PARTIAL: {priv.warnings[:3]}"
    else:
        cap.verdict = Verdict.PASS
        cap.message = (
            f"OK: {cap.data_summary['declared_permissions']} perms, "
            f"{total_sdks} SDKs, "
            f"{cap.data_summary['endpoint_count']} endpoints"
        )

    return cap


def validate_security(apk_path: Path, insp=None, priv=None) -> CapabilityResult:
    """Test 9: Security engine."""
    from apkforge.security.engine import SecurityEngine
    from apkforge.core.models import AnalysisStatus

    cap = CapabilityResult(capability="security")

    def _run():
        engine = SecurityEngine()
        return engine.analyze(
            target=insp,
            privacy=priv,
            apk_path=apk_path,
            keep_workspace=False,
        )

    sec, elapsed, exc = _timed(_run)
    cap.duration_seconds = elapsed

    if exc:
        etype, emsg, etb = _exc_summary(exc)
        cap.error = emsg
        cap.exception_type = etype
        cap.traceback_snippet = etb
        cap.likely_cause = "Exception during security analysis"
        cap.blame = "apkforge"
        return cap

    if sec is None:
        cap.error = "SecurityEngine.analyze() returned None"
        cap.blame = "apkforge"
        return cap

    findings = sec.findings or []
    cap.data_summary = {
        "status": str(sec.status),
        "security_status": str(sec.security_status),
        "total_findings": len(findings),
        "critical": sec.summary.critical_count if sec.summary else 0,
        "high": sec.summary.high_count if sec.summary else 0,
        "medium": sec.summary.medium_count if sec.summary else 0,
        "low": sec.summary.low_count if sec.summary else 0,
        "info": sec.summary.info_count if sec.summary else 0,
        "finding_categories": list(set(
            getattr(f.category, "value", str(f.category)) for f in findings
        )),
        "errors": sec.errors[:3] if sec.errors else [],
        "warnings": sec.warnings[:3] if sec.warnings else [],
    }

    if sec.status == AnalysisStatus.FAILED:
        cap.verdict = Verdict.FAIL
        cap.error = f"Security analysis FAILED: {sec.errors[:3]}"
        cap.blame = "apkforge"
    elif sec.status == AnalysisStatus.PARTIAL:
        cap.verdict = Verdict.PARTIAL
        cap.message = f"Security analysis PARTIAL: {sec.warnings[:3]}"
    else:
        cap.verdict = Verdict.PASS
        cap.message = (
            f"OK: {len(findings)} findings "
            f"(C:{cap.data_summary['critical']} H:{cap.data_summary['high']} "
            f"M:{cap.data_summary['medium']} L:{cap.data_summary['low']} "
            f"I:{cap.data_summary['info']})"
        )

    return cap


def validate_modification_planning(apk_path: Path, insp=None, priv=None,
                                   sec=None) -> CapabilityResult:
    """Test 12: Modification planning."""
    from apkforge.modification.planner import ModificationPlanner

    cap = CapabilityResult(capability="modification_planning")

    def _run():
        planner = ModificationPlanner()
        return planner.create_plan(
            apk_path=apk_path,
            inspection=insp,
            privacy=priv,
            security=sec,
        )

    plan, elapsed, exc = _timed(_run)
    cap.duration_seconds = elapsed

    if exc:
        etype, emsg, etb = _exc_summary(exc)
        cap.error = emsg
        cap.exception_type = etype
        cap.traceback_snippet = etb
        cap.likely_cause = "Exception during modification planning"
        cap.blame = "apkforge"
        return cap

    if plan is None:
        cap.error = "ModificationPlanner.create_plan() returned None"
        cap.blame = "apkforge"
        return cap

    changes = plan.changes or []
    cap.data_summary = {
        "plan_id": plan.plan_id,
        "status": str(plan.status),
        "change_count": plan.change_count,
        "change_types": list(set(c.change_type.value for c in changes)),
        "has_conflicts": plan.has_conflicts,
        "conflict_count": len(plan.conflicts) if plan.conflicts else 0,
        "dependency_count": len(plan.dependencies) if plan.dependencies else 0,
        "warnings": plan.warnings[:3] if plan.warnings else [],
        "limitations": plan.limitations[:3] if plan.limitations else [],
    }

    if plan.change_count > 0:
        cap.verdict = Verdict.PASS
        cap.message = (
            f"OK: {plan.change_count} changes proposed "
            f"(types: {cap.data_summary['change_types']})"
        )
    elif plan.limitations:
        cap.verdict = Verdict.PARTIAL
        cap.message = f"Plan generated but 0 changes. Limitations: {plan.limitations[:2]}"
    else:
        cap.verdict = Verdict.PASS
        cap.message = "Plan generated with 0 changes (no modifications proposed)"

    return cap


# ---------------------------------------------------------------------------
# Diff validation (pick pairs)
# ---------------------------------------------------------------------------


def validate_diff(apk_a: Path, apk_b: Path) -> CapabilityResult:
    """Test 11: APK diff between two APKs."""
    from apkforge.diff.engine import DiffEngine
    from apkforge.core.models import AnalysisStatus

    cap = CapabilityResult(capability="diff")

    def _run():
        engine = DiffEngine()
        return engine.diff(apk_a, apk_b, keep_workspace=False)

    result, elapsed, exc = _timed(_run)
    cap.duration_seconds = elapsed

    if exc:
        etype, emsg, etb = _exc_summary(exc)
        cap.error = emsg
        cap.exception_type = etype
        cap.traceback_snippet = etb
        cap.likely_cause = "Exception during APK diff"
        cap.blame = "apkforge"
        return cap

    if result is None:
        cap.error = "DiffEngine.diff() returned None"
        cap.blame = "apkforge"
        return cap

    cap.data_summary = {
        "status": str(result.status),
        "apk_a": result.apk_a.file_name if result.apk_a else str(apk_a.name),
        "apk_b": result.apk_b.file_name if result.apk_b else str(apk_b.name),
        "summary_lines": len(result.summary.text_lines) if result.summary else 0,
        "identity_changes": len(result.identity.changes) if result.identity else 0,
        "permission_changes": (
            len(result.permissions.added) + len(result.permissions.removed)
            if result.permissions else 0
        ),
        "errors": result.errors[:3] if result.errors else [],
    }

    if result.status == AnalysisStatus.FAILED:
        cap.verdict = Verdict.FAIL
        cap.error = f"Diff FAILED: {result.errors[:3]}"
        cap.blame = "apkforge"
    elif result.status == AnalysisStatus.PARTIAL:
        cap.verdict = Verdict.PARTIAL
        cap.message = f"Diff PARTIAL: {result.warnings[:3]}"
    else:
        cap.verdict = Verdict.PASS
        cap.message = f"OK: diff produced with {cap.data_summary['summary_lines']} summary lines"

    return cap


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------


def run_single_apk(apk_path: Path) -> dict:
    """Run all capability validations against a single APK."""
    print(f"\n{'='*70}")
    print(f"  Testing: {apk_path.name} ({apk_path.stat().st_size / 1024 / 1024:.1f} MB)")
    print(f"{'='*70}")

    results = []
    insp_result = None
    priv_result_obj = None
    sec_result_obj = None

    # 1. Intake
    print("  [1/8] Intake...", end=" ", flush=True)
    intake_r = validate_intake(apk_path)
    results.append(asdict(intake_r))
    print(f"{intake_r.verdict} ({intake_r.duration_seconds:.1f}s)")

    # 2. Full Inspection (includes manifest, dex, native, resources, assets, network)
    print("  [2/8] Inspection...", end=" ", flush=True)
    insp_cap, insp_result = validate_inspection(apk_path)
    results.append(asdict(insp_cap))
    print(f"{insp_cap.verdict} ({insp_cap.duration_seconds:.1f}s)")

    # 3. Sub-inspector validations
    sub_checks = [
        ("manifest", "manifest", _check_manifest),
        ("dex", "dex", _check_dex),
        ("native_libraries", "native", _check_native),
        ("resources_assets", "resources", _check_resources),
        ("strings_urls_domains", "network", _check_network),
    ]
    for i, (name, field_name, check_fn) in enumerate(sub_checks, start=3):
        print(f"  [{i}/8] {name}...", end=" ", flush=True)
        sub_r = validate_sub_inspector(insp_result, name, field_name, check_fn)
        results.append(asdict(sub_r))
        print(f"{sub_r.verdict}")

    # Also check assets sub-inspector
    assets_r = validate_sub_inspector(insp_result, "assets", "assets", _check_assets)
    results.append(asdict(assets_r))

    # 6. Privacy
    print("  [6/8] Privacy...", end=" ", flush=True)
    priv_r = validate_privacy(apk_path, insp=insp_result)
    results.append(asdict(priv_r))
    print(f"{priv_r.verdict} ({priv_r.duration_seconds:.1f}s)")

    # Recover privacy result object for security engine
    if priv_r.verdict != Verdict.FAIL:
        try:
            from apkforge.privacy.engine import PrivacyEngine
            if insp_result is not None:
                priv_result_obj = PrivacyEngine().analyze(insp_result, keep_workspace=False)
        except Exception:
            pass

    # 7. Security
    print("  [7/8] Security...", end=" ", flush=True)
    sec_r = validate_security(apk_path, insp=insp_result, priv=priv_result_obj)
    results.append(asdict(sec_r))
    print(f"{sec_r.verdict} ({sec_r.duration_seconds:.1f}s)")

    # Recover security result object for planner
    if sec_r.verdict != Verdict.FAIL:
        try:
            from apkforge.security.engine import SecurityEngine
            if insp_result is not None:
                sec_result_obj = SecurityEngine().analyze(
                    target=insp_result, privacy=priv_result_obj,
                    apk_path=apk_path, keep_workspace=False,
                )
        except Exception:
            pass

    # 8. Modification Planning
    print("  [8/8] Mod planning...", end=" ", flush=True)
    plan_r = validate_modification_planning(
        apk_path, insp=insp_result, priv=priv_result_obj, sec=sec_result_obj
    )
    results.append(asdict(plan_r))
    print(f"{plan_r.verdict} ({plan_r.duration_seconds:.1f}s)")

    # Force GC to free memory (especially for large APKs)
    del insp_result, priv_result_obj, sec_result_obj
    gc.collect()

    return {
        "filename": apk_path.name,
        "file_size_bytes": apk_path.stat().st_size,
        "capabilities": results,
    }


def run_diff_validation(apks: list[Path]) -> list[dict]:
    """Run diff validation on selected APK pairs."""
    if len(apks) < 2:
        return []

    # Pick 3 diverse pairs: small-small, small-large, mid-mid
    sorted_apks = sorted(apks, key=lambda p: p.stat().st_size)
    pairs = [
        (sorted_apks[0], sorted_apks[1]),  # two smallest
        (sorted_apks[0], sorted_apks[-1]), # smallest vs largest
    ]
    if len(sorted_apks) > 4:
        mid = len(sorted_apks) // 2
        pairs.append((sorted_apks[mid], sorted_apks[mid + 1]))

    diff_results = []
    for i, (a, b) in enumerate(pairs):
        print(f"\n  Diff pair {i+1}: {a.name} vs {b.name}...", end=" ", flush=True)
        dr = validate_diff(a, b)
        dr_dict = asdict(dr)
        dr_dict["apk_a"] = a.name
        dr_dict["apk_b"] = b.name
        diff_results.append(dr_dict)
        print(f"{dr.verdict} ({dr.duration_seconds:.1f}s)")

    return diff_results


def main():
    print("=" * 70)
    print("  APKForge Phase A — Corpus Validation Runner")
    print("=" * 70)

    # Discover corpus
    if not CORPUS_DIR.exists():
        print(f"ERROR: Corpus directory not found: {CORPUS_DIR}")
        sys.exit(1)

    apks = sorted(CORPUS_DIR.glob("*.apk"))
    if not apks:
        print(f"ERROR: No APK files found in {CORPUS_DIR}")
        sys.exit(1)

    print(f"\nCorpus directory: {CORPUS_DIR}")
    print(f"APK files found: {len(apks)}")
    for a in apks:
        print(f"  • {a.name} ({a.stat().st_size / 1024 / 1024:.1f} MB)")

    # Run per-APK validations
    all_results = []
    total_start = time.monotonic()

    for apk_path in apks:
        result = run_single_apk(apk_path)
        all_results.append(result)

    # Run diff validations
    print(f"\n{'='*70}")
    print("  Diff Validation (selected pairs)")
    print(f"{'='*70}")
    diff_results = run_diff_validation(apks)

    total_elapsed = time.monotonic() - total_start

    # Compile final report data
    report = {
        "meta": {
            "runner_version": "1.0.0",
            "corpus_dir": str(CORPUS_DIR),
            "total_apks": len(apks),
            "total_duration_seconds": round(total_elapsed, 1),
            "environment": environment_identity(),
        },
        "per_apk_results": all_results,
        "diff_results": diff_results,
    }

    # Write JSON
    RESULTS_FILE.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(f"\n\nResults saved to: {RESULTS_FILE}")

    # Print summary matrix
    print(f"\n{'='*70}")
    print("  SUMMARY MATRIX")
    print(f"{'='*70}")

    capabilities = set()
    for r in all_results:
        for c in r["capabilities"]:
            capabilities.add(c["capability"])
    capabilities = sorted(capabilities)

    # Header
    max_cap_len = max(len(c) for c in capabilities)
    header = f"{'Capability':<{max_cap_len+2}}"
    for r in all_results:
        short_name = r["filename"].split("_")[0][:12]
        header += f" {short_name:>12}"
    print(header)
    print("-" * len(header))

    # Rows
    for cap_name in capabilities:
        row = f"{cap_name:<{max_cap_len+2}}"
        for r in all_results:
            verdict = "N/A"
            for c in r["capabilities"]:
                if c["capability"] == cap_name:
                    verdict = c["verdict"]
                    break
            color = {"PASS": "✓", "PARTIAL": "◐", "FAIL": "✗", "NOT_APPLICABLE": "—"}
            row += f" {color.get(verdict, '?'):>12}"
        print(row)

    # Summary counts
    print(f"\n{'='*70}")
    print("  AGGREGATE COUNTS")
    print(f"{'='*70}")
    total_pass = sum(
        1 for r in all_results for c in r["capabilities"] if c["verdict"] == "PASS"
    )
    total_partial = sum(
        1 for r in all_results for c in r["capabilities"] if c["verdict"] == "PARTIAL"
    )
    total_fail = sum(
        1 for r in all_results for c in r["capabilities"] if c["verdict"] == "FAIL"
    )
    total_na = sum(
        1 for r in all_results for c in r["capabilities"] if c["verdict"] == "NOT_APPLICABLE"
    )
    total_tests = total_pass + total_partial + total_fail + total_na
    print(f"  Total tests: {total_tests}")
    print(f"  PASS:        {total_pass}")
    print(f"  PARTIAL:     {total_partial}")
    print(f"  FAIL:        {total_fail}")
    print(f"  N/A:         {total_na}")
    print(f"  Duration:    {total_elapsed:.1f}s")

    # Print failures and partials
    failures = []
    partials = []
    for r in all_results:
        for c in r["capabilities"]:
            entry = {"apk": r["filename"], **c}
            if c["verdict"] == "FAIL":
                failures.append(entry)
            elif c["verdict"] == "PARTIAL":
                partials.append(entry)

    if failures:
        print(f"\n{'='*70}")
        print(f"  FAILURES ({len(failures)})")
        print(f"{'='*70}")
        for f in failures:
            print(f"\n  APK:        {f['apk']}")
            print(f"  Capability: {f['capability']}")
            print(f"  Error:      {f['error'][:200]}")
            if f.get("exception_type"):
                print(f"  Exception:  {f['exception_type']}")
            if f.get("likely_cause"):
                print(f"  Cause:      {f['likely_cause']}")
            if f.get("blame"):
                print(f"  Blame:      {f['blame']}")

    if partials:
        print(f"\n{'='*70}")
        print(f"  PARTIAL RESULTS ({len(partials)})")
        print(f"{'='*70}")
        for p in partials:
            print(f"\n  APK:        {p['apk']}")
            print(f"  Capability: {p['capability']}")
            print(f"  Message:    {p['message'][:200]}")
            if p.get("error"):
                print(f"  Error:      {p['error'][:200]}")

    # Diff summary
    if diff_results:
        print(f"\n{'='*70}")
        print(f"  DIFF RESULTS ({len(diff_results)} pairs)")
        print(f"{'='*70}")
        for d in diff_results:
            v = d["verdict"]
            sym = {"PASS": "✓", "PARTIAL": "◐", "FAIL": "✗"}.get(v, "?")
            print(f"  {sym} {d.get('apk_a', '?')} vs {d.get('apk_b', '?')}: {v}")
            if d.get("error"):
                print(f"    Error: {d['error'][:200]}")

    print(f"\n{'='*70}")
    print(f"  Phase A Corpus Validation Complete")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    main()
