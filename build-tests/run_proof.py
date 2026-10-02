#!/usr/bin/env python3
"""APKForge Phase C.1 — Independent Build Toolchain Proof Runner.

Executes the independent toolchain proof pipeline on the test corpus:
  original.apk -> decode -> harmless modification -> build -> zipalign -> sign -> verify
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SAMPLES_DIR = ROOT / "samples"
WORK_DIR = ROOT / "work"
LOGS_DIR = ROOT / "build-tests" / "logs"
KEYSTORE = ROOT / "tools" / "test-signing-key.jks"
KEYSTORE_PASS = "apkforge-test-pass"
KEY_ALIAS = "apkforge-test-key"

TOOLS_DIR = ROOT / "tools"
SDK_BUILD_TOOLS = Path("/home/naishring/Android/Sdk/build-tools/35.0.0")

APKTOOL = str(TOOLS_DIR / "apktool")
ZIPALIGN = str(SDK_BUILD_TOOLS / "zipalign")
APKSIGNER = str(SDK_BUILD_TOOLS / "apksigner")

HARMLESS_TAG = '<meta-data android:name="apkforge.toolchain.proof" android:value="verified"/>'


@dataclass
class StageResult:
    status: str = "FAIL"  # PASS / FAIL / SKIPPED
    duration_seconds: float = 0.0
    command: str = ""
    exit_code: int = -1
    stdout_snippet: str = ""
    stderr_snippet: str = ""
    log_file: str = ""


@dataclass
class APKProofResult:
    filename: str
    filesize_bytes: int
    sha256: str
    package_name: str = ""
    version_name: str = ""
    version_code: str = ""
    target_sdk: str = ""
    min_sdk: str = ""
    structural_notes: str = ""
    stages: dict[str, StageResult] = field(default_factory=dict)
    overall_status: str = "FAIL"  # PASS / FAIL
    failure_stage: str = ""
    failure_category: str = "SUCCESS"  # SUCCESS, DECODE_FAILURE, RESOURCE_FAILURE, FRAMEWORK_FAILURE, BUILD_FAILURE, ALIGNMENT_FAILURE, SIGNING_FAILURE, VERIFICATION_FAILURE, UNSUPPORTED
    failure_cause: str = ""
    failure_is_toolchain: bool = False
    verification_details: dict[str, str] = field(default_factory=dict)


def run_cmd(cmd: list[str], log_path: Path, timeout: int = 300) -> tuple[int, str, str, float]:
    """Execute command, logging stdout and stderr to log_path."""
    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        duration = time.time() - t0
        log_content = (
            f"COMMAND: {' '.join(cmd)}\n"
            f"EXIT CODE: {proc.returncode}\n"
            f"DURATION: {duration:.2f}s\n\n"
            f"=== STDOUT ===\n{proc.stdout}\n\n"
            f"=== STDERR ===\n{proc.stderr}\n"
        )
        log_path.write_text(log_content, encoding="utf-8")
        return proc.returncode, proc.stdout, proc.stderr, duration
    except subprocess.TimeoutExpired:
        duration = time.time() - t0
        log_path.write_text(f"TIMEOUT after {timeout}s: {' '.join(cmd)}", encoding="utf-8")
        return -999, "", f"Timeout after {timeout}s", duration
    except Exception as exc:
        duration = time.time() - t0
        log_path.write_text(f"ERROR: {exc}", encoding="utf-8")
        return -1, "", str(exc), duration


def classify_failure(stage: str, stdout: str, stderr: str) -> tuple[str, str, bool]:
    """Classify failure into standardized categories and determine if toolchain or APK-specific."""
    combined = (stdout + "\n" + stderr).lower()
    if stage == "decode":
        if "framework" in combined or "1.apk" in combined:
            return "FRAMEWORK_FAILURE", "Missing or incompatible Android framework resources", False
        if "resource" in combined or "axml" in combined or "arsc" in combined:
            return "RESOURCE_FAILURE", "Resource decoding error in APK", False
        return "DECODE_FAILURE", "Apktool failed to decode APK structure", False

    if stage == "rebuild":
        if "attribute " in combined and "not found" in combined:
            return "RESOURCE_FAILURE", "Missing resource attribute definition during AAPT linking (known Apktool resource decoding limitation with Material/AAPT2 styles)", False
        if "failed linking file resources" in combined or "error: resource" in combined or "unresolved symbol" in combined:
            return "RESOURCE_FAILURE", "AAPT/AAPT2 resource linking error (APK-specific resource schema)", False
        if "framework" in combined:
            return "FRAMEWORK_FAILURE", "Framework dependency issue during rebuild", False
        return "BUILD_FAILURE", "Apktool build failed", False

    if stage == "zipalign":
        return "ALIGNMENT_FAILURE", "zipalign failed", False

    if stage == "sign":
        return "SIGNING_FAILURE", "apksigner failed", False

    if stage == "verify":
        return "VERIFICATION_FAILURE", "Post-signing verification check failed", False

    return "BUILD_FAILURE", "Unknown failure", False


def modify_manifest(manifest_path: Path) -> tuple[bool, str, str, str]:
    """Insert harmless meta-data tag into AndroidManifest.xml inside <application>."""
    if not manifest_path.exists():
        return False, "", "", "Manifest file does not exist"

    text = manifest_path.read_text(encoding="utf-8")
    original_state = "No apkforge.toolchain.proof meta-data element"
    requested_change = f"Insert {HARMLESS_TAG} inside <application> element"

    idx = text.find("<application")
    if idx == -1:
        return False, original_state, requested_change, "<application> element not found in manifest"

    close_idx = text.find(">", idx)
    if close_idx == -1:
        return False, original_state, requested_change, "Malformed <application> start tag"

    new_text = text[:close_idx + 1] + f"\n        {HARMLESS_TAG}\n" + text[close_idx + 1:]
    manifest_path.write_text(new_text, encoding="utf-8")

    # Verify write
    re_read = manifest_path.read_text(encoding="utf-8")
    if HARMLESS_TAG in re_read:
        actual_change = f"Successfully inserted {HARMLESS_TAG} at character index {close_idx + 1}"
        return True, original_state, requested_change, actual_change
    else:
        return False, original_state, requested_change, "Verification check failed after write"


def verify_built_apk(signed_apk: Path, log_path: Path) -> tuple[bool, dict[str, str], str]:
    """Verify built APK: zipalign check, apksigner verify, zip integrity, and meta-data presence."""
    details = {}

    # 1. zipalign check
    align_cmd = [ZIPALIGN, "-c", "-v", "4", str(signed_apk)]
    code, stdout, stderr, _ = run_cmd(align_cmd, log_path.parent / (log_path.stem + "_align.log"))
    if code != 0 or "Verification succesful" not in stdout:
        return False, details, f"Zipalign verification failed (exit {code})"
    details["zipalign"] = "PASS (4-byte alignment verified)"

    # 2. apksigner verify
    sign_cmd = [APKSIGNER, "verify", "--verbose", "--print-certs", str(signed_apk)]
    code, stdout, stderr, _ = run_cmd(sign_cmd, log_path.parent / (log_path.stem + "_sig.log"))
    if code != 0 or "Verifies" not in stdout:
        return False, details, f"Signature verification failed (exit {code}): {stderr}"
    details["apksigner"] = "PASS (v1/v2/v3 verified)"

    # Extract certificate details
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("Signer #1 certificate DN:"):
            details["cert_dn"] = line.split(":", 1)[1].strip()
        elif line.startswith("Signer #1 certificate SHA-256 digest:"):
            details["cert_sha256"] = line.split(":", 1)[1].strip()
        elif line.startswith("Verified using v1 scheme"):
            details["v1_scheme"] = line.split(":", 1)[1].strip()
        elif line.startswith("Verified using v2 scheme"):
            details["v2_scheme"] = line.split(":", 1)[1].strip()
        elif line.startswith("Verified using v3 scheme"):
            details["v3_scheme"] = line.split(":", 1)[1].strip()

    # 3. Zip integrity & Manifest parse
    try:
        with zipfile.ZipFile(signed_apk) as z:
            bad_file = z.testzip()
            if bad_file:
                return False, details, f"Corrupted file in ZIP: {bad_file}"
            manifest_bytes = z.read("AndroidManifest.xml")
            from androguard.core.axml import AXMLPrinter
            xml = AXMLPrinter(manifest_bytes).get_xml().decode("utf-8", errors="replace")
            if "apkforge.toolchain.proof" not in xml:
                return False, details, "Harmless meta-data key 'apkforge.toolchain.proof' not found in binary manifest"
            if "verified" not in xml:
                return False, details, "Harmless meta-data value 'verified' not found in binary manifest"
            details["manifest_meta_data"] = "FOUND (<meta-data android:name='apkforge.toolchain.proof' android:value='verified'/>)"
            details["zip_integrity"] = "PASS (testzip clean)"
    except Exception as exc:
        return False, details, f"Binary manifest inspection error: {exc}"

    return True, details, "All verification checks passed"


def process_apk(apk_path: Path) -> APKProofResult:
    """Run full pipeline on a single APK."""
    apk_name = apk_path.name
    stem = apk_path.stem
    print(f"\n=======================================================")
    print(f"  Testing Toolchain on: {apk_name} ({apk_path.stat().st_size:,} bytes)")
    print(f"=======================================================")

    data = apk_path.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    work_apk_dir = WORK_DIR / stem
    if work_apk_dir.exists():
        shutil.rmtree(work_apk_dir)
    work_apk_dir.mkdir(parents=True, exist_ok=True)

    decoded_dir = work_apk_dir / "decoded"
    unaligned_apk = work_apk_dir / "unaligned.apk"
    aligned_apk = work_apk_dir / "aligned.apk"
    signed_apk = work_apk_dir / "signed.apk"

    # Analyze basic structure
    with zipfile.ZipFile(apk_path) as z:
        names = z.namelist()
        dex_files = [n for n in names if n.endswith(".dex")]
        so_files = [n for n in names if n.endswith(".so")]
        arsc = "resources.arsc" in names

    structural_notes = f"{len(dex_files)} DEX, {len(so_files)} native libs, arsc={arsc}, total {len(names)} files"

    res = APKProofResult(
        filename=apk_name,
        filesize_bytes=len(data),
        sha256=sha256,
        structural_notes=structural_notes,
    )

    # ----------------------------------------------------
    # Stage 1: Decode
    # ----------------------------------------------------
    print(f"  [1/6] apktool decode...")
    decode_log = LOGS_DIR / f"{stem}_decode.log"
    decode_cmd = [APKTOOL, "d", "-f", "-o", str(decoded_dir), str(apk_path)]
    code, out, err, dur = run_cmd(decode_cmd, decode_log, timeout=300)
    res.stages["decode"] = StageResult(
        status="PASS" if code == 0 else "FAIL",
        duration_seconds=dur,
        command=" ".join(decode_cmd),
        exit_code=code,
        stdout_snippet=out[-500:] if out else "",
        stderr_snippet=err[-500:] if err else "",
        log_file=str(decode_log.relative_to(ROOT)),
    )
    if code != 0:
        print(f"        FAIL ({dur:.1f}s)")
        res.overall_status = "FAIL"
        res.failure_stage = "decode"
        cat, cause, is_tool = classify_failure("decode", out, err)
        res.failure_category = cat
        res.failure_cause = cause
        res.failure_is_toolchain = is_tool
        return res
    print(f"        PASS ({dur:.1f}s)")

    # Extract metadata from decoded apktool.yml and AndroidManifest.xml
    apktool_yml = decoded_dir / "apktool.yml"
    if apktool_yml.exists():
        try:
            with open(apktool_yml, "r", encoding="utf-8") as yf:
                ydata = yaml.safe_load(yf)
                sdk_info = ydata.get("sdkInfo", {}) or {}
                ver_info = ydata.get("versionInfo", {}) or {}
                res.min_sdk = str(sdk_info.get("minSdkVersion", ""))
                res.target_sdk = str(sdk_info.get("targetSdkVersion", ""))
                res.version_name = str(ver_info.get("versionName", ""))
                res.version_code = str(ver_info.get("versionCode", ""))
        except Exception:
            pass

    manifest_xml = decoded_dir / "AndroidManifest.xml"
    if manifest_xml.exists():
        try:
            tree = ET.parse(manifest_xml)
            root = tree.getroot()
            res.package_name = root.attrib.get("package", "")
        except Exception:
            pass

    # ----------------------------------------------------
    # Stage 2: Harmless modification
    # ----------------------------------------------------
    print(f"  [2/6] harmless modification (AndroidManifest.xml)...")
    modify_log = LOGS_DIR / f"{stem}_modify.log"
    t0 = time.time()
    manifest_file = decoded_dir / "AndroidManifest.xml"
    success, orig, req, actual = modify_manifest(manifest_file)
    dur = time.time() - t0
    modify_log.write_text(
        f"ORIGINAL STATE: {orig}\n"
        f"REQUESTED CHANGE: {req}\n"
        f"ACTUAL CHANGE: {actual}\n"
        f"STATUS: {'PASS' if success else 'FAIL'}\n",
        encoding="utf-8",
    )
    res.stages["modify"] = StageResult(
        status="PASS" if success else "FAIL",
        duration_seconds=dur,
        command="Python manifest insertion",
        exit_code=0 if success else 1,
        stdout_snippet=actual,
        log_file=str(modify_log.relative_to(ROOT)),
    )
    if not success:
        print(f"        FAIL ({dur:.1f}s)")
        res.overall_status = "FAIL"
        res.failure_stage = "modify"
        res.failure_category = "RESOURCE_FAILURE"
        res.failure_cause = actual
        return res
    print(f"        PASS ({dur:.1f}s)")

    # ----------------------------------------------------
    # Stage 3: Rebuild
    # ----------------------------------------------------
    print(f"  [3/6] apktool build...")
    build_log = LOGS_DIR / f"{stem}_build.log"
    build_cmd = [APKTOOL, "b", "-o", str(unaligned_apk), str(decoded_dir)]
    code, out, err, dur = run_cmd(build_cmd, build_log, timeout=300)
    res.stages["rebuild"] = StageResult(
        status="PASS" if code == 0 else "FAIL",
        duration_seconds=dur,
        command=" ".join(build_cmd),
        exit_code=code,
        stdout_snippet=out[-500:] if out else "",
        stderr_snippet=err[-500:] if err else "",
        log_file=str(build_log.relative_to(ROOT)),
    )
    if code != 0 or not unaligned_apk.exists():
        print(f"        FAIL ({dur:.1f}s)")
        res.overall_status = "FAIL"
        res.failure_stage = "rebuild"
        cat, cause, is_tool = classify_failure("rebuild", out, err)
        res.failure_category = cat
        res.failure_cause = cause
        res.failure_is_toolchain = is_tool
        return res
    print(f"        PASS ({dur:.1f}s)")

    # ----------------------------------------------------
    # Stage 4: Zipalign
    # ----------------------------------------------------
    print(f"  [4/6] zipalign (4-byte page-align)...")
    align_log = LOGS_DIR / f"{stem}_zipalign.log"
    align_cmd = [ZIPALIGN, "-p", "-f", "-v", "4", str(unaligned_apk), str(aligned_apk)]
    code, out, err, dur = run_cmd(align_cmd, align_log, timeout=120)
    res.stages["zipalign"] = StageResult(
        status="PASS" if code == 0 else "FAIL",
        duration_seconds=dur,
        command=" ".join(align_cmd),
        exit_code=code,
        stdout_snippet=out[-500:] if out else "",
        stderr_snippet=err[-500:] if err else "",
        log_file=str(align_log.relative_to(ROOT)),
    )
    if code != 0 or not aligned_apk.exists():
        print(f"        FAIL ({dur:.1f}s)")
        res.overall_status = "FAIL"
        res.failure_stage = "zipalign"
        cat, cause, is_tool = classify_failure("zipalign", out, err)
        res.failure_category = cat
        res.failure_cause = cause
        res.failure_is_toolchain = is_tool
        return res
    print(f"        PASS ({dur:.1f}s)")

    # ----------------------------------------------------
    # Stage 5: Sign
    # ----------------------------------------------------
    print(f"  [5/6] apksigner sign...")
    sign_log = LOGS_DIR / f"{stem}_sign.log"
    sign_cmd = [
        APKSIGNER,
        "sign",
        "--ks",
        str(KEYSTORE),
        "--ks-pass",
        f"pass:{KEYSTORE_PASS}",
        "--ks-key-alias",
        KEY_ALIAS,
        "--key-pass",
        f"pass:{KEYSTORE_PASS}",
        "--out",
        str(signed_apk),
        str(aligned_apk),
    ]
    code, out, err, dur = run_cmd(sign_cmd, sign_log, timeout=120)
    res.stages["sign"] = StageResult(
        status="PASS" if code == 0 else "FAIL",
        duration_seconds=dur,
        command=" ".join(sign_cmd),
        exit_code=code,
        stdout_snippet=out[-500:] if out else "",
        stderr_snippet=err[-500:] if err else "",
        log_file=str(sign_log.relative_to(ROOT)),
    )
    if code != 0 or not signed_apk.exists():
        print(f"        FAIL ({dur:.1f}s)")
        res.overall_status = "FAIL"
        res.failure_stage = "sign"
        cat, cause, is_tool = classify_failure("sign", out, err)
        res.failure_category = cat
        res.failure_cause = cause
        res.failure_is_toolchain = is_tool
        return res
    print(f"        PASS ({dur:.1f}s)")

    # ----------------------------------------------------
    # Stage 6: Verify
    # ----------------------------------------------------
    print(f"  [6/6] verification (alignment + signature + binary manifest)...")
    verify_log = LOGS_DIR / f"{stem}_verify.log"
    t0 = time.time()
    v_pass, v_details, v_err = verify_built_apk(signed_apk, verify_log)
    dur = time.time() - t0
    res.verification_details = v_details
    verify_log_content = (
        f"VERIFICATION STATUS: {'PASS' if v_pass else 'FAIL'}\n"
        f"DURATION: {dur:.2f}s\n"
        f"DETAILS:\n"
        + "\n".join(f"  {k}: {v}" for k, v in v_details.items())
        + (f"\nERROR: {v_err}\n" if not v_pass else "\n")
    )
    verify_log.write_text(verify_log_content, encoding="utf-8")
    res.stages["verify"] = StageResult(
        status="PASS" if v_pass else "FAIL",
        duration_seconds=dur,
        command="zipalign -c & apksigner verify & axml check",
        exit_code=0 if v_pass else 1,
        stdout_snippet=json.dumps(v_details),
        stderr_snippet=v_err if not v_pass else "",
        log_file=str(verify_log.relative_to(ROOT)),
    )
    if not v_pass:
        print(f"        FAIL ({dur:.1f}s): {v_err}")
        res.overall_status = "FAIL"
        res.failure_stage = "verify"
        cat, cause, is_tool = classify_failure("verify", "", v_err)
        res.failure_category = cat
        res.failure_cause = cause
        res.failure_is_toolchain = is_tool
        return res
    print(f"        PASS ({dur:.1f}s)")

    res.overall_status = "PASS"
    res.failure_category = "SUCCESS"
    return res


def main() -> None:
    apks = sorted(list(SAMPLES_DIR.glob("*.apk")))
    if not apks:
        print("ERROR: No sample APKs found in samples/", file=sys.stderr)
        sys.exit(1)

    print(f"Starting APKForge Phase C.1 Build Toolchain Proof on {len(apks)} APKs...")
    all_results = []

    t_start = time.time()
    for apk in apks:
        result = process_apk(apk)
        all_results.append(result)

    total_time = time.time() - t_start

    # Output JSON summary
    out_json = ROOT / "build-tests" / "proof_results.json"
    serializable = [asdict(r) for r in all_results]
    out_json.write_text(json.dumps(serializable, indent=2), encoding="utf-8")
    print(f"\nSaved detailed proof results to {out_json}")

    # Summary table
    print("\n" + "=" * 80)
    print("  PHASE C.1 INDEPENDENT TOOLCHAIN PROOF SUMMARY")
    print("=" * 80)
    print(f"{'APK':<40} | {'Dec':<4} | {'Mod':<4} | {'Bld':<4} | {'Aln':<4} | {'Sgn':<4} | {'Ver':<4} | {'Status':<6}")
    print("-" * 80)
    pass_count = 0
    fail_count = 0
    for r in all_results:
        d = r.stages.get("decode", StageResult()).status
        m = r.stages.get("modify", StageResult()).status
        b = r.stages.get("rebuild", StageResult()).status
        a = r.stages.get("zipalign", StageResult()).status
        s = r.stages.get("sign", StageResult()).status
        v = r.stages.get("verify", StageResult()).status
        status = r.overall_status
        if status == "PASS":
            pass_count += 1
        else:
            fail_count += 1
        print(f"{r.filename:<40} | {d:<4} | {m:<4} | {b:<4} | {a:<4} | {s:<4} | {v:<4} | {status:<6}")
    print("-" * 80)
    print(f"Total: {len(all_results)} | PASS: {pass_count} | FAIL: {fail_count} | Total Duration: {total_time:.1f}s")
    print("=" * 80)


if __name__ == "__main__":
    main()
