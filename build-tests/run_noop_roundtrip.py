#!/usr/bin/env python3
"""APKForge Phase C.1b — True No-Op Round Trip Runner & Structural Diff.

Executes an exact round trip with ZERO modifications on all 9 corpus APKs:
  original APK -> decode -> build (NO EDIT) -> zipalign -> sign -> verify

Analyzes structural differences between original and rebuilt APKs:
  - File lists, additions, removals
  - Manifest representation
  - DEX differences (smali roundtrip effects)
  - resources.arsc differences
  - Native library preservation (lib/)
  - META-INF / signature differences
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import time
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SAMPLES_DIR = ROOT / "samples"
WORK_DIR = ROOT / "work" / "c1b" / "noop"
LOGS_DIR = ROOT / "build-tests" / "logs" / "c1b"
KEYSTORE = ROOT / "tools" / "test-signing-key.jks"
KEYSTORE_PASS = "apkforge-test-pass"
KEY_ALIAS = "apkforge-test-key"

SDK_BUILD_TOOLS = Path("/home/naishring/Android/Sdk/build-tools/35.0.0")
APKTOOL = str(ROOT / "tools" / "apktool")
ZIPALIGN = str(SDK_BUILD_TOOLS / "zipalign")
APKSIGNER = str(SDK_BUILD_TOOLS / "apksigner")


@dataclass
class StageResult:
    status: str = "FAIL"
    duration_seconds: float = 0.0
    command: str = ""
    exit_code: int = -1
    stdout_snippet: str = ""
    stderr_snippet: str = ""
    log_file: str = ""


@dataclass
class StructuralDiff:
    orig_file_count: int = 0
    rebuilt_file_count: int = 0
    files_added: list[str] = field(default_factory=list)
    files_removed: list[str] = field(default_factory=list)
    files_common: int = 0
    dex_diffs: list[dict] = field(default_factory=list)
    native_libs_identical: bool = True
    native_libs_diffs: list[dict] = field(default_factory=list)
    arsc_orig_size: int = 0
    arsc_rebuilt_size: int = 0
    arsc_identical: bool = False
    manifest_identical: bool = False
    manifest_notes: str = ""


@dataclass
class NoOpResult:
    filename: str
    orig_sha256: str
    orig_size: int
    stages: dict[str, StageResult] = field(default_factory=dict)
    overall_status: str = "FAIL"
    rebuilt_sha256: str = ""
    rebuilt_size: int = 0
    structural_diff: StructuralDiff | None = None


def run_cmd(cmd: list[str], log_path: Path, timeout: int = 300) -> tuple[int, str, str, float]:
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


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compare_apks(orig_apk: Path, rebuilt_apk: Path) -> StructuralDiff:
    diff = StructuralDiff()
    with zipfile.ZipFile(orig_apk) as z_orig, zipfile.ZipFile(rebuilt_apk) as z_rebuilt:
        orig_names = set(z_orig.namelist())
        rebuilt_names = set(z_rebuilt.namelist())

        diff.orig_file_count = len(orig_names)
        diff.rebuilt_file_count = len(rebuilt_names)

        diff.files_added = sorted(list(rebuilt_names - orig_names))
        diff.files_removed = sorted(list(orig_names - rebuilt_names))
        common = sorted(list(orig_names & rebuilt_names))
        diff.files_common = len(common)

        # DEX comparison
        orig_dex = [n for n in orig_names if n.endswith(".dex")]
        for d in sorted(orig_dex):
            if d in rebuilt_names:
                orig_d = z_orig.read(d)
                reb_d = z_rebuilt.read(d)
                diff.dex_diffs.append({
                    "name": d,
                    "orig_size": len(orig_d),
                    "rebuilt_size": len(reb_d),
                    "identical": orig_d == reb_d,
                    "orig_sha256": compute_sha256(orig_d),
                    "rebuilt_sha256": compute_sha256(reb_d),
                })

        # Native libs comparison
        orig_so = [n for n in orig_names if n.startswith("lib/") and n.endswith(".so")]
        native_identical = True
        for so in sorted(orig_so):
            if so in rebuilt_names:
                orig_bytes = z_orig.read(so)
                reb_bytes = z_rebuilt.read(so)
                same = (orig_bytes == reb_bytes)
                if not same:
                    native_identical = False
                diff.native_libs_diffs.append({
                    "name": so,
                    "size": len(orig_bytes),
                    "identical": same,
                })
        diff.native_libs_identical = native_identical

        # resources.arsc comparison
        if "resources.arsc" in orig_names and "resources.arsc" in rebuilt_names:
            orig_arsc = z_orig.read("resources.arsc")
            reb_arsc = z_rebuilt.read("resources.arsc")
            diff.arsc_orig_size = len(orig_arsc)
            diff.arsc_rebuilt_size = len(reb_arsc)
            diff.arsc_identical = (orig_arsc == reb_arsc)

        # AndroidManifest.xml comparison
        if "AndroidManifest.xml" in orig_names and "AndroidManifest.xml" in rebuilt_names:
            orig_m = z_orig.read("AndroidManifest.xml")
            reb_m = z_rebuilt.read("AndroidManifest.xml")
            diff.manifest_identical = (orig_m == reb_m)
            # Compare AXML element counts
            try:
                from androguard.core.axml import AXMLPrinter
                orig_xml = AXMLPrinter(orig_m).get_xml().decode("utf-8", errors="replace")
                reb_xml = AXMLPrinter(reb_m).get_xml().decode("utf-8", errors="replace")
                diff.manifest_notes = (
                    f"AXML identical: {orig_m == reb_m}; "
                    f"Orig AXML size: {len(orig_m)}B, Rebuilt AXML size: {len(reb_m)}B; "
                    f"Text XML len orig: {len(orig_xml)}, reb: {len(reb_xml)}"
                )
            except Exception as e:
                diff.manifest_notes = f"AXML parse error: {e}"

    return diff


def process_noop_apk(apk_path: Path) -> NoOpResult:
    apk_name = apk_path.name
    stem = apk_path.stem
    print(f"\n=======================================================")
    print(f"  No-Op Round Trip: {apk_name} ({apk_path.stat().st_size:,} bytes)")
    print(f"=======================================================")

    orig_data = apk_path.read_bytes()
    orig_sha = compute_sha256(orig_data)
    work_dir = WORK_DIR / stem
    if work_dir.exists():
        shutil.rmtree(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    decoded_dir = work_dir / "decoded"
    unaligned_apk = work_dir / "unaligned.apk"
    aligned_apk = work_dir / "aligned.apk"
    signed_apk = work_dir / "signed.apk"

    res = NoOpResult(
        filename=apk_name,
        orig_sha256=orig_sha,
        orig_size=len(orig_data),
    )

    # 1. Decode
    print("  [1/5] apktool decode...")
    log_file = LOGS_DIR / f"noop_{stem}_decode.log"
    cmd = [APKTOOL, "d", "-f", "-o", str(decoded_dir), str(apk_path)]
    code, out, err, dur = run_cmd(cmd, log_file)
    res.stages["decode"] = StageResult(
        status="PASS" if code == 0 else "FAIL",
        duration_seconds=dur,
        command=" ".join(cmd),
        exit_code=code,
        stdout_snippet=out[-300:] if out else "",
        stderr_snippet=err[-300:] if err else "",
        log_file=str(log_file.relative_to(ROOT)),
    )
    if code != 0:
        print(f"        FAIL ({dur:.1f}s)")
        res.overall_status = "FAIL"
        return res
    print(f"        PASS ({dur:.1f}s)")

    # (NO MODIFICATION STEP)

    # 2. Build (unmodified)
    print("  [2/5] apktool build (no edit)...")
    log_file = LOGS_DIR / f"noop_{stem}_build.log"
    cmd = [APKTOOL, "b", "-o", str(unaligned_apk), str(decoded_dir)]
    code, out, err, dur = run_cmd(cmd, log_file)
    res.stages["build"] = StageResult(
        status="PASS" if code == 0 else "FAIL",
        duration_seconds=dur,
        command=" ".join(cmd),
        exit_code=code,
        stdout_snippet=out[-300:] if out else "",
        stderr_snippet=err[-300:] if err else "",
        log_file=str(log_file.relative_to(ROOT)),
    )
    if code != 0:
        print(f"        FAIL ({dur:.1f}s)")
        res.overall_status = "FAIL"
        return res
    print(f"        PASS ({dur:.1f}s)")

    # 3. Zipalign
    print("  [3/5] zipalign...")
    log_file = LOGS_DIR / f"noop_{stem}_zipalign.log"
    cmd = [ZIPALIGN, "-p", "-f", "-v", "4", str(unaligned_apk), str(aligned_apk)]
    code, out, err, dur = run_cmd(cmd, log_file)
    res.stages["zipalign"] = StageResult(
        status="PASS" if code == 0 else "FAIL",
        duration_seconds=dur,
        command=" ".join(cmd),
        exit_code=code,
        stdout_snippet=out[-300:] if out else "",
        stderr_snippet=err[-300:] if err else "",
        log_file=str(log_file.relative_to(ROOT)),
    )
    if code != 0:
        print(f"        FAIL ({dur:.1f}s)")
        res.overall_status = "FAIL"
        return res
    print(f"        PASS ({dur:.1f}s)")

    # 4. Apksigner
    print("  [4/5] apksigner sign...")
    log_file = LOGS_DIR / f"noop_{stem}_sign.log"
    cmd = [
        APKSIGNER, "sign",
        "--ks", str(KEYSTORE),
        "--ks-pass", f"pass:{KEYSTORE_PASS}",
        "--ks-key-alias", KEY_ALIAS,
        "--key-pass", f"pass:{KEYSTORE_PASS}",
        "--out", str(signed_apk),
        str(aligned_apk),
    ]
    code, out, err, dur = run_cmd(cmd, log_file)
    res.stages["sign"] = StageResult(
        status="PASS" if code == 0 else "FAIL",
        duration_seconds=dur,
        command=" ".join(cmd),
        exit_code=code,
        stdout_snippet=out[-300:] if out else "",
        stderr_snippet=err[-300:] if err else "",
        log_file=str(log_file.relative_to(ROOT)),
    )
    if code != 0:
        print(f"        FAIL ({dur:.1f}s)")
        res.overall_status = "FAIL"
        return res
    print(f"        PASS ({dur:.1f}s)")

    # 5. Verification
    print("  [5/5] verify...")
    log_file = LOGS_DIR / f"noop_{stem}_verify.log"
    align_chk = [ZIPALIGN, "-c", "-v", "4", str(signed_apk)]
    c1, o1, e1, d1 = run_cmd(align_chk, log_file.parent / f"noop_{stem}_align_chk.log")
    sig_chk = [APKSIGNER, "verify", "--verbose", str(signed_apk)]
    c2, o2, e2, d2 = run_cmd(sig_chk, log_file.parent / f"noop_{stem}_sig_chk.log")

    passed = (c1 == 0 and "Verification succesful" in o1 and c2 == 0 and "Verifies" in o2)
    res.stages["verify"] = StageResult(
        status="PASS" if passed else "FAIL",
        duration_seconds=d1 + d2,
        command="zipalign -c & apksigner verify",
        exit_code=0 if passed else 1,
        stdout_snippet=f"align={c1==0}, sig={c2==0}",
        log_file=str(log_file.relative_to(ROOT)),
    )
    if not passed:
        print(f"        FAIL ({d1+d2:.1f}s)")
        res.overall_status = "FAIL"
        return res
    print(f"        PASS ({d1+d2:.1f}s)")

    res.overall_status = "PASS"
    rebuilt_data = signed_apk.read_bytes()
    res.rebuilt_sha256 = compute_sha256(rebuilt_data)
    res.rebuilt_size = len(rebuilt_data)

    # 6. Structural diff
    print("  Comparing structure against original...")
    res.structural_diff = compare_apks(apk_path, signed_apk)
    print(f"        Files: orig {res.structural_diff.orig_file_count}, reb {res.structural_diff.rebuilt_file_count}")
    print(f"        Added: {len(res.structural_diff.files_added)}, Removed: {len(res.structural_diff.files_removed)}")
    print(f"        Native libs identical: {res.structural_diff.native_libs_identical}")
    print(f"        ARSC identical: {res.structural_diff.arsc_identical} (orig {res.structural_diff.arsc_orig_size}B -> reb {res.structural_diff.arsc_rebuilt_size}B)")

    return res


def main():
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    WORK_DIR.mkdir(parents=True, exist_ok=True)

    apks = sorted(list(SAMPLES_DIR.glob("*.apk")))
    print(f"Running True No-Op Round Trip on {len(apks)} APKs...")

    results = []
    t_start = time.time()
    for apk in apks:
        res = process_noop_apk(apk)
        results.append(res)

    total_time = time.time() - t_start

    # Dump JSON results
    out_json = ROOT / "build-tests" / "noop_roundtrip_results.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in results], f, indent=2)

    print("\n" + "=" * 80)
    print("  PHASE C.1b TRUE NO-OP ROUND TRIP SUMMARY")
    print("=" * 80)
    print(f"{'APK':<42} | {'Dec':<4} | {'Bld':<4} | {'Aln':<4} | {'Sgn':<4} | {'Ver':<4} | {'Status'}")
    print("-" * 80)
    for r in results:
        dec = r.stages.get("decode", StageResult()).status
        bld = r.stages.get("build", StageResult()).status
        aln = r.stages.get("zipalign", StageResult()).status
        sgn = r.stages.get("sign", StageResult()).status
        ver = r.stages.get("verify", StageResult()).status
        print(f"{r.filename:<42} | {dec:<4} | {bld:<4} | {aln:<4} | {sgn:<4} | {ver:<4} | {r.overall_status}")
    print("-" * 80)
    passes = sum(1 for r in results if r.overall_status == "PASS")
    print(f"Total: {len(results)} | PASS: {passes} | FAIL: {len(results)-passes} | Duration: {total_time:.1f}s")
    print("=" * 80)


if __name__ == "__main__":
    main()
