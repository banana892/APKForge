"""Phase E experiment: per-entry rebuild determinism and manifest XML differences."""
import hashlib, json, sys, zipfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[3]  # repository root
sys.path.insert(0, str(ROOT / "src"))
from apkforge.builders import BuildService, ToolchainConfig, ensure_dev_keystore
from apkforge.builders.models import BuildOptions

def entries(p):
    with zipfile.ZipFile(p) as z:
        return {i.filename: (hashlib.sha256(z.read(i)).hexdigest(), i.file_size, i.compress_type, i.date_time)
                for i in z.infolist() if not i.is_dir()}

out = ROOT / "work/phase-e/exp"  # work/ is git-ignored
tc = ToolchainConfig.discover()
svc = BuildService(tc, ensure_dev_keystore(tc.keytool), work_dir=out / "builds")
names = sys.argv[1:]
report = {}
for name in names:
    apk = ROOT / "tests/corpus" / name
    builds = []
    for i in (1, 2):
        o = out / f"{apk.stem}.noop{i}.apk"
        r = svc.build_pipeline(apk, BuildOptions(output_apk=o, overwrite_output=True, work_dir=out / "builds"))
        assert r.success, r.failure_cause
        builds.append(entries(o))
    a, b = builds
    orig = entries(apk)
    diff_hash = sorted(k for k in a if k in b and a[k][0] != b[k][0])
    diff_meta = sorted(k for k in a if k in b and a[k][0] == b[k][0] and a[k][2:] != b[k][2:])
    report[name] = {
        "entries_build1": len(a), "entries_build2": len(b),
        "same_entry_set": set(a) == set(b),
        "content_differs_between_rebuilds": diff_hash,
        "zipinfo_meta_differs_between_rebuilds": diff_meta[:20],
        "orig_entries": len(orig),
        "same_path_content_changed_vs_orig": sum(1 for k in orig if k in a and orig[k][0] != a[k][0]),
    }
    print(name, json.dumps(report[name])[:600], flush=True)
(out / "determinism.json").write_text(json.dumps(report, indent=2))
