"""Reference ModKit command-line tool (APKForge test fixture - never for production).

A deliberately tiny, deterministic, *external* program that behaves like a
third-party ModKit CLI so the H.7 framework can be exercised end to end without
any real third-party tool. It imports nothing from APKForge and is run as a
separate process::

    tool.py --version
    tool.py run --input IN.apk --output-dir OUT --result RESULT.json
                --scenario NAME [--marker TEXT] [--token VALUE]

``success`` rewrites the APK deterministically (entries copied in order with a
fixed timestamp, plus ``assets/test-modkit/marker.txt``). Every other scenario
simulates a failure mode the framework must catch. ``RESULT.json`` is the tool's
own claim about its outputs (``{"outputs": [...], "no_op": bool}``) - which the
framework treats as untrusted.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
import zipfile
from pathlib import Path

VERSION = "1.0.0"
MARKER_ENTRY = "assets/test-modkit/marker.txt"
_EPOCH = (1980, 1, 1, 0, 0, 0)

SCENARIOS = (
    "success",
    "noop",
    "noop-undeclared",
    "noop-empty",
    "missing-output",
    "no-declaration",
    "invalid-apk",
    "truncated-apk",
    "nonzero-exit",
    "timeout",
    "crash",
    "multiple-outputs",
    "extra-artifact",
    "outside-workspace",
    "outside-undeclared",
    "symlink-escape",
    "malicious-filename",
    "traversal-entry",
    "directory-output",
    "mutate-input",
    "noisy",
    "echo-env",
    "echo-args",
    "replace-output-dir",
)


def _transform(
    src: Path, dest: Path, marker: str, *, extra: dict[str, bytes] | None = None
) -> None:
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dest, "w") as zout:
        for info in zin.infolist():
            if info.filename == MARKER_ENTRY:
                continue
            data = zin.read(info)
            out = zipfile.ZipInfo(info.filename, date_time=_EPOCH)
            out.compress_type = info.compress_type
            out.external_attr = 0o644 << 16
            zout.writestr(out, data)
        for name, data in {MARKER_ENTRY: marker.encode(), **(extra or {})}.items():
            info = zipfile.ZipInfo(name, date_time=_EPOCH)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zout.writestr(info, data)


def _declare(result: Path, outputs: list[str], *, no_op: bool = False) -> None:
    result.write_text(json.dumps({"outputs": outputs, "no_op": no_op}), encoding="utf-8")


def _run(args: argparse.Namespace) -> int:
    src, out, result = Path(args.input), Path(args.output_dir), Path(args.result)
    s = args.scenario
    primary = out / "patched.apk"
    if s == "success":
        _transform(src, primary, args.marker)
        _declare(result, ["patched.apk"])
    elif s in ("noop", "noop-undeclared"):
        primary.write_bytes(src.read_bytes())
        _declare(result, ["patched.apk"], no_op=s == "noop")
    elif s == "noop-empty":
        _declare(result, [], no_op=True)
    elif s == "missing-output":
        _declare(result, ["patched.apk"])
    elif s == "no-declaration":
        _transform(src, primary, args.marker)
        _declare(result, [])
    elif s == "invalid-apk":
        primary.write_bytes(b"this is not an APK\n")
        _declare(result, ["patched.apk"])
    elif s == "truncated-apk":
        _transform(src, out / "full.tmp", args.marker)
        data = (out / "full.tmp").read_bytes()
        (out / "full.tmp").unlink()
        primary.write_bytes(data[: len(data) // 2])
        _declare(result, ["patched.apk"])
    elif s == "nonzero-exit":
        print("test-modkit: simulated failure", file=sys.stderr)
        return 3
    elif s == "timeout":
        time.sleep(3600)
    elif s == "crash":
        os.kill(os.getpid(), signal.SIGSEGV)
    elif s == "multiple-outputs":
        _transform(src, primary, args.marker)
        _transform(src, out / "patched-2.apk", args.marker + "-2")
        _declare(result, ["patched.apk", "patched-2.apk"])
    elif s == "extra-artifact":
        _transform(src, primary, args.marker)
        (out / "debug.txt").write_text("unexpected\n")
        _declare(result, ["patched.apk"])
    elif s == "outside-workspace":
        _transform(src, out.parent / "escaped.apk", args.marker)
        _declare(result, ["../escaped.apk"])
    elif s == "outside-undeclared":
        _transform(src, primary, args.marker)
        _transform(src, out.parent / "escaped.apk", args.marker)
        _declare(result, ["patched.apk"])
    elif s == "symlink-escape":
        primary.symlink_to(src.resolve())
        _declare(result, ["patched.apk"])
    elif s == "malicious-filename":
        name = "evil;$(touch pwned)\n.apk"
        _transform(src, out / name, args.marker)
        _declare(result, [name])
    elif s == "traversal-entry":
        _transform(src, primary, args.marker, extra={"../../evil.txt": b"zip-slip"})
        _declare(result, ["patched.apk"])
    elif s == "directory-output":
        primary.mkdir()
        _declare(result, ["patched.apk"])
    elif s == "mutate-input":
        os.chmod(src, 0o644)
        with src.open("ab") as f:
            f.write(b"tampered")
        _transform(out.parent / "input" / "input.apk", primary, args.marker)
        _declare(result, ["patched.apk"])
    elif s == "noisy":
        for i in range(2000):
            print(f"\x1b[31mprogress {i}\x1b[0m \x1b]0;title\x07")
            print(f"\x1b[1mwarning {i}\x1b[0m", file=sys.stderr)
        _transform(src, primary, args.marker)
        _declare(result, ["patched.apk"])
    elif s == "echo-env":
        print(json.dumps(dict(os.environ), sort_keys=True))
        _transform(src, primary, args.marker)
        _declare(result, ["patched.apk"])
    elif s == "echo-args":
        print(json.dumps(sys.argv))
        print(json.dumps(sys.argv), file=sys.stderr)
        _transform(src, primary, args.marker)
        _declare(result, ["patched.apk"])
    elif s == "replace-output-dir":
        _transform(src, Path(os.environ["TMPDIR"]) / "patched.apk", args.marker)
        out.rmdir()
        out.symlink_to(Path(os.environ["TMPDIR"]))
        _declare(result, ["patched.apk"])
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="test-modkit")
    parser.add_argument("--version", action="store_true")
    sub = parser.add_subparsers(dest="command")
    run = sub.add_parser("run")
    run.add_argument("--input", required=True)
    run.add_argument("--output-dir", required=True)
    run.add_argument("--result", required=True)
    run.add_argument("--scenario", choices=SCENARIOS, default="success")
    run.add_argument("--marker", default="test-modkit")
    run.add_argument("--token", default="")
    args = parser.parse_args(argv)
    if args.version:
        print(f"test-modkit {VERSION}")
        return 0
    if args.command != "run":
        parser.print_usage(sys.stderr)
        return 2
    return _run(args)


if __name__ == "__main__":
    sys.exit(main())
