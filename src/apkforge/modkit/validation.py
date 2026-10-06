"""Validation of untrusted ModKit output.

A zero exit code proves nothing. Before anything is published the framework
checks, independently of what the adapter claims:

- the output directory is still a real directory inside the workspace,
- nothing new appeared in the workspace root or in input/ (writes outside output/),
- every file in output/ has a safe name, is a regular file (no symlinks, devices,
  FIFOs) and was declared by the adapter (no unexpected extra artifacts),
- every declared name is a safe relative path inside output/,
- exactly one primary output exists (missing / ambiguous otherwise),
- the primary output is a well-formed APK archive within the extraction limits
  (no ``..``/absolute entry names, ``AndroidManifest.xml`` present, CRCs valid),
- an output identical to the input is accepted only as a declared/allowed NO_OP.

Writes outside the workspace entirely cannot be observed without an OS sandbox;
that is a documented limitation (the ModKit runs with the user's privileges).
"""

from __future__ import annotations

import os
import re
import stat
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from apkforge.core.config import ExtractionLimits
from apkforge.modkit.models import (
    FailureCategory,
    ModKitResultStatus,
    OperationSpec,
    OutputDeclaration,
    ValidationCheck,
)
from apkforge.modkit.workspace import sha256_file

if TYPE_CHECKING:
    from apkforge.modkit.workspace import ModKitWorkspace

__all__ = [
    "OutputValidation",
    "WorkspaceSnapshot",
    "is_safe_name",
    "validate_apk_archive",
    "validate_output",
]

_COMPONENT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._+-]{0,199}")
_MAX_DEPTH = 4


def is_safe_name(name: str) -> bool:
    """A relative POSIX path of plain components (no ``..``, no hidden/odd names)."""
    if not name or len(name) > 1024 or "\\" in name or name.startswith("/"):
        return False
    parts = PurePosixPath(name).parts
    if not parts or len(parts) > _MAX_DEPTH:
        return False
    return all(_COMPONENT.fullmatch(p) and p not in (".", "..") for p in parts)


def _escapes(name: str) -> bool:
    return name.startswith("/") or ".." in PurePosixPath(name.replace("\\", "/")).parts


@dataclass(frozen=True)
class WorkspaceSnapshot:
    """Entries of the workspace root and input/ before the ModKit ran."""

    root: frozenset[str]
    input: frozenset[str]

    @classmethod
    def take(cls, ws: ModKitWorkspace) -> WorkspaceSnapshot:
        return cls(
            root=frozenset(os.listdir(ws.root)),
            input=frozenset(os.listdir(ws.input_dir)),
        )

    def new_entries(self, ws: ModKitWorkspace) -> list[str]:
        try:
            root = set(os.listdir(ws.root)) - self.root
            inp = {f"input/{n}" for n in set(os.listdir(ws.input_dir)) - self.input}
        except OSError as exc:
            return [f"<unreadable: {exc}>"]
        return sorted(root | inp)


@dataclass
class OutputValidation:
    status: ModKitResultStatus
    failure: FailureCategory | None = None
    reason: str = ""
    checks: list[ValidationCheck] = field(default_factory=list)
    candidate: Path | None = None

    @property
    def ok(self) -> bool:
        return self.status in (ModKitResultStatus.SUCCESS, ModKitResultStatus.NO_OP)


def _scan(output_dir: Path) -> tuple[list[str], list[tuple[str, str]]]:
    """(regular file names relative to output/, [(name, problem)])."""
    files: list[str] = []
    bad: list[tuple[str, str]] = []

    def walk(d: Path, rel: str, depth: int) -> None:
        try:
            entries = sorted(os.scandir(d), key=lambda e: e.name)
        except OSError as exc:
            bad.append((rel or ".", f"unreadable: {exc}"))
            return
        for e in entries:
            name = f"{rel}/{e.name}" if rel else e.name
            st = e.stat(follow_symlinks=False)
            if stat.S_ISLNK(st.st_mode):
                bad.append((name, "symlink"))
            elif stat.S_ISDIR(st.st_mode):
                if depth >= _MAX_DEPTH:
                    bad.append((name, "directory nesting too deep"))
                else:
                    walk(Path(e.path), name, depth + 1)
            elif stat.S_ISREG(st.st_mode):
                files.append(name)
            else:
                bad.append((name, "not a regular file"))

    walk(output_dir, "", 1)
    return files, bad


def validate_apk_archive(path: Path, limits: ExtractionLimits | None = None) -> list[str]:
    """Problems that make *path* not a well-formed APK archive (empty: valid)."""
    limits = limits or ExtractionLimits()
    problems: list[str] = []
    try:
        size = path.stat().st_size
    except OSError as exc:
        return [f"cannot stat: {exc}"]
    if size == 0:
        return ["empty file"]
    if not zipfile.is_zipfile(path):
        return ["not a ZIP archive"]
    try:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            if len(infos) > limits.max_file_count:
                problems.append(f"{len(infos)} entries exceed limit {limits.max_file_count}")
            total = 0
            names: set[str] = set()
            for info in infos:
                n = info.filename
                if n.startswith("/") or "\\" in n or ".." in PurePosixPath(n).parts:
                    problems.append(f"unsafe entry name {n!r}")
                if n in names:
                    problems.append(f"duplicate entry {n!r}")
                names.add(n)
                if info.file_size > limits.max_single_file_bytes:
                    problems.append(f"entry {n!r} exceeds the single-file limit")
                total += info.file_size
            if total > limits.max_total_size_bytes:
                problems.append("uncompressed size exceeds the total-size limit")
            if "AndroidManifest.xml" not in names:
                problems.append("no AndroidManifest.xml entry")
            if not problems:
                bad = zf.testzip()
                if bad is not None:
                    problems.append(f"corrupt entry {bad!r}")
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, ValueError, EOFError) as exc:
        problems.append(f"malformed archive: {exc}")
    return problems


def validate_output(
    ws: ModKitWorkspace,
    declaration: OutputDeclaration,
    *,
    operation: OperationSpec,
    input_sha256: str,
    expect_change: bool,
    snapshot: WorkspaceSnapshot,
    limits: ExtractionLimits | None = None,
) -> OutputValidation:
    """Validate what the ModKit left in ``output/`` against its *declaration*."""
    R, F = ModKitResultStatus, FailureCategory
    v = OutputValidation(status=R.UNKNOWN)
    checks = v.checks

    def fail(status: ModKitResultStatus, failure: FailureCategory, reason: str) -> OutputValidation:
        v.status, v.failure, v.reason = status, failure, reason
        checks.append(ValidationCheck(id=failure.value.lower(), passed=False, detail=reason))
        return v

    out = ws.root / "output"
    if out.is_symlink() or not out.is_dir() or out.resolve() != ws.output_dir:
        return fail(R.OUTPUT_INVALID, F.OUTPUT_OUTSIDE_WORKSPACE, "output/ was replaced")
    checks.append(ValidationCheck(id="output_dir_intact", passed=True))

    escaped = snapshot.new_entries(ws)
    if escaped:
        return fail(
            R.OUTPUT_INVALID,
            F.OUTPUT_OUTSIDE_WORKSPACE,
            f"files written outside output/: {', '.join(escaped[:5])}",
        )
    checks.append(ValidationCheck(id="no_writes_outside_output", passed=True))

    declared = [*declaration.primary, *declaration.auxiliary]
    for name in declared:
        if _escapes(name):
            return fail(
                R.OUTPUT_INVALID, F.OUTPUT_OUTSIDE_WORKSPACE, f"declared {name!r} escapes output/"
            )
        if not is_safe_name(name):
            return fail(R.OUTPUT_INVALID, F.UNSAFE_FILENAME, f"unsafe declared name {name!r}")
    checks.append(ValidationCheck(id="declared_names_safe", passed=True))

    files, bad = _scan(ws.output_dir)
    for name, problem in bad:
        if problem == "symlink":
            target = ws.output_dir / name
            try:
                inside = target.resolve().is_relative_to(ws.output_dir)
            except OSError:
                inside = False
            return fail(
                R.OUTPUT_INVALID,
                F.OUTPUT_NOT_REGULAR_FILE if inside else F.OUTPUT_OUTSIDE_WORKSPACE,
                f"{name!r} is a symlink" + ("" if inside else " pointing outside output/"),
            )
        return fail(R.OUTPUT_INVALID, F.OUTPUT_NOT_REGULAR_FILE, f"{name!r}: {problem}")
    unsafe = [n for n in files if not is_safe_name(n)]
    if unsafe:
        return fail(R.OUTPUT_INVALID, F.UNSAFE_FILENAME, f"unsafe output file name {unsafe[0]!r}")
    checks.append(ValidationCheck(id="output_entries_regular", passed=True))

    if len(declaration.primary) > 1:
        return fail(
            R.OUTPUT_INVALID,
            F.OUTPUT_AMBIGUOUS,
            f"{len(declaration.primary)} primary outputs declared: "
            + ", ".join(declaration.primary[:5]),
        )
    allow_noop = declaration.declared_no_op and operation.may_be_noop
    if declaration.declared_no_op and not operation.may_be_noop:
        return fail(
            R.OUTPUT_INVALID,
            F.OUTPUT_UNCHANGED,
            f"no-op declared but operation {operation.id!r} does not allow a no-op",
        )

    extra = sorted(set(files) - set(declared))
    if extra:
        return fail(
            R.OUTPUT_INVALID,
            F.UNEXPECTED_ARTIFACT,
            f"undeclared files in output/: {', '.join(extra[:5])}",
        )
    checks.append(ValidationCheck(id="no_unexpected_artifacts", passed=True))

    if not declaration.primary:
        if allow_noop and not files:
            v.status, v.reason = R.NO_OP, "the ModKit declared a no-op and produced no output"
            checks.append(ValidationCheck(id="declared_no_op", passed=True))
            return v
        if len(files) > 1:
            return fail(R.OUTPUT_INVALID, F.OUTPUT_AMBIGUOUS, "no primary output declared")
        return fail(R.OUTPUT_MISSING, F.OUTPUT_MISSING, "the ModKit declared no output")

    name = declaration.primary[0]
    candidate = ws.output_dir / name
    if name not in files:
        if candidate.is_dir():
            return fail(R.OUTPUT_INVALID, F.OUTPUT_NOT_REGULAR_FILE, f"{name!r} is a directory")
        return fail(R.OUTPUT_MISSING, F.OUTPUT_MISSING, f"declared output {name!r} does not exist")
    if not candidate.resolve().is_relative_to(ws.output_dir):
        return fail(R.OUTPUT_INVALID, F.OUTPUT_OUTSIDE_WORKSPACE, f"{name!r} escapes output/")
    checks.append(ValidationCheck(id="primary_output_present", passed=True, detail=name))

    problems = validate_apk_archive(candidate, limits)
    if problems:
        return fail(R.OUTPUT_INVALID, F.OUTPUT_MALFORMED, "; ".join(problems[:5]))
    checks.append(ValidationCheck(id="apk_archive_valid", passed=True))

    out_sha = sha256_file(candidate)
    v.candidate = candidate
    if out_sha == input_sha256:
        if allow_noop or not expect_change:
            v.status, v.reason = R.NO_OP, "the output is byte-identical to the input"
            checks.append(ValidationCheck(id="unchanged_output_accepted", passed=True))
            return v
        v.candidate = None
        return fail(
            R.OUTPUT_INVALID,
            F.OUTPUT_UNCHANGED,
            "output is byte-identical to the input but a transformation was expected",
        )
    if declaration.declared_no_op:
        v.candidate = None
        return fail(
            R.OUTPUT_INVALID, F.OUTPUT_UNCHANGED, "a no-op was declared but the output differs"
        )
    checks.append(ValidationCheck(id="output_changed", passed=True))
    v.status = R.SUCCESS
    return v
