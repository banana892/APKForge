"""Real-APK corpus validation and regression baseline for BuildService (Phase C.4).

A corpus is a set of APKs described by a machine-readable manifest
(``tests/corpus/manifest.json``). Each entry has a stable id, the APK's SHA-256
and size, metadata established by APKForge inspection, and a documented
*expected outcome* (the baseline). A corpus run pushes every entry through the
real :meth:`BuildService.build_pipeline` and compares the observed outcome with
the baseline::

    manifest -> resolve (by hash) -> BuildService.build_pipeline -> CorpusResult
             -> compare with expectation (and optionally a previous run) -> report

Design rules:

- No tool is invoked here. Every build goes through ``BuildService``; per-stage
  data is the service's own :class:`StageResult` (already secret-masked).
- APK identity is the SHA-256, not the filename. A renamed APK is still found;
  a replaced APK (same name, different hash) is a ``CORPUS_ERROR`` and is not
  built, so a replacement can never silently become the new baseline.
- Each entry and attempt gets its own work directory; BuildService additionally
  creates a unique workspace per build, so one entry cannot affect another.
- A failure is only "known" when the manifest documents it with a reason.
  Anything else that fails is a regression or a new failure.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import platform
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from apkforge.builders.models import (
    DEFAULT_STAGE_TIMEOUT_SECONDS,
    BuildFailureCategory,
    BuildOptions,
    BuildResult,
    BuildStage,
    StageResult,
    StageStatus,
)
from apkforge.builders.noop_integrity import compare_noop_rebuild

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from apkforge.builders.runner import CommandRunner
    from apkforge.builders.service import BuildService

__all__ = [
    "SCHEMA_VERSION",
    "Comparison",
    "CorpusEntry",
    "CorpusManifest",
    "CorpusManifestError",
    "CorpusResult",
    "CorpusRun",
    "EntryIdentity",
    "Expectation",
    "FinalStatus",
    "Outcome",
    "ResolvedEntry",
    "compare_outcome",
    "compare_with_previous",
    "describe_apk",
    "new_run_id",
    "render_report",
    "resolve_entries",
    "run_corpus",
    "run_entry",
    "sha256_file",
]

SCHEMA_VERSION = 1
_SHA256 = re.compile(r"[0-9a-f]{64}")
# Ids are used as directory names, so they must be a single safe path component.
_ENTRY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,127}")
_STAGES = tuple(BuildStage)
_TAIL = 2000

# Tool versions that define a toolchain for baseline purposes (ToolchainCheckResult keys).
TOOLCHAIN_KEYS = ("java", "apktool", "zipalign", "apksigner", "build_tools", "android_platform")


class FinalStatus(StrEnum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    NOT_RUN = "NOT_RUN"  # the entry could not be built (corpus identity problem)


class EntryIdentity(StrEnum):
    OK = "OK"  # file at the manifest filename has the manifest hash
    RENAMED = "RENAMED"  # manifest filename absent, but a corpus file has the manifest hash
    HASH_MISMATCH = "HASH_MISMATCH"  # file at the manifest filename has a different hash
    MISSING = "MISSING"  # no corpus file has the manifest hash

    @property
    def buildable(self) -> bool:
        return self in (EntryIdentity.OK, EntryIdentity.RENAMED)


class Comparison(StrEnum):
    """Observed outcome versus a baseline outcome."""

    UNCHANGED_SUCCESS = "UNCHANGED_SUCCESS"
    UNCHANGED_KNOWN_FAILURE = "UNCHANGED_KNOWN_FAILURE"
    IMPROVEMENT = "IMPROVEMENT"  # baseline failure -> success
    REGRESSION = "REGRESSION"  # baseline success -> failure
    NEW_FAILURE = "NEW_FAILURE"  # failure without baseline, or a different failure mode
    NEW_SUCCESS = "NEW_SUCCESS"  # success without baseline
    CORPUS_ERROR = "CORPUS_ERROR"  # APK missing or replaced; not built

    @property
    def unexpected(self) -> bool:
        return self in (Comparison.REGRESSION, Comparison.NEW_FAILURE, Comparison.CORPUS_ERROR)


class CorpusManifestError(ValueError):
    """The manifest is malformed. ``errors`` lists every problem found."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__("Invalid corpus manifest:\n  " + "\n  ".join(errors))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def new_run_id() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")


def _utc_now() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat()


# ---------------------------------------------------------------------------
# Outcomes and expectations
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Outcome:
    """The comparable result of one pipeline run: status, failing stage, category."""

    final_status: FinalStatus
    failure_stage: BuildStage | None = None
    failure_category: BuildFailureCategory = BuildFailureCategory.SUCCESS

    @classmethod
    def from_build_result(cls, res: BuildResult) -> Outcome:
        if res.success:
            return cls(FinalStatus.SUCCESS)
        return cls(FinalStatus.FAILURE, res.failure_stage, res.failure_category)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Outcome:
        stage = d.get("failure_stage")
        return cls(
            FinalStatus(d["final_status"]),
            BuildStage(stage) if stage else None,
            BuildFailureCategory(d.get("failure_category") or "SUCCESS"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "final_status": str(self.final_status),
            "failure_stage": str(self.failure_stage) if self.failure_stage else None,
            "failure_category": str(self.failure_category),
        }

    def __str__(self) -> str:
        if self.final_status != FinalStatus.FAILURE:
            return str(self.final_status)
        return f"{self.failure_category} at {self.failure_stage or '?'}"


@dataclass(frozen=True)
class Expectation:
    """A documented baseline outcome. Failures require a reason."""

    outcome: Outcome
    reason: str = ""
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {**self.outcome.to_dict(), "reason": self.reason, "evidence": self.evidence}


def compare_outcome(baseline: Outcome | None, actual: Outcome) -> Comparison:
    """Classify *actual* against *baseline* (``None`` = no baseline exists)."""
    if actual.final_status == FinalStatus.NOT_RUN:
        return Comparison.CORPUS_ERROR
    ok = actual.final_status == FinalStatus.SUCCESS
    if baseline is None or baseline.final_status == FinalStatus.NOT_RUN:
        return Comparison.NEW_SUCCESS if ok else Comparison.NEW_FAILURE
    if baseline.final_status == FinalStatus.SUCCESS:
        return Comparison.UNCHANGED_SUCCESS if ok else Comparison.REGRESSION
    if ok:
        return Comparison.IMPROVEMENT
    if (baseline.failure_stage, baseline.failure_category) == (
        actual.failure_stage,
        actual.failure_category,
    ):
        return Comparison.UNCHANGED_KNOWN_FAILURE
    return Comparison.NEW_FAILURE  # still failing, but not in the documented way


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


@dataclass
class CorpusEntry:
    id: str
    filename: str
    sha256: str
    size_bytes: int
    expected: Expectation
    package_name: str | None = None
    version_name: str | None = None
    version_code: int | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    characteristics: dict[str, Any] = field(default_factory=dict)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "filename": self.filename,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "package_name": self.package_name,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
            "characteristics": self.characteristics,
            "expected": self.expected.to_dict(),
            "notes": self.notes,
        }


def _parse_expectation(raw: object, where: str, errors: list[str]) -> Expectation | None:
    if not isinstance(raw, dict):
        errors.append(f"{where}: 'expected' must be an object")
        return None
    try:
        outcome = Outcome.from_dict(raw)
    except (KeyError, ValueError) as exc:
        errors.append(f"{where}: invalid expected outcome ({exc})")
        return None
    reason = str(raw.get("reason") or "").strip()
    if outcome.final_status == FinalStatus.NOT_RUN:
        errors.append(f"{where}: expected final_status must be SUCCESS or FAILURE")
        return None
    if outcome.final_status == FinalStatus.FAILURE:
        if (
            outcome.failure_stage is None
            or outcome.failure_category == BuildFailureCategory.SUCCESS
        ):
            errors.append(f"{where}: an expected FAILURE needs failure_stage and failure_category")
            return None
        if not reason:
            errors.append(f"{where}: an expected FAILURE must document its reason")
            return None
    elif (
        outcome.failure_stage is not None
        or outcome.failure_category != BuildFailureCategory.SUCCESS
    ):
        errors.append(f"{where}: an expected SUCCESS cannot name a failure stage/category")
        return None
    return Expectation(outcome, reason, str(raw.get("evidence") or ""))


@dataclass
class CorpusManifest:
    entries: list[CorpusEntry]
    description: str = ""
    baseline_toolchain: dict[str, str | None] = field(default_factory=dict)
    path: Path | None = None
    sha256: str | None = None  # of the manifest file itself

    @classmethod
    def load(cls, path: Path) -> CorpusManifest:
        raw_bytes = path.read_bytes()
        try:
            data = json.loads(raw_bytes)
        except json.JSONDecodeError as exc:
            raise CorpusManifestError([f"{path}: not valid JSON ({exc})"]) from exc
        manifest = cls.from_dict(data)
        manifest.path = path
        manifest.sha256 = hashlib.sha256(raw_bytes).hexdigest()
        return manifest

    @classmethod
    def from_dict(cls, data: object) -> CorpusManifest:
        errors: list[str] = []
        if not isinstance(data, dict):
            raise CorpusManifestError(["manifest must be a JSON object"])
        if data.get("schema_version") != SCHEMA_VERSION:
            errors.append(f"schema_version must be {SCHEMA_VERSION}")
        raw_entries = data.get("entries")
        if not isinstance(raw_entries, list) or not raw_entries:
            raise CorpusManifestError([*errors, "'entries' must be a non-empty list"])

        entries: list[CorpusEntry] = []
        seen: dict[str, dict[str, str]] = {"id": {}, "sha256": {}, "filename": {}}
        for i, raw in enumerate(raw_entries):
            where = f"entries[{i}]"
            if not isinstance(raw, dict):
                errors.append(f"{where}: must be an object")
                continue
            entry_id = raw.get("id")
            if (
                not isinstance(entry_id, str)
                or not _ENTRY_ID.fullmatch(entry_id)
                or ".." in entry_id
            ):
                errors.append(f"{where}: invalid id {entry_id!r}")
                continue
            where = f"entries[{i}] ({entry_id})"
            filename = raw.get("filename")
            if (
                not isinstance(filename, str)
                or Path(filename).name != filename
                or filename in ("", ".", "..")
                or not filename.endswith(".apk")
            ):
                errors.append(f"{where}: filename must be a plain *.apk name, got {filename!r}")
                continue
            digest = raw.get("sha256")
            if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
                errors.append(f"{where}: sha256 must be 64 lowercase hex characters")
                continue
            size = raw.get("size_bytes")
            if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                errors.append(f"{where}: size_bytes must be a non-negative integer")
                continue
            dup = False
            for key, value in (("id", entry_id), ("sha256", digest), ("filename", filename)):
                if value in seen[key]:
                    errors.append(f"{where}: duplicate {key} (also used by {seen[key][value]})")
                    dup = True
                seen[key][value] = entry_id
            expected = _parse_expectation(raw.get("expected"), where, errors)
            if dup or expected is None:
                continue
            entries.append(
                CorpusEntry(
                    id=entry_id,
                    filename=filename,
                    sha256=digest,
                    size_bytes=size,
                    expected=expected,
                    package_name=raw.get("package_name"),
                    version_name=raw.get("version_name"),
                    version_code=raw.get("version_code"),
                    min_sdk=raw.get("min_sdk"),
                    target_sdk=raw.get("target_sdk"),
                    characteristics=dict(raw.get("characteristics") or {}),
                    notes=str(raw.get("notes") or ""),
                )
            )
        if errors:
            raise CorpusManifestError(errors)
        return cls(
            entries=entries,
            description=str(data.get("description") or ""),
            baseline_toolchain=dict(data.get("baseline_toolchain") or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "description": self.description,
            "baseline_toolchain": self.baseline_toolchain,
            "entries": [e.to_dict() for e in self.entries],
        }


@dataclass
class ResolvedEntry:
    """A manifest entry matched against the files actually present."""

    entry: CorpusEntry
    identity: EntryIdentity
    path: Path | None  # the file to build (None unless buildable)
    actual_sha256: str | None = None  # hash of the file at the manifest filename, if any

    @property
    def problem(self) -> str | None:
        e = self.entry
        if self.identity == EntryIdentity.HASH_MISMATCH:
            return (
                f"{e.filename} has SHA-256 {self.actual_sha256}, manifest expects {e.sha256}: "
                "the APK was replaced. Restore it or update the manifest deliberately."
            )
        if self.identity == EntryIdentity.MISSING:
            return f"No corpus APK has SHA-256 {e.sha256} (expected as {e.filename})."
        return None


def resolve_entries(
    manifest: CorpusManifest, corpus_dir: Path
) -> tuple[list[ResolvedEntry], list[str]]:
    """Match manifest entries to files by hash. Returns (resolved, unlisted APK names)."""
    corpus_dir = corpus_dir.resolve()
    candidates = sorted(p for p in corpus_dir.glob("*.apk") if p.is_file() and not p.is_symlink())
    hash_cache: dict[Path, str] = {}

    def _hash(p: Path) -> str:
        if p not in hash_cache:
            hash_cache[p] = sha256_file(p)
        return hash_cache[p]

    resolved: list[ResolvedEntry] = []
    claimed: set[Path] = set()
    for entry in manifest.entries:
        named = corpus_dir / entry.filename
        if named.is_file() and not named.is_symlink():
            digest = _hash(named)
            claimed.add(named)
            if digest == entry.sha256:
                resolved.append(ResolvedEntry(entry, EntryIdentity.OK, named, digest))
            else:
                resolved.append(ResolvedEntry(entry, EntryIdentity.HASH_MISMATCH, None, digest))
            continue
        # Renamed? Only hash files of the recorded size.
        match = next(
            (
                p
                for p in candidates
                if p.stat().st_size == entry.size_bytes and _hash(p) == entry.sha256
            ),
            None,
        )
        if match is not None:
            claimed.add(match)
            resolved.append(ResolvedEntry(entry, EntryIdentity.RENAMED, match))
        else:
            resolved.append(ResolvedEntry(entry, EntryIdentity.MISSING, None))
    unlisted = [p.name for p in candidates if p not in claimed]
    return resolved, unlisted


def describe_apk(apk: Path) -> dict[str, Any]:
    """Metadata for a manifest entry, established by APKForge inspection.

    Fields the inspection could not establish are ``None``; nothing is guessed.
    Used when adding entries to the manifest, never during a corpus run.
    """
    from apkforge.inspection.engine import InspectionEngine

    insp = InspectionEngine().inspect(apk, keep_workspace=False)
    m, inv = insp.manifest, insp.inventory
    ch: dict[str, Any] = {
        "inspection_status": str(insp.status),
        "total_file_count": inv.total_file_count,
        "dex_count": inv.dex_count,
        "multidex": inv.dex_count > 1,
        "native_library_count": inv.native_library_count,
        "native_abis": sorted(insp.native.abis_found) if insp.native else None,
        "resource_count": inv.resource_count,
        "asset_count": inv.asset_count,
        "embedded_apk_count": inv.embedded_apk_count,
        "certificate_count": inv.certificate_count,
    }
    if m is not None:
        ch.update(
            {
                "uses_permission_count": len(m.permissions),
                "declared_permission_count": len(m.declared_permissions),
                "activity_count": len(m.activities),
                "service_count": len(m.services),
                "receiver_count": len(m.receivers),
                "provider_count": len(m.providers),
            }
        )
    if insp.dex is not None:
        ch["dex_total_classes"] = insp.dex.total_classes
        ch["dex_total_methods"] = insp.dex.total_methods
    return {
        "filename": apk.name,
        "sha256": sha256_file(apk),
        "size_bytes": apk.stat().st_size,
        "package_name": m.package_name if m else None,
        "version_name": m.version_name if m else None,
        "version_code": m.version_code if m else None,
        "min_sdk": m.min_sdk if m else None,
        "target_sdk": m.target_sdk if m else None,
        "characteristics": ch,
    }


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------


def _stage_record(sr: StageResult) -> dict[str, Any]:
    """Compact per-stage record; full tool output stays in the stage log file."""
    d: dict[str, Any] = {
        "status": str(sr.status),
        "duration_seconds": round(sr.duration_seconds, 3),
        "exit_code": sr.exit_code,
        "log_file": str(sr.log_file) if sr.log_file else None,
    }
    if sr.status == StageStatus.FAIL:
        d.update(
            {
                "failure_category": str(sr.failure_category) if sr.failure_category else None,
                "classified": sr.classified,
                "failure_cause": sr.failure_cause,
                "evidence": sr.evidence,
                "failed_command": sr.failed_command,  # already secret-masked by CommandRunner
                "stdout_tail": sr.stdout[-_TAIL:],
                "stderr_tail": sr.stderr[-_TAIL:],
            }
        )
    return d


def _integrity_summary(full: dict[str, Any]) -> dict[str, Any]:
    native, manifest = full["native_libs"], full["manifest"]
    return {
        "native_lib_count": native["count"],
        "native_libs_identical": native["all_identical"],
        "manifest_parseable": manifest["rebuilt_parseable"],
        "manifest_identity_and_components_match": manifest["identity_and_component_counts_match"],
    }


@dataclass
class CorpusResult:
    """Outcome of one corpus entry (first attempt) plus repeat-run consistency."""

    corpus_id: str
    filename: str
    expected_sha256: str
    identity: EntryIdentity
    expected: Expectation
    outcome: Outcome
    comparison: Comparison
    apk_path: str | None = None
    apk_sha256: str | None = None  # as hashed by BuildService before the build
    input_unchanged: bool | None = None
    stages: dict[str, dict[str, Any]] = field(default_factory=dict)
    failure_cause: str = ""
    failure_evidence: str | None = None
    failure_command: list[str] | None = None
    signing_mode: str | None = None
    certificate_sha256: str | None = None
    integrity: dict[str, Any] | None = None
    duration_seconds: float = 0.0
    workspace: str | None = None
    log_file: str | None = None
    warnings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    attempts: list[dict[str, Any]] = field(default_factory=list)  # semantic signature per run
    previous: dict[str, Any] | None = None  # comparison with a previous run, if requested

    @property
    def consistent(self) -> bool:
        return all(a == self.attempts[0] for a in self.attempts[1:])

    @property
    def unexpected(self) -> bool:
        return self.comparison.unexpected

    def signature(self) -> dict[str, Any]:
        """What must be identical across repeated runs (not bytes, not timings)."""
        return {
            **self.outcome.to_dict(),
            "stages": {k: v["status"] for k, v in self.stages.items()},
            "apk_sha256": self.apk_sha256,
            "certificate_sha256": self.certificate_sha256,
            "integrity": self.integrity,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "corpus_id": self.corpus_id,
            "filename": self.filename,
            "apk_path": self.apk_path,
            "identity": str(self.identity),
            "expected_sha256": self.expected_sha256,
            "apk_sha256": self.apk_sha256,
            "input_unchanged": self.input_unchanged,
            **self.outcome.to_dict(),
            "failure_cause": self.failure_cause,
            "failure_evidence": self.failure_evidence,
            "failure_command": self.failure_command,
            "expected": self.expected.to_dict(),
            "comparison": str(self.comparison),
            "unexpected": self.unexpected,
            "stages": self.stages,
            "signing_mode": self.signing_mode,
            "certificate_sha256": self.certificate_sha256,
            "integrity": self.integrity,
            "duration_seconds": round(self.duration_seconds, 3),
            "workspace": self.workspace,
            "log_file": self.log_file,
            "warnings": self.warnings,
            "notes": self.notes,
            "attempt_count": len(self.attempts),
            "consistent": self.consistent,
            "attempts": self.attempts,
            "previous": self.previous,
        }


def run_entry(
    service: BuildService,
    resolved: ResolvedEntry,
    work_root: Path,
    *,
    attempt: int = 1,
    stage_timeout: int = DEFAULT_STAGE_TIMEOUT_SECONDS,
    check_integrity: bool = True,
    keep_output: bool = False,
) -> CorpusResult:
    """Build one corpus entry through ``BuildService`` in its own work directory."""
    entry = resolved.entry
    base = CorpusResult(
        corpus_id=entry.id,
        filename=entry.filename,
        expected_sha256=entry.sha256,
        identity=resolved.identity,
        expected=entry.expected,
        outcome=Outcome(FinalStatus.NOT_RUN),
        comparison=Comparison.CORPUS_ERROR,
    )
    if not resolved.identity.buildable or resolved.path is None:
        base.apk_sha256 = resolved.actual_sha256
        base.notes.append(resolved.problem or f"Entry not buildable: {resolved.identity}")
        return base

    base.apk_path = str(resolved.path)
    if resolved.identity == EntryIdentity.RENAMED:
        base.notes.append(f"Found by hash as {resolved.path.name} (manifest: {entry.filename}).")
    work_dir = work_root / entry.id / f"attempt-{attempt}"
    work_dir.mkdir(parents=True, exist_ok=False)  # never reuse a previous attempt's directory
    output = work_dir / "rebuilt.apk"
    t0 = time.monotonic()
    res = service.build_pipeline(
        resolved.path,
        BuildOptions(
            output_apk=output,
            work_dir=work_dir / "workspaces",
            keep_workspace_on_success=False,
            keep_workspace_on_failure=True,
            stage_timeout_seconds=stage_timeout,
        ),
    )
    base.duration_seconds = time.monotonic() - t0

    base.apk_sha256 = res.input_sha256
    base.input_unchanged = res.input_unchanged
    base.stages = {str(s.stage): _stage_record(s) for s in res.stages}
    base.failure_cause = res.failure_cause
    base.failure_evidence = res.failure_evidence
    base.failure_command = res.failure_command
    base.signing_mode = str(res.signing_mode)
    base.certificate_sha256 = res.certificate.sha256_digest if res.certificate else None
    base.workspace = str(res.workspace) if res.workspace else None
    base.log_file = str(res.log_file) if res.log_file else None
    base.warnings = list(res.warnings)
    base.outcome = Outcome.from_build_result(res)

    if res.input_sha256 is not None and res.input_sha256 != entry.sha256:
        # The file changed between resolution and the build; never compare that.
        base.outcome = Outcome(FinalStatus.NOT_RUN)
        base.notes.append(
            f"APK hash at build time ({res.input_sha256}) differs from the manifest; "
            "the corpus file was replaced during the run."
        )
    elif res.success and res.output_apk is not None and check_integrity:
        try:
            base.integrity = _integrity_summary(compare_noop_rebuild(resolved.path, res.output_apk))
        except Exception as exc:  # recorded, never raised: the build itself succeeded
            base.integrity = {"error": f"{type(exc).__name__}: {exc}"}
    if res.output_apk is not None and not keep_output:
        res.output_apk.unlink(missing_ok=True)

    base.comparison = compare_outcome(entry.expected.outcome, base.outcome)
    if base.comparison == Comparison.UNCHANGED_KNOWN_FAILURE:
        base.notes.append(f"Known limitation: {entry.expected.reason}")
    return base


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------


def _apkforge_revision(runner: CommandRunner, repo: Path | None) -> dict[str, Any]:
    from apkforge import __version__

    info: dict[str, Any] = {"version": __version__, "git_commit": None, "git_dirty": None}
    if repo is None:
        return info
    head = runner.run(["git", "-C", str(repo), "rev-parse", "HEAD"], timeout=15)
    if head.ok:
        info["git_commit"] = head.stdout.strip()
        status = runner.run(["git", "-C", str(repo), "status", "--porcelain"], timeout=15)
        info["git_dirty"] = bool(status.stdout.strip()) if status.ok else None
    return info


def toolchain_versions(check: dict[str, Any]) -> dict[str, str | None]:
    """The tool versions that identify a toolchain, from ``ToolchainCheckResult.to_dict()``."""
    tools = check.get("tools", {})
    return {k: (tools.get(k) or {}).get("version") for k in TOOLCHAIN_KEYS}


@dataclass
class CorpusRun:
    run_id: str
    started: str
    finished: str
    duration_seconds: float
    corpus_dir: str
    manifest_path: str | None
    manifest_sha256: str | None
    configuration: dict[str, Any]
    apkforge: dict[str, Any]
    environment: dict[str, Any]
    toolchain: dict[str, Any]
    signing: dict[str, Any]
    baseline_toolchain: dict[str, str | None]
    results: list[CorpusResult]
    unlisted_apks: list[str] = field(default_factory=list)
    previous_run: dict[str, Any] | None = None

    @property
    def toolchain_differences(self) -> dict[str, dict[str, str | None]]:
        current = self.toolchain.get("versions", {})
        return {
            k: {"baseline": v, "current": current.get(k)}
            for k, v in self.baseline_toolchain.items()
            if current.get(k) != v
        }

    def summary(self) -> dict[str, Any]:
        counts = Counter(r.comparison for r in self.results)
        status = Counter(r.outcome.final_status for r in self.results)
        summary: dict[str, Any] = {
            "total": len(self.results),
            "successful": status[FinalStatus.SUCCESS],
            "failed": status[FinalStatus.FAILURE],
            "not_run": status[FinalStatus.NOT_RUN],
            "known_failures": counts[Comparison.UNCHANGED_KNOWN_FAILURE],
            "unexpected_failures": sum(
                1 for r in self.results if r.unexpected and r.comparison != Comparison.CORPUS_ERROR
            ),
            "regressions": counts[Comparison.REGRESSION],
            "new_failures": counts[Comparison.NEW_FAILURE],
            "improvements": counts[Comparison.IMPROVEMENT],
            "corpus_errors": counts[Comparison.CORPUS_ERROR],
            "inconsistent": sum(1 for r in self.results if not r.consistent),
            "by_comparison": {str(c): counts[c] for c in Comparison},
            "attempts_per_entry": self.configuration.get("repeat", 1),
        }
        if self.previous_run is not None:
            prev = Counter((r.previous or {}).get("comparison") for r in self.results)
            summary["vs_previous"] = {str(c): prev[str(c)] for c in Comparison}
        summary["passed"] = (
            not any(r.unexpected for r in self.results) and summary["inconsistent"] == 0
        )
        return summary

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "phase": "C.4",
            "title": "APKForge corpus validation (BuildService no-op rebuild)",
            "run_id": self.run_id,
            "started": self.started,
            "finished": self.finished,
            "duration_seconds": round(self.duration_seconds, 1),
            "corpus_dir": self.corpus_dir,
            "manifest_path": self.manifest_path,
            "manifest_sha256": self.manifest_sha256,
            "configuration": self.configuration,
            "apkforge": self.apkforge,
            "environment": self.environment,
            "toolchain": self.toolchain,
            "baseline_toolchain": self.baseline_toolchain,
            "toolchain_differences": self.toolchain_differences,
            "signing": self.signing,
            "summary": self.summary(),
            "unlisted_apks": self.unlisted_apks,
            "previous_run": self.previous_run,
            "results": [r.to_dict() for r in self.results],
        }


def run_corpus(
    service: BuildService,
    manifest: CorpusManifest,
    corpus_dir: Path,
    work_root: Path,
    *,
    repeat: int = 1,
    stage_timeout: int = DEFAULT_STAGE_TIMEOUT_SECONDS,
    check_integrity: bool = True,
    keep_outputs: bool = False,
    only: Iterable[str] | None = None,
    repo_dir: Path | None = None,
    run_id: str | None = None,
    progress: Callable[[str], None] | None = None,
) -> CorpusRun:
    """Run every (or each ``only``) entry ``repeat`` times; first attempt is authoritative.

    Per-entry failures never stop the run. The toolchain is validated once by
    the service (its result is cached) and recorded with its versions.
    """
    if repeat < 1:
        raise ValueError("repeat must be >= 1")
    say = progress or (lambda _msg: None)
    started, t0 = _utc_now(), time.monotonic()
    run_id = run_id or new_run_id()
    work_root = work_root.resolve()

    resolved, unlisted = resolve_entries(manifest, corpus_dir)
    if only is not None:
        wanted = set(only)
        unknown = wanted - {r.entry.id for r in resolved}
        if unknown:
            raise ValueError(f"Unknown corpus ids: {sorted(unknown)}")
        resolved = [r for r in resolved if r.entry.id in wanted]

    check = service.check_toolchain().to_dict()
    results: dict[str, CorpusResult] = {}
    for attempt in range(1, repeat + 1):
        for i, r in enumerate(resolved, 1):
            say(f"[run {attempt}/{repeat}] [{i}/{len(resolved)}] {r.entry.id} ...")
            res = run_entry(
                service,
                r,
                work_root,
                attempt=attempt,
                stage_timeout=stage_timeout,
                check_integrity=check_integrity,
                keep_output=keep_outputs,
            )
            say(f"    {res.outcome} -> {res.comparison} ({res.duration_seconds:.1f}s)")
            first = results.setdefault(r.entry.id, res)
            first.attempts.append(res.signature())

    signing = service.signing
    return CorpusRun(
        run_id=run_id,
        started=started,
        finished=_utc_now(),
        duration_seconds=time.monotonic() - t0,
        corpus_dir=str(corpus_dir.resolve()),
        manifest_path=str(manifest.path) if manifest.path else None,
        manifest_sha256=manifest.sha256,
        configuration={
            "repeat": repeat,
            "stage_timeout_seconds": stage_timeout,
            "check_integrity": check_integrity,
            "only": sorted(only) if only is not None else None,
            "work_root": str(work_root),
        },
        apkforge=_apkforge_revision(service.runner, repo_dir),
        environment={
            "host": f"{platform.system()} {platform.release()} {platform.machine()}",
            "python": platform.python_version(),
        },
        toolchain={
            "versions": toolchain_versions(check),
            "config": service.toolchain.to_dict(),
            "check": check,
        },
        signing={
            "mode": str(signing.mode) if signing else None,
            "development_key": signing.development_key if signing else None,
            "description": signing.describe() if signing else None,  # paths only, no secrets
        },
        baseline_toolchain=dict(manifest.baseline_toolchain),
        results=[results[r.entry.id] for r in resolved],
        unlisted_apks=unlisted,
    )


def compare_with_previous(run: CorpusRun, previous: dict[str, Any]) -> None:
    """Annotate *run* with a comparison against a previous run's ``to_dict()`` output.

    Entries are matched by APK hash first (identity), then by corpus id.
    """
    by_hash = {r.get("apk_sha256"): r for r in previous.get("results", []) if r.get("apk_sha256")}
    by_id = {r.get("corpus_id"): r for r in previous.get("results", [])}
    for res in run.results:
        prev = by_hash.get(res.apk_sha256 or res.expected_sha256) or by_id.get(res.corpus_id)
        if prev is not None and prev.get("expected_sha256") != res.expected_sha256:
            prev = None  # same id, different APK: not comparable
        prev_outcome = Outcome.from_dict(prev) if prev else None
        res.previous = {
            "outcome": prev_outcome.to_dict() if prev_outcome else None,
            "comparison": str(compare_outcome(prev_outcome, res.outcome)),
        }
    run.previous_run = {
        "run_id": previous.get("run_id"),
        "apkforge": previous.get("apkforge"),
        "toolchain_versions": (previous.get("toolchain") or {}).get("versions"),
    }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

_CELL = {"PASS": "PASS", "FAIL": "FAIL", "SKIPPED": "skip"}


def render_report(run: CorpusRun) -> str:
    """Human-readable Markdown report, generated entirely from *run*."""
    s = run.summary()
    lines = [
        "# APKForge Corpus Validation Report",
        "",
        f"- Run: `{run.run_id}` ({run.started} -> {run.finished}, {run.duration_seconds:.1f}s)",
        f"- APKForge: {run.apkforge.get('version')} commit `{run.apkforge.get('git_commit')}`"
        + (" (working tree dirty)" if run.apkforge.get("git_dirty") else ""),
        f"- Corpus: {s['total']} APKs from `{run.corpus_dir}`",
        f"- Manifest: `{run.manifest_path}` sha256 `{run.manifest_sha256}`",
        f"- Signing mode: {run.signing.get('mode')}"
        + (" (APKForge development key)" if run.signing.get("development_key") else ""),
        f"- Attempts per APK: {s['attempts_per_entry']}; stage timeout "
        f"{run.configuration.get('stage_timeout_seconds')}s",
        f"- Host: {run.environment.get('host')}, Python {run.environment.get('python')}",
        "",
        "## Toolchain",
        "",
        "| Tool | Version | Path |",
        "|---|---|---|",
    ]
    tools = run.toolchain.get("check", {}).get("tools", {})
    for key in TOOLCHAIN_KEYS:
        t = tools.get(key) or {}
        lines.append(f"| {key} | {t.get('version') or '-'} | `{t.get('path') or '-'}` |")
    diffs = run.toolchain_differences
    lines.append("")
    if diffs:
        lines.append(
            "**Toolchain differs from the baseline toolchain** - result changes may be legitimate:"
        )
        lines += [
            f"- {k}: baseline {v['baseline']} -> current {v['current']}" for k, v in diffs.items()
        ]
    else:
        lines.append("Toolchain matches the manifest's baseline toolchain.")

    lines += [
        "",
        "## Results",
        "",
        "| Corpus id | "
        + " | ".join(st.capitalize() for st in _STAGES)
        + " | Final | Expected | Comparison | Consistent | Time |",
        "|---" * (len(_STAGES) + 6) + "|",
    ]
    for r in run.results:
        cells = [_CELL.get(r.stages.get(str(st), {}).get("status", ""), "-") for st in _STAGES]
        lines.append(
            f"| {r.corpus_id} | "
            + " | ".join(cells)
            + f" | {r.outcome} | {r.expected.outcome} | {r.comparison} | "
            + f"{'yes' if r.consistent else '**NO**'} ({len(r.attempts)}) | "
            + f"{r.duration_seconds:.1f}s |"
        )

    problems = [r for r in run.results if r.outcome.final_status != FinalStatus.SUCCESS]
    if problems:
        lines += ["", "## Failure evidence", ""]
        for r in problems:
            lines += [
                f"### {r.corpus_id} - {r.comparison}",
                "",
                f"- APK: `{r.filename}` sha256 `{r.apk_sha256 or r.expected_sha256}`",
                f"- Outcome: {r.outcome}",
                f"- Cause: {r.failure_cause or '-'}",
                f"- Evidence: `{r.failure_evidence or '-'}`",
                f"- Command: `{' '.join(r.failure_command) if r.failure_command else '-'}`",
                f"- Log: `{r.log_file or '-'}`",
            ]
            lines += [f"- Note: {n}" for n in r.notes]
            lines.append("")
    inconsistent = [r for r in run.results if not r.consistent]
    if inconsistent:
        lines += ["", "## Inconsistent repeated runs", ""]
        for r in inconsistent:
            lines.append(f"- {r.corpus_id}: " + json.dumps(r.attempts))

    lines += [
        "",
        "## Summary",
        "",
        f"- Total: {s['total']}",
        f"- Successful: {s['successful']}",
        f"- Failed: {s['failed']}",
        f"- Not run (corpus errors): {s['corpus_errors']}",
        f"- Known failures: {s['known_failures']}",
        f"- Unexpected failures: {s['unexpected_failures']}",
        f"- Regressions: {s['regressions']}",
        f"- New failures: {s['new_failures']}",
        f"- Improvements: {s['improvements']}",
        f"- Inconsistent across repeats: {s['inconsistent']}",
    ]
    if run.previous_run is not None:
        prev = ", ".join(f"{k}={v}" for k, v in s["vs_previous"].items() if v)
        lines.append(f"- Versus previous run `{run.previous_run.get('run_id')}`: {prev}")
    if run.unlisted_apks:
        lines.append(f"- APKs in the corpus directory but not in the manifest: {run.unlisted_apks}")
    lines += ["", f"**Baseline check: {'PASSED' if s['passed'] else 'FAILED'}**", ""]
    return "\n".join(lines)
