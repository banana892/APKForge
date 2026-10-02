"""C.5 precondition: semantic no-op baseline.

C.4 proved that every corpus APK survives decode -> build -> align -> sign -> verify.
This module answers the next question: does an *unmodified* round trip produce only
acceptable rebuild noise? Each APK is rebuilt through ``BuildService.build_pipeline``
with no modification, compared with the original by ``DiffEngine``, and every
observation is classified with :func:`apkforge.diff.expectations.verify_expectations`
(no expected changes).

The result per APK is one of:

- ``EQUIVALENT``: every observation is explained by a documented noise rule
- ``EQUIVALENT_WITH_RESIDUE``: additionally, unpaired resource renames remain whose
  removed and added sizes correspond exactly (known-limitations §2); they are recorded
  per APK and accepted for that APK only, by exact path
- ``NOT_EQUIVALENT``: any other unexplained observation
- ``UNDETERMINED``: the diff was not complete, so equivalence could not be established
- ``BUILD_FAILED``: the no-op rebuild itself failed

This is a separate, explicitly named result; it never rewrites the C.4 build baseline.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from apkforge.builders.models import BuildOptions
from apkforge.diff.engine import DiffEngine
from apkforge.diff.expectations import (
    NOISE_RULES,
    Observation,
    ObservationClass,
    verify_expectations,
)

if TYPE_CHECKING:
    from pathlib import Path

    from apkforge.builders.service import BuildService
    from apkforge.diff.models import DiffResult

__all__ = [
    "NoopSemanticBaseline",
    "NoopSemanticEntry",
    "SemanticResult",
    "classify_noop_diff",
    "run_semantic_noop",
]

SCHEMA_VERSION = 1


class SemanticResult(StrEnum):
    EQUIVALENT = "EQUIVALENT"
    EQUIVALENT_WITH_RESIDUE = "EQUIVALENT_WITH_RESIDUE"
    NOT_EQUIVALENT = "NOT_EQUIVALENT"
    UNDETERMINED = "UNDETERMINED"
    BUILD_FAILED = "BUILD_FAILED"


class NoopSemanticEntry(BaseModel):
    id: str
    filename: str
    sha256: str
    package_name: str | None = None
    build_success: bool
    build_failure: str | None = None
    input_unchanged: bool | None = None
    rebuilt_sha256: str | None = None
    signer_sha256: str | None = None
    diff_status: str | None = None
    observation_counts: dict[str, int] = Field(default_factory=dict)
    noise_rule_counts: dict[str, int] = Field(default_factory=dict)
    residue: list[Observation] = Field(default_factory=list)
    unexpected: list[Observation] = Field(default_factory=list)
    unknown: list[Observation] = Field(default_factory=list)
    diff_failures: list[str] = Field(default_factory=list)
    result: SemanticResult
    notes: list[str] = Field(default_factory=list)


class NoopSemanticBaseline(BaseModel):
    schema_version: int = SCHEMA_VERSION
    name: str = "C.5 precondition semantic no-op baseline"
    purpose: str = (
        "Records what an unmodified BuildService round trip changes, classified by the "
        "documented rebuild-noise rules. Separate from the C.4 build baseline."
    )
    generated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    toolchain: dict[str, Any] = Field(default_factory=dict)
    noise_rules: dict[str, str] = Field(default_factory=lambda: dict(NOISE_RULES))
    entries: list[NoopSemanticEntry] = Field(default_factory=list)

    def entry_for(self, sha256: str) -> NoopSemanticEntry | None:
        return next((e for e in self.entries if e.sha256 == sha256.lower()), None)

    def allowances(self, sha256: str) -> tuple[set[str], set[tuple[str, str, str]]] | None:
        """Noise rules and residue established for this APK, or None if not usable."""
        e = self.entry_for(sha256)
        if e is None or e.result not in (
            SemanticResult.EQUIVALENT,
            SemanticResult.EQUIVALENT_WITH_RESIDUE,
        ):
            return None
        return set(e.noise_rule_counts), {(o.category, o.kind, o.identifier) for o in e.residue}


def _is_resource_file(o: Observation) -> bool:
    return (
        o.category == "file"
        and o.kind in ("added", "removed")
        and o.detail.get("file_category") == "resource"
        and o.identifier.startswith("res/")
    )


def classify_noop_diff(
    diff: DiffResult,
) -> tuple[SemanticResult, dict[str, Any]]:
    """Classify an original-vs-no-op-rebuild diff."""
    verdict = verify_expectations(diff, [])
    unexpected = [c.observation for c in verdict.of(ObservationClass.UNEXPECTED)]
    unknown = [c.observation for c in verdict.of(ObservationClass.UNKNOWN)]

    residue: list[Observation] = []
    candidates = [o for o in unexpected if _is_resource_file(o)]
    removed = Counter(o.detail.get("size") for o in candidates if o.kind == "removed")
    added = Counter(o.detail.get("size") for o in candidates if o.kind == "added")
    # Unpaired renames: accept only when removed and added sizes correspond exactly.
    if candidates and removed == added:
        residue = candidates
        unexpected = [o for o in unexpected if o not in residue]

    counts = Counter(f"{c.observation.category}:{c.observation.kind}" for c in verdict.observations)
    diff_failures = [
        f for f in verdict.failures if not f.endswith(("unexpected change(s)", "be classified"))
    ]
    if unexpected:
        result = SemanticResult.NOT_EQUIVALENT
    elif unknown or diff_failures:
        result = SemanticResult.UNDETERMINED
    elif residue:
        result = SemanticResult.EQUIVALENT_WITH_RESIDUE
    else:
        result = SemanticResult.EQUIVALENT
    return result, {
        "diff_status": verdict.diff_status,
        "observation_counts": dict(sorted(counts.items())),
        "noise_rule_counts": dict(sorted(verdict.noise_rule_counts.items())),
        "residue": residue,
        "unexpected": unexpected,
        "unknown": unknown,
        "diff_failures": diff_failures,
    }


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run_semantic_noop(
    service: BuildService,
    apk: Path,
    *,
    entry_id: str,
    work_dir: Path,
    diff_engine: DiffEngine | None = None,
) -> NoopSemanticEntry:
    """No-op round trip of *apk* through BuildService, then classify the semantic diff."""
    sha = _sha256(apk)
    out = work_dir / f"{apk.stem}.noop.apk"
    res = service.build_pipeline(
        apk, BuildOptions(output_apk=out, overwrite_output=True, work_dir=work_dir / "builds")
    )
    base: dict[str, Any] = {
        "id": entry_id,
        "filename": apk.name,
        "sha256": sha,
        "build_success": res.success,
        "input_unchanged": res.input_unchanged,
        "signer_sha256": res.certificate.sha256_digest if res.certificate else None,
    }
    if not res.success or res.output_apk is None:
        return NoopSemanticEntry(
            **base,
            build_failure=f"{res.failure_stage}: {res.failure_category}: {res.failure_cause}",
            result=SemanticResult.BUILD_FAILED,
        )
    diff = (diff_engine or DiffEngine()).diff(apk, res.output_apk)
    result, detail = classify_noop_diff(diff)
    return NoopSemanticEntry(
        **base,
        package_name=diff.apk_a.package_name,
        rebuilt_sha256=_sha256(res.output_apk),
        result=result,
        **detail,
    )
