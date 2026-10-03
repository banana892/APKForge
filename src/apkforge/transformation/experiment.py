"""Phase H.4 control experiment: produce A (original), B (control), C (transformed).

::

    A ── BuildService no-op round trip ───────────────► B   (run_semantic_noop, kept)
    A ── H.3 TransformationExecutor (noise floor = B) ─► C   (published output)
    TransformationVerifier(A, B, C, plan)                    -> H.4 result

H.3 stays responsible for applying, building, signing and its own post-transform
verification; it publishes C only when it verified. The harness can optionally also
hand a *built but unpublished* H.3 output (kept in the failed run's workspace) to H.4, so
fault-injection experiments can show that H.4 independently rejects it. Such a file is
never written to the requested output path.

:meth:`ControlExperiment.noise_floor` measures the toolchain noise floor itself: two
independent unmodified rebuilds B1, B2 of A, compared with each other and classified
against each other with :meth:`TransformationVerifier.verify_noop`.

Nothing here writes the input APK; every artifact lives under the given work directory.
"""

from __future__ import annotations

import hashlib
import shutil
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from apkforge.builders.semantic_baseline import (
    NoopSemanticBaseline,
    NoopSemanticEntry,
    current_toolchain_identity,
    run_semantic_noop,
)
from apkforge.transformation.application import (
    ApplicationStatus,
    TransformationApplicationResult,
)
from apkforge.transformation.executor import TransformationExecutor, content_sha256
from apkforge.transformation.verification import (  # noqa: TC001 - pydantic fields
    TransformationVerificationResult,
)
from apkforge.transformation.verifier import TransformationVerifier

if TYPE_CHECKING:
    from apkforge.builders.service import BuildService
    from apkforge.diff.engine import DiffEngine
    from apkforge.reference.service import ReferenceAnalysisService
    from apkforge.transformation.models import PlanningResult, TransformationPlan

__all__ = ["ControlExperiment", "ExperimentResult", "NoiseFloorExperiment"]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class ExperimentResult(BaseModel):
    """A, B, C of one controlled transformation and their H.3 / H.4 results."""

    original: str
    original_sha256: str
    original_sha256_after: str | None = None
    control: str | None = None
    control_entry: NoopSemanticEntry | None = None
    transformed: str | None = None
    #: ``published`` (H.3 VERIFIED output), ``unpublished`` (built by a failed H.3 run,
    #: handed to H.4 only on request) or None (nothing was built)
    transformed_source: str | None = None
    application: TransformationApplicationResult | None = None
    verification: TransformationVerificationResult
    seconds: dict[str, float] = Field(default_factory=dict)


class NoiseFloorExperiment(BaseModel):
    """Two unmodified rebuilds of one APK: the measured toolchain noise floor."""

    original: str
    original_sha256: str
    original_sha256_after: str | None = None
    rebuilds: list[dict[str, Any]] = Field(default_factory=list)
    #: outer APK bytes of the two rebuilds are identical (not expected: ZIP metadata)
    apk_bytes_identical: bool | None = None
    #: every entry's content is identical between the two rebuilds
    entry_content_identical: bool | None = None
    #: the two A -> Bi no-op classifications accepted identical noise (with content)
    fingerprints_identical: bool | None = None
    noop_results: list[str] = Field(default_factory=list)
    #: H.4 verify_noop(A, control=B1, candidate=B2)
    verification: TransformationVerificationResult | None = None
    seconds: dict[str, float] = Field(default_factory=dict)


class ControlExperiment:
    """Reusable H.4 harness (see the module docstring)."""

    def __init__(
        self,
        service: BuildService,
        *,
        reference_service: ReferenceAnalysisService | None = None,
        diff_engine: DiffEngine | None = None,
    ) -> None:
        self.service = service
        self.diff_engine = diff_engine
        self.executor = TransformationExecutor(
            service, reference_service=reference_service, diff_engine=diff_engine
        )
        self.verifier = TransformationVerifier(
            service, reference_service=self.executor.reference, diff_engine=diff_engine
        )

    def rebuild_control(self, apk: Path, out_dir: Path) -> tuple[Path | None, NoopSemanticEntry]:
        """One unmodified BuildService round trip of *apk* into *out_dir* (kept), with
        its Phase E no-op classification."""
        out_dir.mkdir(parents=True, exist_ok=True)
        entry = run_semantic_noop(
            self.service, apk, entry_id=apk.name, work_dir=out_dir, diff_engine=self.diff_engine
        )
        shutil.rmtree(out_dir / "builds", ignore_errors=True)
        path = out_dir / f"{apk.stem}.noop.apk"
        return (path if entry.build_success and path.is_file() else None), entry

    def run(
        self,
        apk: Path | str,
        plan: Path | str | TransformationPlan | PlanningResult,
        work_dir: Path,
        *,
        verify_unpublished: bool = False,
    ) -> ExperimentResult:
        """Produce B and C for *plan* and verify C with H.4.

        With *verify_unpublished*, a transformed APK that H.3 built but refused to
        publish is verified too (fault-injection experiments).
        """
        src = Path(apk).expanduser().resolve()
        sha = _sha256(src)
        work_dir = Path(work_dir)
        work_dir.mkdir(parents=True, exist_ok=True)
        seconds: dict[str, float] = {}

        t = time.monotonic()
        control, entry = self.rebuild_control(src, work_dir / "control")
        seconds["control_rebuild"] = round(time.monotonic() - t, 3)
        identity = current_toolchain_identity(self.service)
        baseline = NoopSemanticBaseline(
            name="H.4 control rebuild (measured noise floor)",
            toolchain={"versions": identity.model_dump() if identity else None},
            toolchain_identity=identity,
            entries=[entry],
        )

        t = time.monotonic()
        out = work_dir / "transformed.apk"
        application = self.executor.run(
            src,
            plan,
            apply=True,
            output_apk=out,
            noop_baseline=baseline,
            work_dir=work_dir / "h3",
            keep_workspace=verify_unpublished,
        )
        seconds["h3"] = round(time.monotonic() - t, 3)
        transformed: Path | None = None
        source: str | None = None
        if application.status is ApplicationStatus.VERIFIED and out.is_file():
            transformed, source = out, "published"
        elif verify_unpublished and application.workspace:
            built = sorted(Path(application.workspace).rglob("signed/signed.apk"))
            if built and ApplicationStatus.BUILT in application.status_history:
                transformed = work_dir / "transformed.unpublished.apk"
                shutil.copyfile(built[0], transformed)
                source = "unpublished"
        if application.workspace and verify_unpublished:
            shutil.rmtree(application.workspace, ignore_errors=True)

        t = time.monotonic()
        verification = self.verifier.verify(
            src, control, transformed, plan, work_dir=work_dir / "h4"
        )
        seconds["h4"] = round(time.monotonic() - t, 3)
        return ExperimentResult(
            original=str(src),
            original_sha256=sha,
            original_sha256_after=_sha256(src),
            control=str(control) if control else None,
            control_entry=entry,
            transformed=str(transformed) if transformed else None,
            transformed_source=source,
            application=application,
            verification=verification,
            seconds=seconds,
        )

    def noise_floor(self, apk: Path | str, work_dir: Path) -> NoiseFloorExperiment:
        """Two independent unmodified rebuilds; B2 verified against A with B1 as control."""
        src = Path(apk).expanduser().resolve()
        res = NoiseFloorExperiment(original=str(src), original_sha256=_sha256(src))
        built: list[tuple[Path | None, NoopSemanticEntry]] = []
        for i in (1, 2):
            t = time.monotonic()
            path, entry = self.rebuild_control(src, Path(work_dir) / f"control-{i}")
            res.seconds[f"rebuild_{i}"] = round(time.monotonic() - t, 3)
            built.append((path, entry))
            res.noop_results.append(str(entry.result))
            res.rebuilds.append(
                {
                    "path": str(path) if path else None,
                    "sha256": _sha256(path) if path else None,
                    "content_sha256": content_sha256(path) if path else None,
                    "result": str(entry.result),
                    "noise_rule_counts": dict(entry.noise_rule_counts),
                    "build_failure": entry.build_failure,
                }
            )
        (b1, e1), (b2, e2) = built
        if b1 is not None and b2 is not None:
            r1, r2 = res.rebuilds
            res.apk_bytes_identical = r1["sha256"] == r2["sha256"]
            res.entry_content_identical = r1["content_sha256"] == r2["content_sha256"]
            res.fingerprints_identical = (
                e1.fingerprint is not None and e1.fingerprint == e2.fingerprint
            )
        t = time.monotonic()
        res.verification = self.verifier.verify_noop(src, b1, b2)
        res.seconds["h4"] = round(time.monotonic() - t, 3)
        res.original_sha256_after = _sha256(src)
        return res
