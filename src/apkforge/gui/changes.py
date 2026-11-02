"""Phase 9.2 - actions that write an APK: remediation, transformation, no-op build.

Every one is two steps. A *preview* job runs the read-only half (a remediation plan, an
H.2 transformation plan, a toolchain check) and the server remembers exactly what it was
given, including the APK's SHA-256. ``POST /api/jobs/apply`` then names that preview job
and an output path, and nothing else: the parameters, the APK and (for remediation and
transformation) the plan applied are the previewed ones, so what was shown is what runs.

An apply is refused unless the preview finished, says the change is applicable, has not
been applied already, and the APK still has the previewed SHA-256. The input APK is never
written; the output must be a new ``.apk`` path.
"""

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastapi import HTTPException
from pydantic import BaseModel

# Services are imported here, not in job threads: two threads importing the same
# circular package at once raise _DeadlockError.
from apkforge.builders import BuildOptions
from apkforge.builders.corpus import sha256_file
from apkforge.gui.jobs import Job, JobManager, JobStatus
from apkforge.privacy.service import PrivacyAnalysisService
from apkforge.reference import ReferenceAnalysisService
from apkforge.remediation import RemediationService
from apkforge.remediation.execution import default_build_service
from apkforge.remediation.mapping import map_finding_to_remediations
from apkforge.remediation.models import RemediationPlan
from apkforge.transformation import (
    CATALOG,
    TransformationExecutor,
    TransformationPlanningService,
    TransformationRequest,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from fastapi import FastAPI

__all__ = ["add_change_routes"]

#: What the Remediate tab shows of a Phase F finding (the full model is large).
_FINDING_FIELDS = {"id", "category", "title", "description", "severity", "confidence",
                   "evidence_locations", "source_component"}  # fmt: skip


class RemediationPlanBody(BaseModel):
    apk: str
    finding_id: str
    remediation_id: str | None = None


class TransformPlanBody(BaseModel):
    apk: str
    transformation_id: str
    target: str
    replacement: str | None = None


class BuildCheckBody(BaseModel):
    apk: str


class ApkBody(BaseModel):
    apk: str


class ApplyBody(BaseModel):
    preview_job: str
    output: str


@dataclass(frozen=True)
class _Preview:
    apk: Path
    sha256: str
    inputs: dict[str, Any] = field(default_factory=dict)


class _Previews:
    """Preview inputs by job id; :meth:`take` hands each out once (an apply per preview)."""

    def __init__(self) -> None:
        self._items: dict[str, _Preview] = {}
        self._lock = threading.Lock()

    def put(self, job_id: str, preview: _Preview) -> None:
        with self._lock:
            self._items[job_id] = preview

    def get(self, job_id: str) -> _Preview | None:
        with self._lock:
            return self._items.get(job_id)

    def take(self, job_id: str) -> _Preview | None:
        with self._lock:
            return self._items.pop(job_id, None)


def _applicable(kind: str, result: Any) -> str | None:  # noqa: ANN401
    """Why a finished preview cannot be applied, or None."""
    if not isinstance(result, dict):
        return "the preview produced no result"
    if kind == "remediation-plan":
        state = result.get("state")
        return None if state == "planned" else f"the remediation plan is {state}, not planned"
    if kind == "transform-plan":
        decisions = result.get("decisions") or []
        if result.get("errors"):
            return "the transformation plan has errors"
        if len(decisions) != 1 or decisions[0].get("plan") is None:
            state = decisions[0].get("eligibility") if decisions else "missing"
            return f"no applicable plan (eligibility {state})"
        return None
    if kind == "build-check":
        return None if result.get("toolchain", {}).get("valid") else "the toolchain is not valid"
    return f"{kind} jobs cannot be applied"


def _new_apk_path(value: str, source: Path) -> Path:
    p = Path(value).expanduser()
    if not p.is_absolute():
        raise HTTPException(422, "output: an absolute path is required")
    if p.suffix.lower() != ".apk":
        raise HTTPException(422, "output: must end in .apk")
    if p.exists():
        raise HTTPException(422, f"output: {p} already exists; choose a new file")
    if p.resolve() == source:
        raise HTTPException(422, "output: must differ from the input APK")
    return p


def add_change_routes(
    app: FastAPI,
    jobs: JobManager,
    session_dir: Path,
    apk_path: Callable[[str, str], Path],
) -> None:
    """Register the 9.2 routes. *session_dir* holds plan files for the session;
    *apk_path* is app.py's validator for user-typed APK paths."""
    previews = _Previews()
    plans_dir = session_dir / "plans"

    def preview(kind: str, apk: Path, summary: dict[str, Any], work: Callable[[], Any],
                **inputs: Any) -> Job:  # noqa: ANN401  # fmt: skip
        record = _Preview(apk=apk, sha256=sha256_file(apk), inputs=inputs)
        job = jobs.submit(kind, {"apk": str(apk), **summary}, work)
        previews.put(job.id, record)
        return job

    @app.post("/api/jobs/remediation-findings", status_code=202)
    def remediation_findings(body: ApkBody) -> Job:
        """Phase F privacy findings of *apk* with the remediations each one maps to."""
        apk = apk_path(body.apk, "apk")

        def work() -> list[dict[str, Any]]:

            analysis = PrivacyAnalysisService.analyze(apk)
            return [
                {
                    "finding": f.model_dump(mode="json", include=_FINDING_FIELDS),
                    "remediations": [
                        c.model_dump(mode="json") for c in map_finding_to_remediations(f)
                    ],
                }
                for f in analysis.findings
            ]

        return jobs.submit("remediation-findings", {"apk": str(apk)}, work)

    @app.post("/api/jobs/remediation-plan", status_code=202)
    def remediation_plan(body: RemediationPlanBody) -> Job:

        apk = apk_path(body.apk, "apk")
        return preview(
            "remediation-plan", apk,
            {"finding_id": body.finding_id, "remediation_id": body.remediation_id},
            lambda: RemediationService.plan(apk, body.finding_id,
                                            remediation_id=body.remediation_id),
        )  # fmt: skip

    @app.post("/api/jobs/transform-plan", status_code=202)
    def transform_plan(body: TransformPlanBody) -> Job:

        apk = apk_path(body.apk, "apk")
        tid = body.transformation_id.strip().upper()
        if tid not in CATALOG:
            raise HTTPException(422, f"unknown transformation {body.transformation_id}")
        if body.replacement and tid != "H-TRANS-003":
            raise HTTPException(422, "replacement applies only to H-TRANS-003")
        plan_file = plans_dir / f"{secrets.token_hex(8)}.json"

        def work() -> Any:  # noqa: ANN401
            request = TransformationRequest(
                transformation_id=tid, target=body.target,
                parameters={"replacement": body.replacement} if body.replacement else {},
            )  # fmt: skip
            result = TransformationPlanningService(ReferenceAnalysisService()).plan(apk, [request])
            # The apply step runs this exact file (`transform --plan FILE --apply`).
            plan_file.parent.mkdir(parents=True, exist_ok=True)
            plan_file.write_text(result.to_json() + "\n", encoding="utf-8")
            return result

        summary = {"transformation_id": tid, "target": body.target}
        return preview("transform-plan", apk, summary, work, plan_file=plan_file)

    @app.post("/api/jobs/build-check", status_code=202)
    def build_check(body: BuildCheckBody) -> Job:
        apk = apk_path(body.apk, "apk")

        def work() -> dict[str, Any]:

            service = default_build_service()
            return {
                "toolchain": service.check_toolchain().to_dict(),
                "signing": service.signing.describe() if service.signing else None,
            }

        return preview("build-check", apk, {}, work)

    @app.post("/api/jobs/apply", status_code=202)
    def apply(body: ApplyBody) -> Job:
        job = jobs.get(body.preview_job)
        record = previews.get(body.preview_job)
        if job is None or record is None:
            raise HTTPException(409, "unknown preview job, or it was already applied")
        if job.status is not JobStatus.DONE:
            raise HTTPException(409, f"the preview is {job.status}, not DONE")
        reason = _applicable(job.kind, job.result)
        if reason:
            raise HTTPException(409, f"cannot apply: {reason}")
        output = _new_apk_path(body.output, record.apk)
        if sha256_file(record.apk) != record.sha256:
            raise HTTPException(409, "the APK changed since the preview; preview it again")
        if previews.take(job.id) is None:  # a concurrent apply won
            raise HTTPException(409, "this preview was already applied")
        output.parent.mkdir(parents=True, exist_ok=True)
        work = _apply_work(job.kind, job.result, record, output)
        summary = {"preview_job": job.id, "preview_kind": job.kind,
                   "apk": str(record.apk), "output": str(output)}  # fmt: skip
        return jobs.submit("apply", summary, work)


def _apply_work(kind: str, result: Any, record: _Preview, output: Path) -> Callable[[], Any]:  # noqa: ANN401
    if kind == "remediation-plan":

        def remediate() -> Any:  # noqa: ANN401

            plan = RemediationPlan.model_validate(result)
            return RemediationService.apply(plan, approved=True, output_path=output)

        return remediate
    if kind == "transform-plan":

        def transform() -> Any:  # noqa: ANN401

            service = default_build_service()
            check = service.check_toolchain()
            if not check.valid:
                raise RuntimeError("build toolchain not valid: " + "; ".join(check.errors))
            return TransformationExecutor(service).run(
                record.apk, record.inputs["plan_file"], apply=True, output_apk=output
            )

        return transform

    def build() -> Any:  # noqa: ANN401

        service = default_build_service()
        return service.build_pipeline(record.apk, BuildOptions(output_apk=output)).to_dict()

    return build
