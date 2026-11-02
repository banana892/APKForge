"""Phase 9.2 - H.1 reference analysis for picking transformation targets.

One job runs ``ReferenceAnalysisService`` and returns every defined class and method with
the number of incoming references H.1 observed, unreferenced first. The full result (all
evidence) is too large to send, so the last few are kept here and the call sites inside
one method (H-TRANS-003 targets) are fetched on demand.

The counts are a guide, not a decision: string mentions are not counted, and the H.2 plan
the user runs next re-checks every requirement.
"""

from __future__ import annotations

import secrets
import threading
from collections import Counter, OrderedDict
from typing import TYPE_CHECKING, Any

from fastapi import HTTPException
from pydantic import BaseModel

from apkforge.gui.jobs import Job  # noqa: TC001 - FastAPI resolves the response model
from apkforge.reference import ReferenceAnalysisService
from apkforge.reference.models import ReferenceKind

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from fastapi import FastAPI

    from apkforge.gui.jobs import JobManager
    from apkforge.reference.models import ReferenceAnalysisResult

__all__ = ["add_reference_routes", "summarize"]

#: Reference results kept for call-site lookups; each can be large.
MAX_RESULTS = 3
_INVOKES = (ReferenceKind.METHOD_REFERENCE, ReferenceKind.CONSTRUCTOR_REFERENCE)


class ReferencesBody(BaseModel):
    apk: str


def summarize(result: ReferenceAnalysisResult) -> dict[str, Any]:
    """Classes and methods with incoming-reference counts, in one pass over the evidence
    (``assess_absence`` per class would rescan it for every class)."""
    definitive: Counter[str] = Counter()
    indirect: Counter[str] = Counter()
    calls: Counter[str] = Counter()
    for ev in result.all_evidence():
        cls = ev.target_class or ev.target
        if ev.kind is ReferenceKind.STRING_REFERENCE or ev.source_class == cls:
            continue  # the same filter as ReferenceIndex.assess_absence
        (definitive if ev.definitive else indirect)[cls] += 1
        if ev.kind in _INVOKES and ev.member_name and ev.descriptor is not None:
            calls[f"{ev.target_class}->{ev.member_name}{ev.descriptor}"] += 1
    classes = [
        {
            "name": c.name,
            "superclass": c.superclass,
            "analysis_state": str(c.analysis_state),
            "references": definitive[c.name],
            "indirect": indirect[c.name],
            "methods": [
                {
                    "name": m.name,
                    "descriptor": m.descriptor,
                    "calls": calls[f"{c.name}->{m.name}{m.descriptor}"],
                }
                for m in c.methods
            ],
        }
        for c in sorted(
            result.defined_classes,
            key=lambda c: (definitive[c.name] + indirect[c.name], c.name),  # unreferenced first
        )
    ]
    return {
        "apk": result.apk.model_dump(mode="json"),
        "analysis_state": str(result.analysis_state),
        "component_states": {k: str(v) for k, v in result.component_states.items()},
        "reflection": len(result.reflection),
        "native": len(result.native),
        "classes": classes,
        "limitations": result.limitations,
        "errors": result.errors,
    }


def call_sites(result: ReferenceAnalysisResult, cls: str, method: str) -> list[dict[str, Any]]:
    """Invocations inside ``cls->method`` (``method`` = name + proto) as H-TRANS-003
    targets, ``caller@invoked`` plus ``#n`` when the same method is invoked again."""
    seen: Counter[str] = Counter()
    rows = []
    evs = result.index().invocations_in(cls, method)
    totals = Counter(f"{e.target_class}->{e.member_name}{e.descriptor or ''}" for e in evs)
    for ev in evs:
        invoked = f"{ev.target_class}->{ev.member_name}{ev.descriptor or ''}"
        seen[invoked] += 1
        nth = f"#{seen[invoked]}" if totals[invoked] > 1 else ""
        rows.append({
            "invoked": invoked,
            "line": ev.java_line or ev.source_line,
            "instruction": ev.instruction,
            "target": f"{cls}->{method}@{invoked}{nth}",
        })  # fmt: skip
    return rows


def add_reference_routes(
    app: FastAPI, jobs: JobManager, apk_path: Callable[[str, str], Path]
) -> None:
    results: OrderedDict[str, ReferenceAnalysisResult] = OrderedDict()
    lock = threading.Lock()

    @app.post("/api/jobs/references", status_code=202)
    def references(body: ReferencesBody) -> Job:
        apk = apk_path(body.apk, "apk")
        ref_id = secrets.token_hex(8)

        def work() -> dict[str, Any]:
            result = ReferenceAnalysisService().analyze(apk)
            with lock:
                results[ref_id] = result
                while len(results) > MAX_RESULTS:
                    results.popitem(last=False)
            return {"ref_id": ref_id, "apk_path": str(apk), **summarize(result)}

        return jobs.submit("references", {"apk": str(apk)}, work)

    @app.get("/api/references/{ref_id}/call-sites")
    def get_call_sites(ref_id: str, class_name: str, method: str) -> list[dict[str, Any]]:
        with lock:
            result = results.get(ref_id)
        if result is None:
            raise HTTPException(410, "reference result expired; run the analysis again")
        return call_sites(result, class_name, method)
