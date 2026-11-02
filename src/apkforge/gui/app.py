"""Phase 9.1 - the local web workbench (FastAPI).

Every ``/api`` request must carry the per-launch token (``X-APKForge-Token``) and a
``Host`` of ``127.0.0.1``/``localhost``: the token stops other local users and other
web pages (CSRF) from driving the server, the Host check stops DNS rebinding. The page
itself (``/``) is static and holds no data; it reads the token from the URL fragment,
which browsers never send to the server.

The API only *calls existing services* (``run_full_analysis``, ``DiffEngine``,
``ModKitManager``/``ModKitChainRunner``) on paths the user typed; it adds no logic of its
own beyond input validation and masking.
"""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, Field, ValidationError

from apkforge.core.config import load_default_config
from apkforge.gui.jobs import Job, JobManager
from apkforge.modkit.masking import MASK, is_sensitive_name

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

__all__ = ["TOKEN_HEADER", "create_app"]

TOKEN_HEADER = "X-APKForge-Token"  # noqa: S105 - a header name, not a secret
_STATIC = Path(__file__).parent / "static"
_LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost"})


# -- request bodies ------------------------------------------------------------------


class AnalyzeBody(BaseModel):
    apk: str


class DiffBody(BaseModel):
    original: str
    modified: str


class ModKitRunBody(BaseModel):
    modkit: str
    apk: str
    output_dir: str
    operation: str
    parameters: dict[str, str] = Field(default_factory=dict)
    allow_noop: bool = False
    timeout_seconds: int | None = Field(default=None, ge=1, le=86_400)


class ChainBody(BaseModel):
    apk: str
    output_dir: str
    #: Same shape as a pipeline file's ``steps`` (``apkforge.modkit.chain.ChainStep``).
    steps: list[dict[str, Any]]
    check_conflicts: bool = False


# -- helpers -------------------------------------------------------------------------


def _apk_path(value: str, field: str) -> Path:
    p = Path(value).expanduser()
    if not p.is_absolute():
        raise HTTPException(422, f"{field}: an absolute path is required")
    if not p.is_file():
        raise HTTPException(422, f"{field}: {p} is not an existing file")
    return p.resolve()


def _dir_path(value: str, field: str) -> Path:
    p = Path(value).expanduser()
    if not p.is_absolute():
        raise HTTPException(422, f"{field}: an absolute path is required")
    if p.exists() and not p.is_dir():
        raise HTTPException(422, f"{field}: {p} exists and is not a directory")
    return p


def _masked(params: dict[str, str]) -> dict[str, str]:
    return {k: (MASK if is_sensitive_name(k) else v) for k, v in params.items()}


def create_app(
    token: str,
    *,
    modkit_config: Path | None = None,
    jobs: JobManager | None = None,
) -> FastAPI:
    app = FastAPI(title="APKForge workbench", docs_url=None, redoc_url=None, openapi_url=None)
    manager_jobs = jobs or JobManager()
    app.state.jobs = manager_jobs

    @app.middleware("http")
    async def guard(request: Request, call_next: Callable[[Request], Awaitable[Response]]
                    ) -> Response:  # fmt: skip
        host = (request.headers.get("host") or "").rsplit(":", 1)[0]
        if host not in _LOCAL_HOSTS:
            return JSONResponse({"detail": "forbidden host"}, status_code=403)
        if request.url.path.startswith("/api/"):
            sent = request.headers.get(TOKEN_HEADER, "")
            if not secrets.compare_digest(sent, token):
                return JSONResponse({"detail": "missing or invalid token"}, status_code=401)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
        )
        return response

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(_STATIC / "index.html")

    @app.get("/app.js", include_in_schema=False)
    def script() -> FileResponse:
        return FileResponse(_STATIC / "app.js", media_type="text/javascript")

    # -- read-only ---------------------------------------------------------------

    @app.get("/api/health")
    def health() -> dict[str, str]:
        import apkforge

        return {"status": "ok", "version": apkforge.__version__}

    @app.get("/api/modkits")
    def modkits() -> list[dict[str, Any]]:
        from apkforge.modkit import default_manager

        return [i.to_json_dict() for i in default_manager(modkit_config).discover()]

    # -- jobs --------------------------------------------------------------------

    @app.get("/api/jobs")
    def list_jobs() -> list[Job]:
        return manager_jobs.list()

    @app.get("/api/jobs/{job_id}")
    def get_job(job_id: str) -> Job:
        job = manager_jobs.get(job_id)
        if job is None:
            raise HTTPException(404, "unknown job")
        return job

    @app.post("/api/jobs/analyze", status_code=202)
    def analyze(body: AnalyzeBody) -> Job:
        apk = _apk_path(body.apk, "apk")

        def work() -> Any:  # noqa: ANN401
            from apkforge.analysis.full import run_full_analysis

            return run_full_analysis(apk, load_default_config())[0]

        return manager_jobs.submit("analyze", {"apk": str(apk)}, work)

    @app.post("/api/jobs/diff", status_code=202)
    def diff(body: DiffBody) -> Job:
        original = _apk_path(body.original, "original")
        modified = _apk_path(body.modified, "modified")

        def work() -> dict[str, Any]:
            from apkforge.diff.engine import DiffEngine
            from apkforge.diff.expectations import observe

            result = DiffEngine(config=load_default_config()).diff(original, modified)
            # The full DiffResult can be hundreds of MB on large apps; the page needs the
            # summary and the flat observation list.
            return {
                "status": str(result.status),
                "apk_a": result.apk_a.model_dump(mode="json"),
                "apk_b": result.apk_b.model_dump(mode="json"),
                "summary": result.summary.model_dump(mode="json"),
                "observations": [o.model_dump(mode="json") for o in observe(result)],
                "warnings": result.warnings,
                "errors": result.errors,
                "limitations": result.limitations,
            }

        return manager_jobs.submit(
            "diff", {"original": str(original), "modified": str(modified)}, work
        )

    @app.post("/api/jobs/modkit-run", status_code=202)
    def modkit_run(body: ModKitRunBody) -> Job:
        from apkforge.modkit import ExecutionRequest, default_manager

        apk = _apk_path(body.apk, "apk")
        request = ExecutionRequest(
            input_apk=apk,
            output_dir=_dir_path(body.output_dir, "output_dir"),
            operation=body.operation,
            parameters=body.parameters,
            timeout_seconds=body.timeout_seconds,
            expect_change=not body.allow_noop,
        )
        summary = {"modkit": body.modkit, "operation": body.operation, "apk": str(apk),
                   "parameters": _masked(body.parameters)}  # fmt: skip
        return manager_jobs.submit(
            "modkit-run", summary,
            lambda: default_manager(modkit_config).execute(body.modkit, request),
        )  # fmt: skip

    @app.post("/api/jobs/modkit-chain", status_code=202)
    def modkit_chain(body: ChainBody) -> Job:
        from apkforge.modkit import ChainSpec, ModKitChainRunner, default_manager

        apk = _apk_path(body.apk, "apk")
        out = _dir_path(body.output_dir, "output_dir")
        try:
            spec = ChainSpec.model_validate({"steps": body.steps})
        except ValidationError as exc:
            raise HTTPException(422, f"invalid chain: {exc}") from exc
        summary = {
            "apk": str(apk),
            "steps": [f"{s.modkit}/{s.operation} {_masked(s.parameters)}" for s in spec.steps],
            "check_conflicts": body.check_conflicts,
        }
        return manager_jobs.submit(
            "modkit-chain", summary,
            lambda: ModKitChainRunner(default_manager(modkit_config)).run(
                spec, apk, out, check_conflicts=body.check_conflicts
            ),
        )  # fmt: skip

    return app
