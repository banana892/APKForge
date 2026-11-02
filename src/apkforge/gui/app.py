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

import re
import secrets
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, Field, ValidationError

# Services are imported here, not in job threads: two threads importing the same
# circular package at once raise _DeadlockError.
import apkforge
from apkforge.analysis.full import run_full_analysis
from apkforge.core.config import load_default_config
from apkforge.diff.engine import DiffEngine
from apkforge.diff.expectations import observe
from apkforge.gui.jobs import Job, JobManager
from apkforge.modkit import ChainSpec, ExecutionRequest, ModKitChainRunner, default_manager
from apkforge.modkit.masking import MASK, is_sensitive_name
from apkforge.modkit.validation import validate_apk_archive

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

__all__ = ["TOKEN_HEADER", "create_app"]

TOKEN_HEADER = "X-APKForge-Token"  # noqa: S105 - a header name, not a secret
_STATIC = Path(__file__).parent / "static"
_LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost"})
#: Uploads are a convenience for APKs not already on disk; larger ones: type the path.
MAX_UPLOAD_BYTES = 1024 * 1024 * 1024
_UNSAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


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


class PatchesBody(BaseModel):
    modkit: str
    patches: str
    package: str | None = None
    with_options: bool = True


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


def _upload_name(name: str) -> str:
    stem = _UNSAFE_NAME.sub("_", Path(name).name).strip("._")[:100] or "upload"
    return stem if stem.lower().endswith(".apk") else f"{stem}.apk"


def create_app(
    token: str,
    *,
    modkit_config: Path | None = None,
    jobs: JobManager | None = None,
    upload_dir: Path | None = None,
) -> FastAPI:
    """*upload_dir*: where uploaded APKs go (the caller deletes it on shutdown); default
    a fresh directory under the configured workspace base."""
    app = FastAPI(title="APKForge workbench", docs_url=None, redoc_url=None, openapi_url=None)
    manager_jobs = jobs or JobManager()
    app.state.jobs = manager_jobs
    if upload_dir is None:
        base = load_default_config().workspace.base_directory
        base.mkdir(parents=True, exist_ok=True)
        upload_dir = Path(tempfile.mkdtemp(prefix="gui-uploads-", dir=base))
    app.state.upload_dir = upload_dir

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

        return {"status": "ok", "version": apkforge.__version__}

    @app.get("/api/modkits")
    def modkits() -> list[dict[str, Any]]:

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

    @app.post("/api/jobs/{job_id}/cancel")
    def cancel_job(job_id: str) -> Job:
        job = manager_jobs.cancel(job_id)
        if job is None:
            raise HTTPException(404, "unknown job")
        return job

    @app.post("/api/uploads", status_code=201)
    async def upload(request: Request, name: str = "upload.apk") -> dict[str, Any]:
        """Raw request body = the APK (no multipart dependency). Stored under a random
        directory with a sanitised name; the client's name is never used as a path."""

        folder = upload_dir / secrets.token_hex(8)
        folder.mkdir(parents=True)
        dest = folder / _upload_name(name)
        size = 0
        with dest.open("xb") as out:
            async for chunk in request.stream():
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    out.close()
                    dest.unlink()
                    folder.rmdir()
                    raise HTTPException(413, f"upload larger than {MAX_UPLOAD_BYTES} bytes")
                out.write(chunk)
        problems = validate_apk_archive(dest)
        if problems:
            dest.unlink()
            folder.rmdir()
            raise HTTPException(422, "not a valid APK: " + "; ".join(problems[:3]))
        return {"path": str(dest), "size": size}

    @app.post("/api/jobs/modkit-patches", status_code=202)
    def modkit_patches(body: PatchesBody) -> Job:

        adapter = default_manager(modkit_config).get(body.modkit)
        if adapter is None or not hasattr(adapter, "list_patches"):
            raise HTTPException(422, f"{body.modkit} does not support patch bundle listing")

        def work() -> Any:  # noqa: ANN401
            listing, err = adapter.list_patches(
                body.patches, package=body.package or None, with_options=body.with_options
            )
            if listing is None:
                raise RuntimeError(err)
            return listing

        summary = {"modkit": body.modkit, "patches": body.patches}
        return manager_jobs.submit("modkit-patches", summary, work)

    @app.post("/api/jobs/analyze", status_code=202)
    def analyze(body: AnalyzeBody) -> Job:
        apk = _apk_path(body.apk, "apk")

        def work() -> Any:  # noqa: ANN401

            return run_full_analysis(apk, load_default_config())[0]

        return manager_jobs.submit("analyze", {"apk": str(apk)}, work)

    @app.post("/api/jobs/diff", status_code=202)
    def diff(body: DiffBody) -> Job:
        original = _apk_path(body.original, "original")
        modified = _apk_path(body.modified, "modified")

        def work() -> dict[str, Any]:

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
