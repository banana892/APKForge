"""Background jobs for the GUI: analysis, diff and ModKit runs can take minutes, so the
HTTP request only queues work and the page polls for the result.

With a *store* directory each job is also kept as ``<id>.json`` (mode 0600, rewritten on
every change) and reloaded on the next start, so results survive a restart; a job that was
still queued or running then is reloaded as ERROR. Without one, jobs live in memory only.
The work itself writes nothing new: each job calls the same service the CLI does.

Cancelling: a queued job never starts. A running ModKit job has its process group killed
(:data:`apkforge.modkit.process.CANCEL_EVENT`, the Ctrl+C path). Other running work
(analysis, diff) cannot be interrupted in a Python thread: it runs to the end and is then
marked CANCELLED instead of DONE.
"""

from __future__ import annotations

import contextlib
import datetime
import json
import os
import secrets
import threading
from collections import OrderedDict
from concurrent.futures import Future, ThreadPoolExecutor
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from loguru import logger
from pydantic import BaseModel, Field, ValidationError

from apkforge.modkit.process import CANCEL_EVENT

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

__all__ = ["Job", "JobManager", "JobStatus"]

#: Finished jobs kept for the page; the oldest are dropped first.
MAX_JOBS = 200
INTERRUPTED = "interrupted: the workbench stopped before this job finished"


class JobStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    DONE = "DONE"
    #: The job raised: an APKForge bug or bad input, not an analysis verdict.
    ERROR = "ERROR"
    CANCELLED = "CANCELLED"


class Job(BaseModel):
    id: str
    kind: str
    #: What was asked, already masked (see app.py) - shown in the job list.
    summary: dict[str, Any] = Field(default_factory=dict)
    status: JobStatus = JobStatus.QUEUED
    created: str
    started: str | None = None
    finished: str | None = None
    result: Any = None
    error: str | None = None
    cancel_requested: bool = False


def _now() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")


_FINAL = (JobStatus.DONE, JobStatus.ERROR, JobStatus.CANCELLED)


def _load(store: Path) -> list[Job]:
    jobs = []
    for f in store.glob("*.json"):
        try:
            job = Job.model_validate_json(f.read_bytes())
        except (OSError, ValidationError) as exc:
            logger.warning("skipping unreadable job file {}: {}", f, exc)
            continue
        if job.id != f.stem:
            continue
        if job.status not in _FINAL:
            job = job.model_copy(update={"status": JobStatus.ERROR, "error": INTERRUPTED})
        jobs.append(job)
    return sorted(jobs, key=lambda j: (j.created, j.id))


class JobManager:
    def __init__(self, workers: int = 2, store: Path | None = None) -> None:
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="apkforge-job")
        self._jobs: OrderedDict[str, Job] = OrderedDict()
        self._futures: dict[str, Future[None]] = {}
        self._cancel: dict[str, threading.Event] = {}
        self._lock = threading.Lock()
        #: Serialises file writes; each write takes the job's state at that moment, so the
        #: last write is never older than an earlier one.
        self._io_lock = threading.Lock()
        self._store = store
        if store is not None:
            store.mkdir(parents=True, exist_ok=True, mode=0o700)
            jobs = _load(store)
            self._forget([j.id for j in jobs[:-MAX_JOBS]])
            for job in jobs[-MAX_JOBS:]:
                self._jobs[job.id] = job

    def _persist(self, job_id: str) -> None:
        if self._store is None:
            return
        with self._io_lock:
            with self._lock:
                job = self._jobs.get(job_id)
            if job is None:
                return
            tmp = self._store / f".{job_id}.tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(job.model_dump_json())
            os.replace(tmp, self._store / f"{job_id}.json")

    def _forget(self, job_ids: list[str]) -> None:
        if self._store is None:
            return
        with self._io_lock:
            for old in job_ids:
                with contextlib.suppress(FileNotFoundError):
                    (self._store / f"{old}.json").unlink()

    def submit(self, kind: str, summary: dict[str, Any], work: Callable[[], Any]) -> Job:
        """Queue *work*; its return value must be JSON-serialisable (or a pydantic model)."""
        job = Job(id=secrets.token_hex(6), kind=kind, summary=summary, created=_now())
        evicted = []
        with self._lock:
            self._jobs[job.id] = job
            self._cancel[job.id] = threading.Event()
            while len(self._jobs) > MAX_JOBS:
                old, _ = self._jobs.popitem(last=False)
                self._futures.pop(old, None)
                self._cancel.pop(old, None)
                evicted.append(old)
            self._futures[job.id] = self._pool.submit(self._run, job.id, work)
        self._forget(evicted)
        self._persist(job.id)  # writes the latest state, even if the job already moved on
        return job

    def cancel(self, job_id: str) -> Job | None:
        """Cancel *job_id*; returns the updated job (None if unknown). Finished jobs are
        returned unchanged."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.status not in (JobStatus.QUEUED, JobStatus.RUNNING):
                return job
            self._cancel[job_id].set()
            future = self._futures.get(job_id)
            if future is not None and future.cancel():  # never started
                update = {"status": JobStatus.CANCELLED, "finished": _now()}
                job = job.model_copy(update={**update, "cancel_requested": True})
            else:
                job = job.model_copy(update={"cancel_requested": True})
            self._jobs[job_id] = job
        self._persist(job_id)
        return job

    def _update(self, job_id: str, **fields: Any) -> None:  # noqa: ANN401
        with self._lock:
            if job_id in self._jobs:
                self._jobs[job_id] = self._jobs[job_id].model_copy(update=fields)
        self._persist(job_id)

    def _run(self, job_id: str, work: Callable[[], Any]) -> None:
        with self._lock:
            event = self._cancel.get(job_id)
        if event is None or event.is_set():
            return
        self._update(job_id, status=JobStatus.RUNNING, started=_now())
        # Pool threads are reused: reset the variable so it never leaks into the next job.
        token = CANCEL_EVENT.set(event)
        try:
            value = work()
            # Normalise now, on the worker thread, so serving a job is cheap and stable.
            if isinstance(value, BaseModel):
                value = json.loads(value.model_dump_json())
            # A cancelled job keeps what it produced (e.g. a CANCELLED ModKit result with
            # its workspace path) as evidence; it is just not DONE.
            status = JobStatus.CANCELLED if event.is_set() else JobStatus.DONE
            self._update(job_id, status=status, finished=_now(), result=value)
        except Exception as exc:  # surface any failure to the page instead of a dead job
            self._update(job_id, status=JobStatus.ERROR, finished=_now(),
                         error=f"{type(exc).__name__}: {exc}")  # fmt: skip
        finally:
            CANCEL_EVENT.reset(token)

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self) -> list[Job]:
        """Newest first, without results (they can be large)."""
        with self._lock:
            jobs = list(self._jobs.values())
        return [j.model_copy(update={"result": None}) for j in reversed(jobs)]

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
