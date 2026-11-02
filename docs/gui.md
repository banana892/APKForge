# Workbench GUI (Phase 9)

`apkforge gui` opens a local web workbench in your browser. It is a thin layer over the
same services the CLI uses; it adds no analysis or modification logic of its own.

```bash
pip install 'apkforge[gui]'      # FastAPI + uvicorn; the core install does not need them
apkforge gui                     # free port on 127.0.0.1, opens the browser
apkforge gui --port 8765 --no-browser --config ~/modkits.toml
```

The command prints a URL like `http://127.0.0.1:PORT/#token=…`. Stop it with Ctrl+C.

## What 9.1 covers

| Tab | Does | Same as |
|---|---|---|
| Analyze | Inspection + privacy + security of one APK; findings sorted by severity | `apkforge analyze` (`apkforge.analysis.full.run_full_analysis`) |
| Diff | Phase E semantic diff of two APKs: summary counters and the flat observation list, filterable | `apkforge diff` (`DiffEngine` + `observe()`) |
| ModKits | Discovered ModKits with status/capabilities; run one operation with a form built from its `ParameterSpec`s (choices → dropdown, `sensitive` → password field). For Morphe, "List patches in this bundle" shows every patch (filterable, with compatibility and option keys); ticking patches fills `enable` | `apkforge modkits`, `apkforge modkit run`, `apkforge modkit patches` |
| Chain | Build a ModKit chain step by step (add, remove, reorder; per-step parameter form), or edit the same steps as JSON; optional conflict check | `apkforge modkit chain` (H.9/H.10) |
| Jobs | Every job of this session; click to reopen its result, cancel running ones | — |

APKs are given as **absolute paths on the local machine**, or uploaded with the "Upload…"
button next to each APK field (see below). Work runs as background jobs (two at a time)
and the page polls for the result, because analysis of a large APK can take minutes. Every
result has a "Download JSON" button. Jobs are in memory only and are forgotten when the
server stops.

**Cancel.** A queued job is dropped. A running ModKit run or chain has its tool's process
group killed (the same path as Ctrl+C on the CLI) and ends `CANCELLED`, keeping the result
it produced (which step stopped, the chain directory). A running analysis or diff cannot
be interrupted inside Python: it finishes in the background and is then marked
`CANCELLED` instead of `DONE`.

**Upload.** The file is streamed to a fresh directory under the workspace base
(`<tmp>/apkforge/gui-uploads-*/<random>/`), its name reduced to `[A-Za-z0-9._-]`, at most
1 GiB, and rejected unless it is a valid APK archive. The directory is deleted when
`apkforge gui` stops; nothing uploaded outlives the session.

The diff job returns the summary and observations rather than the full `DiffResult`,
which can be hundreds of MB for large apps; use `apkforge diff --json` for the full
structure.

## Security model

- **127.0.0.1 only.** The command binds the socket itself to `127.0.0.1`; there is no
  option to listen on another interface.
- **Per-launch token.** `secrets.token_urlsafe(32)`, required as `X-APKForge-Token` on every
  `/api/*` request (constant-time compare), otherwise `401`. It travels to the page in the
  URL *fragment*, which browsers never send to a server; the page moves it to
  `sessionStorage` and strips it from the address bar.
- **Host check.** Any request whose `Host` is not `127.0.0.1`/`localhost` is `403`, even
  with the token: this blocks DNS-rebinding pages that resolve their own name to
  127.0.0.1.
- **Untrusted content stays text.** APK strings, file names and tool output are rendered
  with `textContent` only (no `innerHTML`); the CSP is `default-src 'self'` with no inline
  scripts, `frame-ancestors 'none'`. No external CDN: the page works offline.
- **Secrets.** ModKit parameters whose names look like credentials are masked in the job
  list/summary; results carry the ModKit framework's own masking.
- No interactive API docs (`/docs`, `/openapi.json`) are served.

Anyone who has the URL (with its token) can use the workbench as you until it stops.

## Limits (9.1)

**Scope: not in the GUI yet** (CLI only). Each of these changes files or needs an approval
flow of its own, so they are later Phase 9 stages:

- modification planning and applying (`plan`, `modify`), remediation (`remediate`)
- H.2–H.4 transformations (`transform`, `verify`), `build`, `references`
- the standalone `privacy`/`security` reports and `analyze --report` exports; Analyze shows
  the unified result, and the job JSON is the only export
- patch *options* are listed (keys and defaults) but not edited in a form: type them into
  the `options` field as comma-separated `key=value`
- `diff --baseline` (normalized diff) and `--security` (security-relevant diff)
- `modkit run --analyze` post-analysis

**Input and output**

- Uploads go through the browser (1 GiB cap) and are copied once; for large APKs already
  on this machine, typing the path is faster.
- ModKit/chain output directories are typed; the final APK is published there and the
  page shows its path, it does not offer an APK download.
- The chain form checks steps only on submit (the server validates the whole chain).
- The Diff tab returns the summary and the flat observation list, not the full
  `DiffResult` (use `apkforge diff --json`).

**Jobs**

- In memory only: restarting `apkforge gui` forgets every job and result.
- At most two jobs run at once; more are queued. The last 200 jobs are kept.
- Cancel stops ModKit processes immediately but cannot stop an analysis or diff that is
  already running (see above).
- The page polls once a second; there is no progress bar inside a job.
- Results are held whole in memory and sent whole to the browser; an analysis with very
  many findings can make the page slow.
- `run_full_analysis`/`DiffEngine` workspaces are cleaned up the same way as on the CLI
  (DiffEngine currently leaves its workspaces in the temp directory, as it does there).

**Access and security**

- Single user, single machine. Anyone with the URL (including its token) can use the
  workbench as you until it stops; there are no accounts or roles.
- The token is per launch and never expires while the server runs; it lives in the tab's
  `sessionStorage`, so a new tab needs the original URL again.
- Not reachable from other machines by design (no `--host` option, no TLS).
- No OS-level sandbox, exactly as for the CLI: ModKits run with your privileges (see
  `docs/modkits.md`, "Security boundary").
- Only credential-*named* ModKit parameters are masked in the job list; a secret passed under
  an ordinary name is shown as typed (results still carry the ModKit framework's masking).

**Verification**

- Automated tests cover the API (`tests/unit/test_gui.py`); the JavaScript is only
  syntax-checked (`node --check`) and has no automated UI tests.
- Checked by hand in Chrome: Analyze (OpenLink), the ModKits tab, Morphe patch listing
  (194 patches from the 2.0.0 bundle, select → `enable`), upload, the chain step form and
  JSON round trip, cancelling a running chain, and the Jobs tab. The Diff tab was exercised
  through the API only.
- Tested in Chrome only; other browsers are untested. No accessibility audit was done
  beyond semantic HTML, labelled inputs and tab roles.
- The FastAPI test client logs a deprecation warning (Starlette is moving from `httpx` to
  `httpx2`).

## Code

- `src/apkforge/gui/app.py`: `create_app(token, modkit_config=...)`, the guard middleware
  and the API.
- `src/apkforge/gui/jobs.py`: `JobManager` (thread pool, in-memory, last 200 jobs).
- `src/apkforge/gui/static/`: `index.html` + `app.js` (no build step).
- Cancellation: `apkforge.modkit.process.CANCEL_EVENT` (a context variable the job thread
  sets; the process runner polls it).
- Tests: `tests/unit/test_gui.py` (token/Host guard, headers, path validation, analyze,
  diff, ModKit run with secret masking, chain, job errors, cancel, upload, patch listing).
