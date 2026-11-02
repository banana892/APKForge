# Workbench GUI (Phase 9)

`apkforge gui` opens a local web workbench in your browser. It is a thin layer over the
same services the CLI uses; it adds no analysis or modification logic of its own.

```bash
pip install 'apkforge[gui]'      # FastAPI + uvicorn; the core install does not need them
apkforge gui                     # free port on 127.0.0.1, opens the browser
apkforge gui --port 8765 --no-browser --config ~/modkits.toml
```

The command prints a URL like `http://127.0.0.1:PORT/#token=…`. Stop it with Ctrl+C.

**Status: Phase 9 is complete** (9.1–9.4, plus optional AI explanations). What it leaves
out is listed under [Limits](#limits): the CLI-only options, browsers other than Chrome,
an accessibility audit, and browser tests for the Plan tab and the ModKits list. These
are the backlog for any later GUI work.

## What the workbench covers

| Tab | Does | Same as |
|---|---|---|
| Analyze | Inspection + privacy + security of one APK; findings sorted by severity. "Open in Remediate" lists the same APK's remediable privacy findings (per APK: security findings do not name the privacy findings remediations act on) | `apkforge analyze` (`apkforge.analysis.full.run_full_analysis`) |
| Diff | Phase E semantic diff of two APKs: summary counters and the flat observation list, filterable | `apkforge diff` (`DiffEngine` + `observe()`) |
| ModKits | Discovered ModKits with status/capabilities; run one operation with a form built from its `ParameterSpec`s (choices → dropdown, `sensitive` → password field). For Morphe, "List patches in this bundle" shows every patch (filterable, with compatibility and option keys); ticking patches shows a field per option key of the ticked patches (Boolean → true/false, possible values as suggestions, required marked, current `options` prefilled); "Use selected" fills `enable` and `options` | `apkforge modkits`, `apkforge modkit run`, `apkforge modkit patches` |
| Chain | Build a ModKit chain step by step (add, remove, reorder; per-step parameter form), or edit the same steps as JSON; optional conflict check | `apkforge modkit chain` (H.9/H.10) |
| Plan (9.2) | Analysis-driven modification suggestions (risk, target, reason), optionally with diff evidence from the original; read-only | `apkforge plan APK [--diff ORIGINAL]` |
| Modify (9.2) | Phase D modifiers with their parameters: dry run (plan, preconditions, conflicts), then Apply (decode → modify → rebuild → sign → verify) | `apkforge modify APK --modifier ID --param ID:K=V --dry-run`, then without |
| Remediate (9.2) | Phase F privacy findings with the Phase G remediations each maps to; "Plan" shows preconditions, planned changes, expected diff; then Apply | `apkforge remediate --finding ID [--remediation R]`, then `--apply -o OUT` |
| References (9.2) | H.1 references: every defined class (unreferenced first, filterable) with its incoming references, its methods with call counts, and the call sites inside a method. Buttons hand a class, method or call site to Transform (H-TRANS-001/002 plan at once; H-TRANS-003 stops for the replacement) | `apkforge references APK` |
| Transform (9.2) | H.2 eligibility and plan for H-TRANS-001/002/003 and one target; then Apply (H.3/H.5/H.6) | `apkforge transform -t ID --target T --report plan.json`, then `--plan plan.json --apply -o OUT` |
| Build (9.2) | Toolchain + signing check, then a no-op rebuild | `apkforge build APK -o OUT` |
| Verify (9.2) | One APK: structure + signature. Two: the original → modified matrix with unexpected/unknown changes, optional noise floor and declared changes (JSON). A Modify apply's "Verify output" fills in the changes its modifiers declared. After a transformation apply, "Verify transformation" runs H.4 with a control rebuild | `apkforge verify A [B] [--measure-noise-floor] [--expected FILE]`, `verify A T --plan P --build-control` |
| Jobs | Every job of this session; click to reopen its result, cancel running ones | — |
| AI | Provider, model, base URL and API key for Explain, held in memory for this session (overrides the environment) | `APKFORGE_AI_*` / `ANTHROPIC_API_KEY` ([ai.md](ai.md)) |
| Explain (optional) | On a finished Analyze, Diff or Verify result, when an AI provider is configured (AI tab or the server's environment): a plain-language explanation, run as its own job | `apkforge explain RESULT.json` ([ai.md](ai.md)) |

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

## Changing an APK: preview, then apply (9.2)

Modify, Remediate, Transform and Build never write anything in one step. The first job is
a *preview* (modifier dry run, remediation plan, H.2 transformation plan, toolchain check)
that only reads.
When it says the change is applicable, an **Apply** form appears under it; it takes only
an output path. `POST /api/jobs/apply` names the preview job, and the server:

- runs exactly the previewed inputs: the remediation plan object that was shown, the H.2
  plan file the preview wrote (`transform --plan FILE --apply`), the same APK;
- refuses (409) unless the preview is `DONE` and applicable (dry run `dry_run`;
  remediation `planned`; a transformation decision with a plan and no errors; a valid
  toolchain);
- refuses if the APK's SHA-256 differs from the preview's (re-preview after any change);
- applies a preview **once**; a second apply, or two racing ones, gets 409;
- writes only a new `.apk` path (absolute, not existing, not the input). The input APK is
  never modified, as on the CLI.

A modifier apply needs a noise floor to classify what changed: the Modify tab measures it
by default (one extra rebuild, `--measure-noise-floor`); without it the result is
`failed` with "noise floor not established", exactly as on the CLI.

Signing is the same as the CLI: `APKFORGE_SIGNING_*` if set, otherwise the APKForge
development key (shown in the Build check).

**Verifying a Modify result again.** "Verify output" on a Modify apply runs a pair
verification of the original and the output, declaring the modifiers' `expected_changes`
and the archive entries rebuilt from the project files they edited
(`archive_entries_for(file_changes)`, e.g. `AndroidManifest.xml`, `classesN.dex`), the same
inputs the pipeline's own verification uses. Without those entries a re-encoded
`AndroidManifest.xml` would count as unexpected. The CLI equivalent is
`apkforge verify ORIGINAL MODIFIED --expected FILE --planned-file AndroidManifest.xml`
(repeatable; the GUI request field is `planned_files`, both end in
`verify_pair(planned_entries=...)`). A project file with no known archive mapping is
refused (GUI 422, CLI exit 2) rather than guessed.

**Choosing transformation targets.** The References tab counts what H.1 observed:
definitive and indirect references per class, invocations per method, call sites per
method. String mentions are not counted and the counts do not decide anything: the H.2
plan the button starts re-checks every requirement (reflection, resources, manifest,
partial analysis), so an "unreferenced" class can still be UNDETERMINED or INELIGIBLE. The
full H.1 result stays on the server (the last 3 analyses) for call-site lookups; an older
one answers 410 and has to be analyzed again.

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
  list/summary; results carry the ModKit framework's own masking. Stored jobs are written
  as they are shown (masked), one `0600` file per job in a `0700` directory; they hold
  analysis results of your APKs, so `--no-history` is the choice for sensitive work.
- **Downloads.** A link cannot carry the token header, so "Download APK" first asks
  (with the token) for a ticket: 32 random bytes, valid once and for 60 s, bound to the
  output the server itself recorded for that job (an apply's new `.apk` path, or a ModKit
  `published` artifact, re-hashed against its recorded SHA-256). `GET /download/{ticket}`
  needs no token but still passes the Host check; a path from the request is never
  served.
- **AI explanations.** Off unless a provider is set in the AI tab or the server's
  environment ([ai.md](ai.md)). A key entered in the AI tab is held in memory only. "Explain" names the provider, model and host before
  anything is sent, and sends the result only, never the APK. Keys stay in the server's
  environment: neither `GET /api/ai` nor any job carries them.
- No interactive API docs (`/docs`, `/openapi.json`) are served.

Anyone who has the URL (with its token) can use the workbench as you until it stops.

## Limits

**Scope: not in the GUI yet** (CLI only):

- `modify --plan FILE` (the pre-Phase D framework): it produces a decoded working copy, not
  an APK; the GUI's Plan tab is read-only and changes go through Modify or Remediate
- `--noop-baseline FILE`, `--expected-signer`, `verify --control APK`: the GUI measures
  the noise floor or builds the control itself. Declared changes are pasted as JSON (the
  `verify --expected` format), not loaded from a file
- `references --json` / `--no-resources` / the absence assessment for one class: the
  References tab shows counts and call sites, not the evidence list (use the CLI)
- remediation parameters: the GUI plans with the mapped defaults, like the CLI without
  `--param`; `--report` files (use Download JSON)
- the standalone `privacy`/`security` reports and `analyze --report` exports; Analyze shows
  the unified result, and the job JSON is the only export
- patch option values cannot contain a comma (the Morphe `options` parameter is
  comma-separated; the form refuses them), and one value per key applies to every
  selected patch with that key (Morphe's `-O key=value`); list-typed options are plain text
- `diff --baseline` (normalized diff) and `--security` (security-relevant diff)
- `modkit run --analyze` post-analysis

**Input and output**

- Uploads go through the browser (1 GiB cap) and are copied once; for large APKs already
  on this machine, typing the path is faster.
- Output paths and directories are typed. "Download APK" on a finished apply or ModKit
  run/chain sends the APK through the browser as well; it is still written to the typed
  path first.
- The chain form checks steps only on submit (the server validates the whole chain).
- The Diff tab returns the summary and the flat observation list, not the full
  `DiffResult` (use `apkforge diff --json`).

**Jobs**

- Jobs are kept across restarts in `$XDG_DATA_HOME/apkforge/gui/jobs` (`--jobs-dir DIR`;
  `--no-history` keeps them in memory only). What a job needed from its session is not:
  a preview from an earlier session cannot be applied (preview again, 409), a reference
  analysis has to be run again for call sites (410), and "Verify transformation" needs the
  session's plan file (409; plan and apply again). Uploaded APKs are deleted on exit, so
  their jobs show paths that no longer exist. A job that was queued or running when the
  workbench stopped comes back as ERROR "interrupted".
- At most two jobs run at once; more are queued. The last 200 jobs are kept.
- Cancel stops ModKit processes immediately but cannot stop an analysis, diff, plan or
  build that is already running (see above); a cancelled apply may still write its output.
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

- Automated tests cover the API (`tests/unit/test_gui.py`) and, in a headless browser,
  the page's handoffs (`tests/integration/test_gui_browser.py`, Playwright: modifier
  parameter fields, References → Transform with the `#2` call-site target, invalid declared
  changes not sent, Modify → Verify output with its declared changes and planned entries).
  9.4 adds Analyze (severity order) → Open in Remediate → plan → apply, Diff (observations
  and filter), a ModKit run (parameter form, secret field, Download APK), the chain JSON
  round trip and run, Build check → no-op rebuild, and the patch options form (shared
  keys, presets, required and comma checks, hand-typed options kept), and Explain on an
  Analyze result (hint names the provider; the answer is rendered as text). Analyze, Diff and
  the test ModKit run for real; remediation and the build toolchain are stubbed. The
  Plan tab and the ModKits list have no browser tests. The browser tests skip without
  Playwright's Chromium or an installed Google Chrome.
- Checked by hand in Chrome: Analyze (OpenLink), the ModKits tab, Morphe patch listing
  (194 patches from the 2.0.0 bundle, select → `enable`), upload, the chain step form and
  JSON round trip, cancelling a running chain, and the Jobs tab. 9.2 on OpenLink:
  build check → no-op rebuild (SUCCESS), PRIV-REC-BOOT → G-REM-001 plan → apply
  (`verified`; diff against the rebuild: 1 permission removed, 1 component modified), a
  second apply of the same preview refused (409), and a REFUSED H-TRANS-001 plan with its
  reasons. 9.2b on OpenLink: Plan (1 suggestion), `c5.disable_boot_receiver` dry run →
  apply with noise floor (`verified`, all build stages PASS), and pair verification of the
  result (renders the matrix; FAILED because a pair verify without declared expectations
  counts the intended changes as unexpected, as on the CLI). 9.2c: References on OpenLink
  (108 classes, 8 unreferenced; `a.a` → H-TRANS-001 plan UNDETERMINED: unknown reflection
  targets, assets PARTIAL); on the H.3 `h3_isolated` fixture APK, References →
  `com.example.h1.B` → H-TRANS-001 ELIGIBLE → apply `VERIFIED` → H.4 `VERIFIED`; and
  Modify `c5.disable_boot_receiver` → apply → "Verify output" `VERIFIED` (2 of 2 declared
  changes, nothing unexpected). 9.3 with the real CLI (`--jobs-dir`): Build check →
  no-op rebuild apply on OpenLink → ticket download (245 919 bytes, same SHA-256 as the
  output) → restart → both jobs listed with results, "Download APK" shown and working,
  re-applying the old preview refused (409). 9.4: Morphe 2.0.0 bundle (194 patches, 13
  with options) → "Clone app" with `packageName=com.example.openlink.clone`,
  `updateProviders=false` from the form → Morphe SUCCESS, output package
  `com.example.openlink.clone`; Analyze OpenLink → Open in Remediate → 2 privacy findings
  (G-REM-001/002/003 offered). AI explain: `apkforge explain` on the OpenLink analysis
  with a local Ollama model (`qwen2.5-coder:7b`, OpenAI-compatible); the Claude backend
  was tested against a local fake server only. The Diff tab was exercised through the API and the browser
  tests only.
- Tested in Chrome only; other browsers are untested. No accessibility audit was done
  beyond semantic HTML, labelled inputs and tab roles.
- The FastAPI test client logs a deprecation warning (Starlette is moving from `httpx` to
  `httpx2`).

## Code

- `src/apkforge/gui/app.py`: `create_app(token, modkit_config=...)`, the guard middleware
  and the API.
- `src/apkforge/gui/jobs.py`: `JobManager` (thread pool, last 200 jobs; with `store=DIR`
  each job is also a JSON file, reloaded at start).
- `src/apkforge/gui/changes.py`: the 9.2 preview/apply routes and their checks.
- `src/apkforge/gui/references.py`: the H.1 summary (one pass over the evidence) and the
  call-site lookup.
- `src/apkforge/gui/static/`: `index.html` + `app.js` (no build step).
- Cancellation: `apkforge.modkit.process.CANCEL_EVENT` (a context variable the job thread
  sets; the process runner polls it).
- Tests: `tests/unit/test_gui.py` (token/Host guard, headers, path validation, analyze,
  diff, ModKit run with secret masking, chain, job errors, cancel, upload, patch listing,
  apply gating: unchanged APK, applicable preview, once only, new output path; modifier
  dry run → apply on the simulated Phase D toolchain; plan and verify read-only; H.4 needs
  a verified transformation apply; reference counts agree with `assess_absence`, call-site
  targets use the H.6 syntax; declared changes and planned files reach `verify_pair`).
  `tests/integration/test_gui_browser.py`: the page in headless Chromium/Chrome.
