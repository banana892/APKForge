# Intent-filter extraction fix: before/after report

Base: `7415f67`, unmodified. Before-state runs used a detached worktree of it
(`work/intent-filter-fix-before-wt`, git-ignored). After-state runs used the working tree
with the fix (uncommitted). All runs used `PYTHONHASHSEED=0` and the `.venv-validation`
environment. Every figure below cites a file in this directory.

## Code change

`src/apkforge/inspection/manifest.py`:

- `_extract_intent_filters` no longer requires `xml.etree.ElementTree.Element`. It takes any
  element with `findall`/`get` (a typing `Protocol`), so it reads the `lxml.etree._Element`
  that Androguard returns. Its blanket `contextlib.suppress(Exception)` is removed.
- The three per-component blocks (activity/service/receiver) were each wrapped in
  `suppress(Exception)`. One helper, `_component_intent_filters`, replaces them. On any
  failure it appends `intent-filter extraction failed for <tag> <name>: <reason>` to the
  inspector warnings, which makes the manifest inspection `partial`. That covers an
  exception, a missing `<application>` and a component element that cannot be found.
  The text-XML fallback path uses the same rule (`_fallback_intent_filters`).
- **Beyond the strict minimum, flagged for review:** components are now matched to their
  element by resolved class name first, with the old simple-name match as fallback. Without
  this, AntennaPod's `androidx.media3.session.MediaButtonReceiver` would get the 2 filters of
  `de.danoeh.antennapod.playback.service.MediaButtonReceiver` instead of its own 1. The old
  matcher took the first element whose simple class name matched. This is covered by
  `test_receivers_sharing_a_simple_class_name_keep_their_own_filters`. Reverting it means
  shipping known-wrong filter data for that receiver.

Tests: `tests/unit/test_inspection_manifest_intent_filters.py`, 7 tests. They drive the
Androguard path with a real `lxml.etree._Element` tree and cover:

- an activity (VIEW, categories, `https` data with host and pathPrefix)
- a service
- a receiver with 2 filters, actions, categories and two `<data>` (scheme, mimeType)
- the duplicate simple-name case
- an extraction failure recorded per component with its reason
- an engine-level PARTIAL check (`inspector_statuses["manifest"] == "partial"`,
  `status == PARTIAL`), with a control that the same APK is `complete` without the failure

Against the pre-fix source, 6 of the 7 fail (`tests_against_prefix_src.txt`). The one that
passes only checks that the fixture tree is lxml.

## Manifest inspection, before vs after (`comparison.json`, `compare_stdout.txt`)

| APK | activities | services | receivers | components changed | status before → after |
|---|---|---|---|---:|---|
| com.emanuelef.remote_capture@95 (PCAPdroid) | 0 → 1 | 0 → 1 | 0 → 5 | 4 | complete → complete |
| com.oF2pks.applicationsinfo@19 | 0 → 1 | 0 → 0 | 0 → 0 | 1 | complete → complete |
| de.audioattack.openlink@28 | 0 → 3 | 0 → 0 | 0 → 5 | 5 | complete → complete |
| de.danoeh.antennapod@3120295 | 0 → 18 | 0 → 3 | 0 → 17 | 27 | complete → complete |
| eu.siacs.conversations@4218104 | 0 → 18 | 0 → 2 | 0 → 9 | 16 | complete → complete |
| godau.fynn.usagedirect@10 | 0 → 1 | 0 → 0 | 0 → 5 | 3 | complete → complete |
| io.github.muntashirakon.AppManager@451 | 0 → 42 | 0 → 1 | 0 → 11 | 18 | complete → complete |
| org.mozilla.fennec_fdroid@1560020 | 0 → 13 | 0 → 4 | 0 → 15 | 19 | complete → complete |
| org.schabi.newpipe@1015 | 0 → 16 | 0 → 2 | 0 → 7 | 9 | complete → complete |

Totals: 0 → 200 filters. Per-component counts are in `before|after/filter_counts.json`.

- **Independent check:** for every activity/service/receiver in all 9 APKs, each filter's
  actions, categories and `<data>` count equal what `aapt2 dump xmltree` reports
  (`aapt2_verification.json`, `all_match: true`, 200 = 200).
- No intent-filter warnings were produced.
- Apart from `intent_filters`, the manifest inspections are identical before and after
  (`non_filter_fields_identical: true` for all 9), comparing lists order-insensitively.
- **Run-to-run variation, measured rather than assumed:** component and permission list
  order varies between two runs of the same code (`before/rerun_noise_check/`,
  `after/rerun_noise_check/`). The comparison therefore keys components by name.

## Security findings, three reviewed apps (`comparison.json` → `security`)

Noise reference: two runs of the same code differ only in the evidence sampling or order
of `SEC-SPY-CLIPBOARD-001` and `SEC-MAL-PERSISTENCE-FG-SERVICE` in PCAPdroid/AppManager,
and of `SEC-MAL-BOOT-001` after the fix (`comparison.json` → `noise`, known-limitations
§15). No run-to-run change in ids, severity or confidence.

| app | finding | change | cause |
|---|---|---|---|
| OpenLink | — | 5 → 5, none added or removed | |
| OpenLink | `SEC-MAL-PERSISTENCE-BOOT` | confidence high → **confirmed**; evidence +`Boot startup broadcast receiver: de.audioattack.openlink.conf.PackageChangeBroadcastReceiver` | `PersistenceAnalyzer` returns CONFIRMED when a receiver has a BOOT_COMPLETED filter |
| PCAPdroid | `SEC-MAL-BOOT-001` | **added** (medium / high) | rule `all: boot_receiver: true, component_type: service`; `boot_receiver` needs filter actions |
| PCAPdroid | `SEC-MAL-PERSISTENCE-BOOT` | confidence high → **confirmed**; evidence +`com.emanuelef.remote_capture.BootReceiver` | as above |
| AppManager | `SEC-MAL-BOOT-001` | **added** (medium / high) | as above |
| AppManager | `SEC-MAL-PERSISTENCE-BOOT` | confidence high → **confirmed**; evidence +`io.github.muntashirakon.AppManager.self.BootReceiver` | as above |
| AppManager | `SEC-MAL-PERSISTENCE-FG-SERVICE`, `SEC-SPY-CLIPBOARD-001` | evidence sample/order only | same variation between two pre-fix runs: noise, not the fix |

None were removed, and no severity changed.

### Classification of new findings

**PCAPdroid `SEC-MAL-BOOT-001`: true positive.** `com.emanuelef.remote_capture.BootReceiver`
declares BOOT_COMPLETED (aapt2, `aapt2_verification.json`). Its `onReceive` reads
`Prefs.startAtBoot`, calls `VpnService.prepare` and starts a service with `startService`
or `startForegroundService` (`boot_receiver_xrefs.json`). The rule's claim holds: a boot
receiver plus a service it starts.

**AppManager `SEC-MAL-BOOT-001`: true positive.**
`io.github.muntashirakon.AppManager.self.BootReceiver` declares BOOT_COMPLETED (aapt2).
Its `onReceive` calls `ContextCompat.startForegroundService` and
`InternalCacheCleanerService.scheduleAlarm` (`boot_receiver_xrefs.json`).

Precision caveats on both, which affect evidence quality, not the verdict:

- the rule duplicates `SEC-MAL-PERSISTENCE-BOOT` (PRC-04 pattern)
- its evidence location `manifest:receiver:BOOT_COMPLETED` does not name the receiver
- it lists every declared service, not the one started, for example AppManager's
  `NoRootAccessibilityService`

The earlier review counted PRC-04 duplicates as true positives, and this keeps that
convention.

### Precision re-baseline (`precision.json`)

Same method as `findings_review_post_prc.md`: FP / total findings. Retained findings keep
their hand-review verdict from `artifacts/security-validation/findings_review.json`.

| | findings | TP | FP | unclear | FP rate |
|---|---:|---:|---:|---:|---:|
| pre-fix inspector (reproduces the published 11.9%) | 42 | 35 | 5 | 2 | 11.9% |
| post-fix inspector | 44 | 37 | 5 | 2 | 11.4% |

Per app after the fix: OpenLink 0/5, PCAPdroid 2/10 (20.0%), AppManager 3/29 (10.3%).

Side observation, not edited: `findings_review_post_prc.md` gives AppManager's FP rate as
"17.9% (5/28)". Its own per-finding verdicts give 3/28. The 5 FPs overall are 2 in
PCAPdroid and 3 in AppManager.

## Capability corpus, 9 APKs (`tests/corpus_runner.py`; `corpus_comparison.json`)

- **Verdicts:** 96 PASS / 3 PARTIAL before and after. No verdict changed, and the 3
  PARTIALs are Fennec, as before. Diff pairs are unchanged.
- **Field changes:** all trace to the new filter data (`other_apps.json`,
  `new_domains_vs_aapt2_hosts.json`).
- **Security counts:**
  - PCAPdroid +1 and AppManager +1: `SEC-MAL-BOOT-001`, covered above.
  - AntennaPod +1 and NewPipe +1: `SEC-MAL-BOOT-001`.
  - Conversations +2 and Fennec +2: `SEC-MAL-BOOT-001` plus **`SEC-COMB-PERSISTENT-LOC`
    (HIGH)**, boot receiver + location permissions/API.

  These are not hand-reviewed because they are outside the three reviewed apps.
  `SEC-MAL-PERSISTENCE-BOOT` moves high → confirmed in all four.
- **Network and privacy:** AntennaPod domains 47 → 48 and privacy endpoints 94 → 95;
  NewPipe 98 → 111 domains and 233 → 246 endpoints. Every added domain is an intent-filter
  `android:host` per aapt2 (`all_are_aapt2_intent_filter_hosts: true`). They reach the
  network inspector through `InspectionEngine`'s existing manifest-strings path, which
  feeds activity filter hosts in. They are deep-link hosts, not hosts the app is shown to
  contact (recorded as a limitation).

## C.5 (`c5_comparison.json`, `before|after/c5/`, `after/c5/openlink_filter_check.json`)

- **Semantic no-op baseline:** identical before vs after after removing timestamps and
  paths. The 9 verdicts are 4 EQUIVALENT, 4 EQUIVALENT_WITH_RESIDUE and Fennec
  UNDETERMINED; noise counts and residue are the same, with 0 unexpected and 0 unknown.
  Rebuilding the APKs does not change their intent filters, so no new observations
  appeared.
- **OpenLink acceptance:** VERIFIED before and after.
  - Classification is `expected_modification` 2 (RECEIVE_BOOT_COMPLETED removed;
    PackageChangeBroadcastReceiver enabled true → false), `rebuild_noise` 74,
    `unexpected` 0, `unknown` 0. Stages all PASS, original SHA-256 preserved.
  - The only non-volatile differences are stage log paths (different checkout) and the
    resolved apktool path. The worktree lacks the untracked `tools/apktool_3.0.3.jar`, so
    the wrapper on `PATH` was used; both report apktool 3.0.3.
- **Filter data in the diff:**
  - DiffEngine's inspections of the original and modified OpenLink now carry 8 filters
    each (aapt2 also counts 8 in the modified APK). The target receiver keeps
    `[BOOT_COMPLETED, MY_PACKAGE_REPLACED]` with `enabled` true → false.
  - The modification doesn't touch filters, so `intent_filter_diff` is correctly absent.
  - Positive control: removing BOOT_COMPLETED from the modified side in memory makes
    `ComponentDiffer` report `actions_removed: [android.intent.action.BOOT_COMPLETED]`.
    Before the fix this could not fire, because both sides had 0 filters
    (`before/manifest_de.audioattack.openlink_28.json`).

## Static analysis and tests

- **ruff check src tests:** 77 issues before and after. The only new one during the work,
  an unused `noqa`, was removed. `manifest.py`'s remaining SIM114 already fails at HEAD
  (`ruff_before.txt`, `ruff_after.txt`).
- **ruff format:** both touched files are formatted. The 28 pre-existing unformatted files
  are unchanged (`ruff_format_*.txt`).
- **mypy src:** 111 → 107 errors, none new; 4 removed in `manifest.py`
  (`mypy_before.txt`, `mypy_after.txt`).
- **pytest:** 656 passed, including the 9 opt-in corpus build tests
  (`APKFORGE_CORPUS_BUILD=1`, `pytest_full_with_corpus.txt`).
- **Pre-existing order-dependent failure:** `test_cli_inspect_json_contains_all_phase2_fields`
  fails when only `tests/unit/test_inspection_engine.py` is run, on unmodified HEAD too.
  It passes alone and in the full suite (`order_dependent_cli_test.txt`). Not caused by this
  change, and not fixed.

## Baselines

- **Not regenerated, because their content did not change:** the C.5 no-op baseline, the
  C.5 OpenLink result and the C.4 build baseline (BuildService does not use the inspector).
- **`tests/corpus_results.json`:** restored to HEAD after the runner overwrote it. A fresh
  pre-fix run already differs from it in 7 unrelated fields (native_libraries,
  modification_planning). Updating it would mix that drift into this change. Decision for
  the reviewer.
- **`tests/corpus_results_baseline.json`:** untouched. It differs from current pre-fix
  output in 25 verdicts, so it is not maintained against current code.
- **`docs/known-limitations.md`:** gets a new "Status update — intent-filter extraction fix
  (§16)" section. §6, §16 and the historical reports are not edited.

## Scripts

`capture.py`, `capture_other.py`, `compare.py`, `compare_c5.py`, `compare_corpus.py`,
`verify_with_aapt2.py`, `boot_receiver_xrefs.py`, `openlink_filter_check.py`, `precision.py`.
