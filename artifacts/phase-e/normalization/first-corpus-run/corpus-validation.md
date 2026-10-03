# Phase E: content-aware no-op baseline and corpus validation

Generated 2026-10-03T03:10:27.428463+00:00. Toolchain: apktool 3.0.3, build-tools 35.0.0, java 25.0.4.1, zipalign 35.0.0, apksigner 0.9, android-35; normalization schema 1, semantic schema 2; APKForge fda21291a158a23d95d79c85dc5bf0ab94a131e1 (dirty: True).

Per APK: no-op rebuild #1 establishes the fingerprint; no-op rebuild #2 checks per-entry determinism, fingerprint reproducibility and is verified against the fingerprint with `verify_pair` (structural, apksigner, normalized/semantic/security diff).

| APK | result | fingerprint (exact / path_only / signer) | rebuild #2 content diffs | reproducible | pair verification | drift vs C.5 |
|---|---|---|---:|---|---|---|
| com.emanuelef.remote_capture@95 | EQUIVALENT_WITH_RESIDUE | 2236 / 5 / 1 | 0 | True | VERIFIED | none |
| com.oF2pks.applicationsinfo@19 | EQUIVALENT_WITH_RESIDUE | 36 / 5 / 1 | 0 | True | VERIFIED | none |
| de.audioattack.openlink@28 | EQUIVALENT | 68 / 5 / 1 | 0 | True | VERIFIED | none |
| de.danoeh.antennapod@3120295 | NOT_EQUIVALENT | 1408 / 5 / 1 | 0 | True | FAILED | result EQUIVALENT_WITH_RESIDUE -> NOT_EQUIVALENT |
| eu.siacs.conversations@4218104 | EQUIVALENT | 1234 / 5 / 1 | 0 | True | VERIFIED | none |
| godau.fynn.usagedirect@10 | EQUIVALENT | 470 / 5 / 1 | 0 | True | VERIFIED | none |
| io.github.muntashirakon.AppManager@451 | EQUIVALENT_WITH_RESIDUE | 1457 / 5 / 1 | 0 | True | VERIFIED | none |
| org.mozilla.fennec_fdroid@1560020 | UNDETERMINED | 2512 / 5 / 1 | 0 | True | FAILED | none |
| org.schabi.newpipe@1015 | EQUIVALENT | 1086 / 5 / 1 | 0 | True | VERIFIED | none |

## Incomplete comparators (no-op diff)

- com.emanuelef.remote_capture@95: {'resource_table': 'not_comparable'}
- com.oF2pks.applicationsinfo@19: {'resource_table': 'not_comparable'}
- de.audioattack.openlink@28: {'resource_table': 'not_comparable'}
- de.danoeh.antennapod@3120295: {'resource_table': 'not_comparable'}
- eu.siacs.conversations@4218104: {'resource_table': 'not_comparable'}
- godau.fynn.usagedirect@10: {'resource_table': 'not_comparable'}
- io.github.muntashirakon.AppManager@451: {'resource_table': 'not_comparable'}
- org.mozilla.fennec_fdroid@1560020: {'resource_table': 'not_comparable', 'embedded': 'partial'}
- org.schabi.newpipe@1015: {'resource_table': 'not_comparable'}

## Pair verification details

- com.emanuelef.remote_capture@95: VERIFIED — every applicable check passed
- com.oF2pks.applicationsinfo@19: VERIFIED — every applicable check passed
- de.audioattack.openlink@28: VERIFIED — every applicable check passed
- de.danoeh.antennapod@3120295: FAILED — failed: unexpected_changes, security_diff
  - unexpected ['manifest_element modified application[name=de.danoeh.antennapod.PodcastApp]/provider[name=androidx.core.content.FileProvider]@android:authorities']; unknown []; diff []
- eu.siacs.conversations@4218104: VERIFIED — every applicable check passed
- godau.fynn.usagedirect@10: VERIFIED — every applicable check passed
- io.github.muntashirakon.AppManager@451: VERIFIED — every applicable check passed
- org.mozilla.fennec_fdroid@1560020: FAILED — failed: unexpected_changes
  - unexpected []; unknown []; diff ['diff status is partial, not complete']
- org.schabi.newpipe@1015: VERIFIED — every applicable check passed

## Rule policies

- `signature_replaced`: path_only
- `certificate_replaced`: signer
- `dex_reencoded`: exact
- `dex_compiler_marker_removed`: exact
- `manifest_reencoded`: exact
- `resource_table_reencoded`: exact
- `resource_reencoded`: exact
- `resource_path_canonicalized`: exact
- `manifest_resource_path_canonicalized`: exact
- `baseline_residue`: exact
