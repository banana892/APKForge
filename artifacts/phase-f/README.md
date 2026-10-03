# Phase F: Privacy, Tracker & Ads Intelligence Layer

- **Verification Checkpoint**: `e0d8e9b143bf15eb830ecc77dcf467b271319bcc`
- **Corpus**: 9 Reference APKs (`tests/corpus/`)
- **Total Duration**: 868.29s

## Deliverables and Artifact Index

| File | Description |
|---|---|
| [`corpus-summary.md`](corpus-summary.md) | Aggregate metrics, findings counts, and per-APK table |
| [`corpus-summary.json`](corpus-summary.json) | Full machine-readable aggregate results |
| [`sdk-catalog-evidence.md`](sdk-catalog-evidence.md) | Third-party SDK catalog matching and network disclaimers |
| [`domain-classification-evidence.md`](domain-classification-evidence.md) | Endpoint classification and raw endpoint preservation |
| [`permission-correlation-evidence.md`](permission-correlation-evidence.md) | Static permission-to-code correlation results |
| [`phase-b-comparison.md`](phase-b-comparison.md) | Systematic cross-check against Phase B security findings |
| [`known-limitations.md`](known-limitations.md) | Explicit static analysis boundaries and disclaimers |
| [`toolchain-info.md`](toolchain-info.md) | Exact environment and toolchain provenance |
| [`corpus/`](corpus/) | Per-APK structured JSON and human-readable Markdown reports |

## Key Architecture Features
1. **Evidence Provenance**: Every finding provides `evidence_locations`, `evidence_values`, and concrete file paths.
2. **Explicit States**: Analysis results distinguish `OBSERVED`, `INFERRED`, `UNKNOWN`, and `PARTIAL` states.
3. **Strict Neutrality**: No speculative 'spyware probability', 'privacy score', or safety claims based on absence of findings.
4. **No Side Effects**: Strictly read-only analysis without APK modification or execution.
