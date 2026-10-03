# Phase G Evidence Artifacts: Controlled Privacy/Security Remediation

This directory contains inspectable, reproducible evidence artifacts for Phase G.

## Contents
- `remediation-catalog.md`: Auditable definition of supported and conditional remediations.
- `corpus-summary.json` & `corpus-summary.md`: Aggregate execution results across all 9 corpus APKs.
- `toolchain-info.md`: Exact system and toolchain versions.
- `test-logs.txt`: Consolidated execution logs across all quality gates and test suites.
- `corpus/`: Per-APK before/plan/apply/verification/comparison artifacts.

## Architectural Guarantees Demonstrated
1. **Explicit Separation**: Finding -> Evidence -> Candidate -> Plan -> Approval -> Modification -> Build -> Verification -> Report.
2. **Strict Approval Gate**: No APK is modified without explicit approval (`--apply` / `approved=True`).
3. **Original Byte-Identical Integrity**: Original APK SHA-256 is verified unchanged before, during, and after every run.
4. **Truthful Outcome States**: Partial remediation (e.g. permission removed but DEX code remains) is explicitly reported as `PARTIALLY_REMEDIATED`.
5. **Zero Assumptions of Safety**: Successful remediation does not claim the APK is 'malware-free' or 'safe'.
