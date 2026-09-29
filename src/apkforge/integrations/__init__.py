"""APKForge integrations package.

Phase 2+ will implement integrations with external tools here.

Planned integrations (Phase 2+):
- jadx: JADX-based decompilation (read-only, no execution)
- apktool: APKTool for disassembly and rebuild
- revanced: ReVanced patch integration
- virustotal: VirusTotal hash lookup (hash only, no upload without consent)

Security note:
    Integrations must NEVER automatically submit APK data to external
    services without explicit user consent and configuration.
"""
