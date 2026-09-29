"""APKForge builders package.

Phase 3+ will implement APK build/repack functionality here.

Security principles:
- APKForge will NEVER execute the APK being built.
- Build output must be verified before it is delivered to the user.

Planned builders (Phase 3+):
- apktool: APKTool-based rebuild
- aapt2: Direct AAPT2-based rebuild
"""
