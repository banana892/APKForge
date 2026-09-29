"""APKForge analysis package.

Phase 1+ will implement analysis modules here.

Each module will be a :class:`~apkforge.core.plugins.AnalyzerPlugin` that
accepts a workspace and returns an :class:`~apkforge.core.models.AnalysisResult`.

Planned modules (Phase 1+):
- manifest: AndroidManifest.xml analysis
- permissions: Permission usage and over-privilege detection
- dex: DEX file structure analysis
- strings: String extraction and pattern matching
- certificates: APK signing certificate analysis
- native: Native library (.so) analysis
"""
