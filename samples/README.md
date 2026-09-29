# APKForge Sample APKs

This directory is for sample APK files used in integration tests.

## ⚠️ Security Notice

- **Never commit real malicious APKs** to this repository.
- Sample APKs should be minimal, purpose-built test fixtures.
- All `.apk`, `.zip`, `.jar`, `.aab` files are excluded from git by `.gitignore`.
- To add a sample for integration testing, document it here and load it
  programmatically in tests using `pytest`'s `tmp_path` fixture.

## Phase 0

No sample APKs are present in Phase 0.  Integration tests will be added
in Phase 1+ alongside the actual APK parsing implementation.
