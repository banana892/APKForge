# Phase G Remediation Catalog

| ID | Name | Target Categories | Risk | Status | Description |
|---|---|---|:---:|:---:|---|
| `G-REM-001` | Disable Boot Receiver | persistence, boot_persistence | `medium` | `supported` | Disables a specified boot receiver by setting android:enabled='false' in the manifest and removing the RECEIVE_BOOT_COMPLETED uses-permission declaration. |
| `G-REM-002` | Remove Specific Permission | permission, location, contacts, camera, microphone, storage, identifiers, network | `medium` | `supported` | Removes an exact <uses-permission> declaration from AndroidManifest.xml. If static DEX code still references the associated API, post-remediation analysis truthfully reports the result as PARTIALLY_REMEDIATED. |
| `G-REM-003` | Disable Specific Manifest Component | component, activity, service, receiver, provider | `medium` | `supported` | Disables a specific activity, service, receiver, or provider in AndroidManifest.xml by setting android:enabled='false'. |
| `G-REM-004` | Remove Specific Tracker/SDK Artifact | advertising, analytics, tracking, sdk | `high` | `conditional` | Conditionally removes an identified third-party tracker/advertising SDK artifact. Phase G permits this only when class references and assets are completely isolated without cross-module code dependencies; otherwise reports UNSUPPORTED_REMEDIATION. |
