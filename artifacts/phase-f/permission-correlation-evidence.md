# Permission & Component Static Correlation Evidence

Phase F strictly separates mere permission declaration from verified bytecode invocation.
Where permissions are declared without matching API or component references, the status `DECLARED_ONLY` is reported with explicit uncertainty.

## Correlation Categories
- **STRONG_CORRELATION**: Both manifest permission and framework APIs / components observed.
- **DECLARED_ONLY**: Permission declared in `AndroidManifest.xml`, but no static bytecode call was found.
- **API_WITHOUT_PERMISSION**: Framework API called without manifest permission (often optional or unprivileged).

## Declared Permissions Without Static Correlation by APK

### `com.oF2pks.applicationsinfo_19.apk` (com.oF2pks.applicationsinfo)
- Declared Permissions: 4
- Declared Without Static Code Correlation: 0

### `de.audioattack.openlink_28.apk` (de.audioattack.openlink)
- Declared Permissions: 2
- Declared Without Static Code Correlation: 0

### `com.emanuelef.remote_capture_95.apk` (com.emanuelef.remote_capture)
- Declared Permissions: 13
- Declared Without Static Code Correlation: 0

### `de.danoeh.antennapod_3120295.apk` (de.danoeh.antennapod)
- Declared Permissions: 11
- Declared Without Static Code Correlation: 1

### `eu.siacs.conversations_4218104.apk` (eu.siacs.conversations)
- Declared Permissions: 51
- Declared Without Static Code Correlation: 4

### `godau.fynn.usagedirect_10.apk` (godau.fynn.usagedirect)
- Declared Permissions: 2
- Declared Without Static Code Correlation: 0

### `io.github.muntashirakon.AppManager_451.apk` (io.github.muntashirakon.AppManager)
- Declared Permissions: 63
- Declared Without Static Code Correlation: 0

### `org.mozilla.fennec_fdroid_1560020.apk` (org.mozilla.fennec_fdroid)
- Declared Permissions: 32
- Declared Without Static Code Correlation: 2

### `org.schabi.newpipe_1015_cb84069.apk` (org.schabi.newpipe)
- Declared Permissions: 11
- Declared Without Static Code Correlation: 0
