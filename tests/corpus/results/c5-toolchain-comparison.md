# C.5 toolchain comparison: no-op round trip, Phase B toolchain vs current

Generated 2026-10-02T18:47:57.381758+00:00.

- **old**: `apkforge-toolchain:pinned` (`sha256:79434918ee5e180f89345fa73e6c14fea2d1d14e95c863e022613d0d30226379`): Apktool 2.10.0, build-tools 34.0.0, OpenJDK 17.0.20.1 (Temurin); signed with throwaway PKCS12 key generated per APK, deleted after signing.
- **current**: java 25.0.4.1, apktool 3.0.3, zipalign 35.0.0, apksigner 0.9, build_tools 35.0.0, android_platform android-35 (BuildService), from `c5-semantic-noop-baseline.json`.

Both outputs are compared with the same original by the same `DiffEngine` and classified by the same noise rules. The two toolchains are not treated as interchangeable; this records whether their no-op output differs materially.

| APK | old result | current result | classification |
|---|---|---|---|
| de.audioattack.openlink@28 | NOT_EQUIVALENT | EQUIVALENT | **DIFFERENT** |
| de.danoeh.antennapod@3120295 | NOT_EQUIVALENT | EQUIVALENT_WITH_RESIDUE | **DIFFERENT** |
| io.github.muntashirakon.AppManager@451 | NOT_EQUIVALENT | EQUIVALENT_WITH_RESIDUE | **DIFFERENT** |

## Conclusions per APK

### de.audioattack.openlink@28

- result NOT_EQUIVALENT (old) vs EQUIVALENT (current); 16 unexplained only with old toolchain, e.g. ['file removed META-INF/androidx.annotation_annotation-experimental.version', 'file removed META-INF/androidx.arch.core_core-runtime.version', 'file removed META-INF/androidx.core_core-viewtree.version', 'file removed META-INF/androidx.core_core.version', 'file removed META-INF/androidx.interpolator_interpolator.version']
- old noise rules: {'certificate_replaced': 1, 'dex_compiler_marker_removed': 1, 'dex_reencoded': 1, 'manifest_reencoded': 1, 'resource_path_canonicalized': 64, 'resource_table_reencoded': 1, 'signature_replaced': 5}
- current noise rules: {'certificate_replaced': 1, 'dex_compiler_marker_removed': 1, 'dex_reencoded': 1, 'manifest_reencoded': 1, 'resource_path_canonicalized': 64, 'resource_table_reencoded': 1, 'signature_replaced': 5}
- old unexplained: 16, current unexplained: 0
- original unchanged: True

### de.danoeh.antennapod@3120295

- result NOT_EQUIVALENT (old) vs EQUIVALENT_WITH_RESIDUE (current); 73 unexplained only with old toolchain, e.g. ['file removed META-INF/androidx.activity_activity-ktx.version', 'file removed META-INF/androidx.activity_activity.version', 'file removed META-INF/androidx.annotation_annotation-experimental.version', 'file removed META-INF/androidx.appcompat_appcompat-resources.version', 'file removed META-INF/androidx.appcompat_appcompat.version']
- old noise rules: {'certificate_replaced': 1, 'dex_compiler_marker_removed': 1, 'dex_reencoded': 3, 'manifest_reencoded': 1, 'manifest_resource_path_canonicalized': 1, 'resource_path_canonicalized': 1214, 'resource_reencoded': 183, 'resource_table_reencoded': 1, 'signature_replaced': 5}
- current noise rules: {'certificate_replaced': 1, 'dex_compiler_marker_removed': 1, 'dex_reencoded': 3, 'manifest_reencoded': 1, 'manifest_resource_path_canonicalized': 1, 'resource_path_canonicalized': 1214, 'resource_reencoded': 183, 'resource_table_reencoded': 1, 'signature_replaced': 5}
- old unexplained: 73, current unexplained: 0
- original unchanged: True

### io.github.muntashirakon.AppManager@451

- result NOT_EQUIVALENT (old) vs EQUIVALENT_WITH_RESIDUE (current); 4 unexplained only with old toolchain, e.g. ['file removed META-INF/androidx/annotation/annotation/LICENSE.txt', 'file removed META-INF/androidx/room/room-common/LICENSE.txt', 'file removed META-INF/com/android/build/gradle/app-metadata.properties', 'file removed META-INF/version-control-info.textproto']
- old noise rules: {'certificate_replaced': 1, 'dex_compiler_marker_removed': 3, 'dex_reencoded': 6, 'manifest_reencoded': 1, 'manifest_resource_path_canonicalized': 1, 'resource_path_canonicalized': 1183, 'resource_reencoded': 258, 'resource_table_reencoded': 1, 'signature_replaced': 5}
- current noise rules: {'certificate_replaced': 1, 'dex_compiler_marker_removed': 3, 'dex_reencoded': 6, 'manifest_reencoded': 1, 'manifest_resource_path_canonicalized': 1, 'resource_path_canonicalized': 1183, 'resource_reencoded': 258, 'resource_table_reencoded': 1, 'signature_replaced': 5}
- old unexplained: 4, current unexplained: 0
- original unchanged: True

