# Phase F Known Limitations & Static Analysis Boundaries

Phase F is a static intelligence and evidence layer. It adheres to strict analytical boundaries:

1. **Static Presence != Dynamic Execution**: Bytecode references, class files, and strings indicate that code is packaged in the APK. They do not prove that code is executed or invoked during runtime.
2. **Static Endpoints != Network Transmission**: Extracted URLs and domains indicate configured endpoints. They do not establish that data is actually sent to or received from those endpoints.
3. **Code Obfuscation / Reflection**: ProGuard/R8 renamed classes and reflection-based invocations cannot always be mapped to known catalog signatures without dynamic tracing or symbol deobfuscation.
4. **Native Code (JNI / NDK)**: Privacy-relevant operations performed entirely in compiled C/C++ shared objects (`.so`) are not indexed by Java/DEX opcode scanners.
5. **Dynamic Code Loading**: `DexClassLoader` or reflection can load code from external files or memory that is invisible during static inspection. Phase F flags the dynamic loading capability itself.
6. **No Intent Inference**: Declaring permissions or shipping advertising/analytics libraries does NOT justify labeling an application as 'malicious', 'spyware', or 'malware'.
