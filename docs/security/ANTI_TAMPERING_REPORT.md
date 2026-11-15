# Ta3alm Platform — Android Anti-Tampering & Hardening Report

**Scope:** Defense-in-depth runtime telemetry, release signing separation, R8/ProGuard code shrinking, and honest operational limits.

---

## 1. Release Build & Obfuscation Hardening

Configured in [build.gradle.kts](file:///F:/work/ta3alm/flutter_app/android/app/build.gradle.kts) and [proguard-rules.pro](file:///F:/work/ta3alm/flutter_app/android/app/proguard-rules.pro):

- **Debug vs Release Isolation:**
  - `debug` builds use `applicationIdSuffix = ".debug"` and `isMinifyEnabled = false`.
  - `release` builds enable `isMinifyEnabled = true`, `isShrinkResources = true`, `proguard-android-optimize.txt`, custom `proguard-rules.pro`, and `ndk { debugSymbolLevel = "SYMBOL_TABLE" }`.
- **ProGuard / R8 Rules (`proguard-rules.pro`):**
  - Preserves Flutter engine/embedding, `MainActivity` platform channel entrypoint, `com.google.android.play.core.integrity.**`, and `androidx.media3.**` while allowing obfuscation of internal helpers.
  - Strips verbose Android debug logging calls (`android.util.Log.v`, `d`, `i`, `isLoggable`) in release builds via `-assumenosideeffects`.
- **Release Signing Key Hygiene:**
  - Credentials load from git-ignored `android/key.properties` or CI environment variables (`TA3ALM_KEYSTORE_PATH`, `TA3ALM_KEYSTORE_PASSWORD`, `TA3ALM_KEY_ALIAS`, `TA3ALM_KEY_PASSWORD`).
  - When `TA3ALM_REQUIRE_RELEASE_SIGNING=true`, Gradle fails the build if signing credentials are missing.
- **Flutter Dart Obfuscation:**
  - Documented release build flags in [ANDROID_SIGNING_GUIDE.md](file:///F:/work/ta3alm/ANDROID_SIGNING_GUIDE.md): `--obfuscate --split-debug-info=...`.

---

## 2. Runtime Tamper & Environment Telemetry (`DeviceSecurityInspector`)

Implemented in [DeviceSecurityInspector.kt](file:///F:/work/ta3alm/flutter_app/android/app/src/main/kotlin/online/ta3alm/ta3alm_flutter/DeviceSecurityInspector.kt) and transported via [platform_security_service.dart](file:///F:/work/ta3alm/flutter_app/lib/core/security/platform_security_service.dart) (`MethodChannel("online.ta3alm.ta3alm_flutter/security")`):

| Signal | Detection Method in `DeviceSecurityInspector` |
|---|---|
| `is_debug_build` | Checks `ApplicationInfo.FLAG_DEBUGGABLE` |
| `debugger_attached` | Checks `Debug.isDebuggerConnected() \|\| Debug.waitingForDebugger()` |
| `root_detected` | Checks common `su` binary paths, `test-keys` in `Build.TAGS`, and root/Xposed manager packages (`com.topjohnwu.magisk`, `de.robv.android.xposed.installer`, `org.lsposed.manager`, etc.) |
| `hooking_detected` | Scans `/proc/self/maps` and `Throwable().stackTrace` for `xposed`, `edxposed`, `lsposed`, `substrate` |
| `frida_detected` | Scans `/proc/self/maps` for `frida`, `gum-js-loop`, `gmain`, and checks local Frida TCP ports (`27042`, `27043`) |
| `emulator_detected` | Checks `Build.FINGERPRINT`, `MODEL`, `BRAND`, `DEVICE`, `PRODUCT`, `MANUFACTURER` heuristics |
| `apk_cert_sha256` | Reads app signing certificate via `GET_SIGNING_CERTIFICATES` (API 28+) / `GET_SIGNATURES` and computes lowercase SHA-256 hex |
| `installer_package` | Reads `InstallSourceInfo.installingPackageName` (API 30+) / `getInstallerPackageName` |

Note: `DeviceSecurityInspector` deliberately **does not** modify or block normal Android Developer Options system settings.

---

## 3. Window & Credential Protections

- **Screen Capture Prevention:** `MainActivity.kt` exposes `setSecureFlag` (`WindowManager.LayoutParams.FLAG_SECURE`) and `setKeepScreenOn` (`FLAG_KEEP_SCREEN_ON`) over the security MethodChannel for active lecture screens.
- **Secure Token Storage:** JWT access/refresh tokens use `FlutterSecureStorage` with Android `encryptedSharedPreferences: true` ([token_storage.dart](file:///F:/work/ta3alm/flutter_app/lib/core/storage/token_storage.dart)).
- **Server Authority:** Client tamper signals are **defense-in-depth telemetry only**; authoritative block/step-up/allow decisions are evaluated server-side in `verify_and_record_integrity` alongside Google Play Integrity verdicts.

---

## 4. Known Limitations

- **Client-Side Checks Are Bypassable on Compromised Devices:** A skilled attacker with kernel/root access and dynamic instrumentation (e.g., modified Frida ports, Zygisk hiding `/proc/self/maps`, patched APK checks) can spoof client-side telemetry. That is why Google Play Integrity server verification and backend single-session + rate-limit controls serve as the primary trust anchors.
- **Web Platform:** Browser builds (`kIsWeb`) do not execute Android `DeviceSecurityInspector` or `FLAG_SECURE`; security on web depends on HTTPS, JWT auth, server entitlements, and CORS/CSRF controls.

