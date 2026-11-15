# Application Tampering & Reverse-Engineering Resistance Report — Ta3alm Platform

## 1. Realistic Security Boundary Statement
An APK distributed to end-user Android devices can always be downloaded and statically inspected/decompiled offline on an attacker's workstation; **no mobile client can reliably detect offline static decompilation or claim 100% prevention of reverse engineering**. Therefore, Ta3alm's defense architecture focuses on:
1. Making static analysis non-trivial via R8/ProGuard shrinking and Flutter release symbol/Dart obfuscation.
2. Collecting runtime integrity & instrumentation indicators on Android (`DeviceSecurityInspector.kt` + Play Integrity).
3. Enforcing **all final trust, playback, and session decisions on the Django backend** (`views_video.py`, `device_security_service.py`, `integrity_service.py`), never relying on unchecked client-side pass/fail booleans alone.

---

## 2. Client-Side Build Hardening (`flutter_app/android/app/build.gradle.kts`)
- Release builds enable `isMinifyEnabled = true` and `isShrinkResources = true` with `proguard-android-optimize.txt` + `proguard-rules.pro`.
- Flutter release builds support `--obfuscate --split-debug-info=<dir>` alongside Android R8 code shrinking.
- Strict release signing guard (`TA3ALM_REQUIRE_RELEASE_SIGNING=true`) fails CI builds if production keystore credentials are absent.
- `BuildConfig.PLAY_CLOUD_PROJECT_NUMBER` wires Google Cloud project configuration cleanly for Google Play Integrity API token requests (`PlayIntegrityBridge.kt`).

---

## 3. Native Android Runtime Inspection (`DeviceSecurityInspector.kt`)
Implemented in `flutter_app/android/app/src/main/kotlin/online/ta3alm/ta3alm_flutter/DeviceSecurityInspector.kt`:
- **Package Name & Signing Certificate Verification:** Extracts `context.packageName` and runtime APK signing certificate SHA-256 via `PackageManager.GET_SIGNING_CERTIFICATES` (with fallback for pre-API 28) and transmits them for backend validation.
- **Debug Build & Debugger Detection:** Checks `ApplicationInfo.FLAG_DEBUGGABLE` and `Debug.isDebuggerConnected() || Debug.waitingForDebugger()`.
- **Root Indicators:** Inspects known `su` binary paths, build `test-keys` tags, and known root-management packages.
- **Emulator Heuristics:** Evaluates `Build.FINGERPRINT`, `MODEL`, `MANUFACTURER`, `BRAND`, `DEVICE`, `HARDWARE`, and QEMU/Goldfish properties.
- **Frida & Hooking Framework Detection:** Inspects open Frida default/alternate local ports, scans `/proc/self/maps` for Frida/gum-js-loop/Xposed/Substrate artifacts, and inspects stack traces for hooking frames.
- **Non-Restricted Display & VPN Context:** Reports external/virtual displays (`DisplayManager`), suspected recording/presentation flags, and active `NetworkInterface` TUN/PPP/VPN interfaces.

---

## 4. Server-Side Authority & Play Integrity Integration
All signals flow through three authoritative Django checkpoints:
1. **`PlayIntegrityChallengeAPIView` & `PlayIntegrityVerifyAPIView` (`api_v1/views_video.py`, `api_v1/integrity_service.py`):**
   - Issues single-use nonces (`PlayIntegrityNonce`) with server-computed expected request hashes to prevent replay attacks (`NONCE_ALREADY_USED`, `NONCE_EXPIRED`).
   - Verifies Play Integrity verdicts and evaluates tamper payloads on Django (`evaluate_integrity_payload`).
   - When `policy_decision == 'block'` or `risk_level in ('high', 'critical')`, `PlayIntegrityVerifyAPIView` immediately updates matching `RegisteredDevice` records (`trust_status = 'restricted'` / `'suspicious'`, `requires_reauth = True`) and logs a `DeviceSecurityEvent` (`integrity_verification_failed`).
2. **Authentication & Device Registration (`device_security_service.py`):**
   - `_verify_app_identity_signals` compares submitted `package_name` against `settings.ANDROID_APP_PACKAGE_NAME` and `signing_cert_sha256` against `settings.ANDROID_SIGNING_CERT_SHA256` (unexpected values add `+85` risk points immediately).
   - Frida or runtime hooking adds `+90` risk points (`CRITICAL` -> `trust_status='restricted'`), revoking active playback sessions and gating sensitive video authorization until remediated/verified.
3. **Playback Gating (`VideoAuthorizeAPIView` & `VideoHeartbeatAPIView`):**
   - Re-checks `check_device_allowed(request.user, device_id)` and `_check_required_integrity(...)` before returning any protected HLS/MP4 stream URL or refreshing playback heartbeats.

