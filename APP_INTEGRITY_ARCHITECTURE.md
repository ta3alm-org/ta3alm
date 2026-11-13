# Ta3alm Platform — Application Integrity & Anti-Tampering Architecture

## 1. Threat Model & Realistic Security Guarantees

Mobile clients operate on user-controlled hardware. Determined attackers with rooted devices, custom kernels, or dynamic instrumentation tools (such as Frida) can attempt to inspect or hook client-side code. Therefore, Ta3alm's integrity architecture follows **defense-in-depth** principles:

- **What this architecture enforces reliably:**
  1. Unmodified release verification and hardware-backed device/Play attestation evaluated **by the Django backend** using **Google Play Integrity API**.
  2. Cryptographic binding of every sensitive action (`video_authorize`, `app_startup`, `login`, `checkout`, `exam_start`) to a single-use server nonce and SHA-256 `requestHash`, preventing token replay.
  3. Immediate server-side session revocation, single-active-stream enforcement, short-lived playback JWTs (`180s`), and screen-capture deterrence (`FLAG_SECURE` + dynamic watermark).
- **What client-side checks do NOT claim:**
  - Client-only Kotlin root/Frida/signature checks raise the attacker's cost and supply telemetry, but **final enforcement never trusts client booleans alone**.
  - Ta3alm **never** alters, disables, or locks out a student's Android system Developer Options setting.

---

## 2. Google Play Integrity Flow (Standard API + Server Verification)

1. **Client Challenge Request (`POST /api/v1/security/integrity/challenge/`):**
   - `AppIntegrityGuard.verifyForAction()` asks Django for a fresh `nonce_id` (`5-minute TTL`) bound to `action` and `binding_data` (e.g., `lecture_id`).
   - Backend computes and stores `expected_request_hash = SHA256("ta3alm|<action>|<binding_data>|<nonce_id>")`.
2. **Android Native Token Acquisition (`PlayIntegrityBridge.kt`):**
   - Uses `com.google.android.play:integrity:1.4.0` (`StandardIntegrityManager`), warming up `prepareIntegrityToken(cloudProjectNumber)` and calling `request(requestHash)`.
   - Concurrently collects runtime telemetry (`DeviceSecurityInspector.kt`): `is_debug_build`, `debugger_attached`, `root_detected`, `frida_detected`, `hooking_detected`, `emulator_detected`, `apk_cert_sha256`, `installer_package`.
3. **Server Token Decryption & Verdict (`POST /api/v1/security/integrity/verify/`):**
   - Atomically marks `PlayIntegrityNonce.is_used = True` (`select_for_update`), rejecting replayed or expired nonces (`NONCE_ALREADY_USED` / `NONCE_EXPIRED`).
   - Calls Google Play Integrity `v1.decodeIntegrityToken` using Google Service Account credentials (`PLAY_INTEGRITY_SERVICE_ACCOUNT_JSON` or `GOOGLE_APPLICATION_CREDENTIALS`).
   - Verifies:
     - `requestDetails.requestPackageName == PLAY_INTEGRITY_PACKAGE_NAME` (`online.ta3alm.ta3alm_flutter`)
     - `requestDetails.requestHash == expected_request_hash`
     - Token age `<= 300 seconds`
     - `appIntegrity.appRecognitionVerdict` (`PLAY_RECOGNIZED` vs `UNRECOGNIZED_VERSION`)
     - `deviceIntegrity.deviceRecognitionVerdict` (`MEETS_STRONG_INTEGRITY`, `MEETS_DEVICE_INTEGRITY`, `MEETS_BASIC_INTEGRITY`)
     - Optional reference release signing SHA-256 (`ANDROID_RELEASE_CERT_SHA256`)

---

## 3. Environment-Aware Policy Matrix (`PLAY_INTEGRITY_POLICY_MODE`)

| Mode | Use Case | Play Store Release (`PLAY_RECOGNIZED`) | Play Device Integrity Missing | Debug / Internal Build | Frida / Signature Tampering |
|---|---|---|---|---|---|
| `strict` | High-security production rollout | `allow` | `block` | `block` | `block` |
| `balanced` (Prod default) | Standard production rollout | `allow` | `block` (unrecognized/none) / `warn` (basic only) | `block` unless dev flag | `block` |
| `audit` | Soft launch telemetry | `allow` | `warn` (logged) | `warn` | `warn` |
| `dev_bypass` (`DEBUG=True`) | Local Android Studio / QA | `allow` | `allow` (debug builds) | `allow` | **`block`** (even in debug if Frida or cert mismatch flagged!) |

Every decision creates a persistent `DeviceIntegrityRecord` and `VideoSecurityAuditLog` row. When `VIDEO_REQUIRE_PLAY_INTEGRITY=True` is set in production, `/api/v1/videos/<id>/authorize/` checks the latest integrity record for `device_id` and rejects blocked/missing integrity states with `403 INTEGRITY_REQUIRED`.

---

## 4. Android Screen Protection & Transport Security

1. **Android `FLAG_SECURE` (`MainActivity.kt` -> `setSecureFlag`):**
   - Automatically enabled in `Ta3almNativeVideoPlayer.initState()` and cleared in `dispose()`.
   - Blocks standard screenshots, Android system screen recorders, and recents-drawer preview thumbnails during video playback.
2. **Release Transport Security (`AndroidManifest.xml` + `res/xml/network_security_config.xml`):**
   - Global `android:usesCleartextTraffic="false"` and `android:allowBackup="false"`.
   - Production build enforces HTTPS-only with system trust anchors across `*.ta3alm.online` and all CDN endpoints (`src/main/res/xml/network_security_config.xml`).
   - Debug build variant (`src/debug/res/xml/network_security_config.xml`) permits HTTP solely for emulator/local test hosts (`10.0.2.2`, `127.0.0.1`, `localhost`).
3. **Certificate Pinning Evaluation:**
   - Static SPKI certificate pinning is intentionally **not** hardcoded into `network_security_config.xml` initially because Ta3alm's API runs on dynamic cloud/edge hosting (Vercel / Railway / Cloudflare CDN) whose leaf and intermediate certificates rotate automatically; hardcoding pins without redundant backup pins and an OTA update fallback risks bricking all installed mobile apps on routine TLS renewal.
   - If strict pinning is desired later for dedicated backend gateways, pin only root/backup CAs with >=2 independent backup SPKIs and short pin expiration dates.

