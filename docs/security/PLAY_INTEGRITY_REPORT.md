# Ta3alm Platform — Google Play Integrity API Report

**Scope:** Server-side integrity challenge, Android Standard Integrity token request, verdict verification, replay defense, and environment-aware risk policy.

---

## 1. End-to-End Verification Flow

1. **Challenge Issuance (`PlayIntegrityNonce`):**
   - Backend function `issue_integrity_challenge` in [integrity_service.py](file:///F:/work/ta3alm/api_v1/integrity_service.py#L47-L57) creates a single-use `PlayIntegrityNonce` with `NONCE_TTL_SECONDS = 300` and precomputes `expected_request_hash = SHA-256("ta3alm|{action}|{binding_data}|{nonce_id}")`.
   - Flutter client computes the identical hash locally in `AppIntegrityGuard.buildRequestHash` ([video_security_test.dart](file:///F:/work/ta3alm/flutter_app/test/video_security_test.dart#L112-L125)).
2. **Android Standard Integrity Token Request (`PlayIntegrityBridge`):**
   - Implemented in [PlayIntegrityBridge.kt](file:///F:/work/ta3alm/flutter_app/android/app/src/main/kotlin/online/ta3alm/ta3alm_flutter/PlayIntegrityBridge.kt) using Google Play `StandardIntegrityManager` (`prepareIntegrityToken` warm-up + `request` with `setRequestHash`).
   - Configured via `BuildConfig.PLAY_CLOUD_PROJECT_NUMBER` from env var `TA3ALM_PLAY_CLOUD_PROJECT_NUMBER` in [build.gradle.kts](file:///F:/work/ta3alm/flutter_app/android/app/build.gradle.kts#L49-L50).
   - If `BuildConfig.PLAY_CLOUD_PROJECT_NUMBER <= 0L`, returns structured `CLOUD_PROJECT_NOT_CONFIGURED` so callers degrade cleanly according to server policy.
3. **Server-Side Token Decoding (`decode_token_with_google_api`):**
   - Backend verifies the integrity token via Google's `playintegrity` `v1.decodeIntegrityToken` API using Service Account credentials (`PLAY_INTEGRITY_SERVICE_ACCOUNT_JSON` or `GOOGLE_APPLICATION_CREDENTIALS`).
   - Client verdict is **never trusted on its own**.
4. **Replay & Freshness Checks (`verify_and_record_integrity`):**
   - Looks up `PlayIntegrityNonce` with `select_for_update()` inside `@transaction.atomic`.
   - Rejects unknown (`INVALID_NONCE`), already-used (`NONCE_ALREADY_USED` + logs critical `token_replayed` event), and expired (`NONCE_EXPIRED`) nonces.
   - Verifies `requestPackageName` matches `PLAY_INTEGRITY_PACKAGE_NAME` (default `online.ta3alm.ta3alm_flutter`), verifies `requestHash`, and rejects tokens older than `MAX_TOKEN_AGE_SECONDS = 300` (`stale_integrity_token`).

---

## 2. Verdict Evaluation & Policy Modes

Evaluated server-side in `evaluate_integrity_payload` ([integrity_service.py](file:///F:/work/ta3alm/api_v1/integrity_service.py#L92-L189)):

- **Verdicts Inspected:**
  - `appRecognitionVerdict` (`PLAY_RECOGNIZED`, `UNRECOGNIZED_VERSION`, `UNEVALUATED`)
  - `deviceRecognitionVerdict` (`MEETS_STRONG_INTEGRITY`, `MEETS_DEVICE_INTEGRITY`, `MEETS_BASIC_INTEGRITY`)
  - `appLicensingVerdict`
  - Optional release signing digest comparison (`ANDROID_RELEASE_CERT_SHA256` vs `apk_cert_sha256` -> sets `signature_mismatch` if mismatched on non-debug builds)
- **Configurable Policies (`PLAY_INTEGRITY_POLICY_MODE`):**
  - `strict`: Allows only `risk_level == 'low'`, `appRecognitionVerdict == 'PLAY_RECOGNIZED'`, and `MEETS_DEVICE_INTEGRITY` or `MEETS_STRONG_INTEGRITY`. Blocks everything else.
  - `balanced` *(default when `DEBUG=False`)*: Blocks critical risks (`package_name_mismatch`, `request_hash_mismatch`, Frida/hooking, APK signature mismatch) and `UNRECOGNIZED_VERSION` / empty device verdicts; warns/steps up on basic-only verdicts.
  - `audit`: Logs risks and returns `warn` instead of blocking (for phased rollout monitoring).
  - `dev_bypass` *(default when `DEBUG=True`)*: Allows local debug/emulator development when Play Store credentials are absent, **except** confirmed `frida_detected`/`hooking_detected` or `signature_mismatch` still result in `block`.

Every verification outcome persists to `DeviceIntegrityRecord` and logs to `VideoSecurityAuditLog`. Blocked devices receive `403 INTEGRITY_REQUIRED` on subsequent playback authorization.

---

## 3. Production Deployment Prerequisites

To enforce full `strict` / `balanced` Play Integrity in production:
1. Set `TA3ALM_PLAY_CLOUD_PROJECT_NUMBER` when building the release APK/AAB.
2. Link the release app and upload SHA-256 signing certificate fingerprint in Google Play Console + set `ANDROID_RELEASE_CERT_SHA256` on Django.
3. Provide Google Service Account credentials via `PLAY_INTEGRITY_SERVICE_ACCOUNT_JSON` or `GOOGLE_APPLICATION_CREDENTIALS` with Play Integrity API enabled.
4. Set `PLAY_INTEGRITY_POLICY_MODE=balanced` (or `strict` after rollout validation).

