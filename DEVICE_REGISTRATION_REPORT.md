# Device Registration & Session Architecture Report — Ta3alm Platform

## 1. Architecture Integration
Device registration integrates directly into Ta3alm's existing authentication endpoints (JWT `access`/`refresh` + DRF Token compatibility) without rebuilding user accounts or authentication workflows.

All device registration logic is centralized in:
- `api_v1/device_security_service.py` (`register_or_update_device`)
- `api_v1/authentication.py` (`generate_jwt_pair`, `JWTAndTokenAuthentication._enforce_device_and_session`)
- `api_v1/views_auth.py` (`LoginAPIView`, `RegisterAPIView`, `GoogleLoginAPIView`, `OneTimeLoginAPIView`, `TokenRefreshAPIView`, `LogoutAPIView`, `_handle_auth_device_registration`)
- `api_v1/views_security.py` (`SecurityDeviceRegisterAPIView`)
- `flutter_app/lib/features/auth/providers/auth_provider.dart`

---

## 2. Database Models (`api_v1/models.py`)
1. **`RegisteredDevice`** — Represents a registered user installation (`unique_together = ('user', 'installation_id')`):
   - Identity & hardware traits (`device_uuid`, `installation_id`, `device_name`, `manufacturer`, `model`, `os_name`, `android_version`, `api_level`, `cpu_arch`, `cpu_info`, `gpu_renderer`, `gpu_vendor`, `screen_resolution`, `app_version`, `app_build_number`, `package_name`, `signing_cert_sha256`, `signing_cert_verified`, `installer_source`).
   - Trust & risk metadata (`trust_status` via `DeviceTrustStatus`: `trusted`, `pending`, `suspicious`, `restricted`, `revoked`, `blocked`; `risk_score`, `risk_level`, `requires_reauth`, `is_active`, `is_verified`).
   - Network snapshots (`last_ip`, `last_country`, `last_region`, `ip_history` bounded JSON array up to 20 entries).
2. **`DeviceFingerprint`** — Immutable versioned fingerprint trail linked to `RegisteredDevice` (`algorithm_version`, `fingerprint_hash`, `core_hash`, `supporting_hash`, `normalized_traits`, `drift_score`, `drift_notes`, `is_current`).
3. **`DeviceSession`** — Per-device authenticated session (`session_uuid`, `device`, `installation_id`, `access_jti`, `refresh_jti`, `status` [`active`, `logged_out`, `revoked`, `expired`], IP/country/region/ISP/VPN snapshot, `started_at`, `last_seen_at`, `expires_at`).
4. **`DeviceActivity`** — Granular behavioral ledger (`device_registered`, `device_login`, `login_failed`, `token_refresh`, `device_reverified`, `lecture_access`, client capture events, etc.) storing server-observed IP & metadata.
5. **`DeviceSecurityEvent`** — Correlated security alerts and investigations (`event_uuid`, `event_type`, `severity`, `risk_score`, `action_taken`, `investigation_status` [`open`, `investigating`, `resolved`, `false_positive`], reviewer attribution).
6. **`DeviceBlock`** — Explicit administrative block records (`installation_id`, optional linked `device`, `block_type` [`temporary`, `permanent`], `is_active`, `expires_at`, unblock audit fields).
7. **`SecurityPolicyConfig`** — Singleton administrative configuration controlling device limits per role, session/playback concurrency caps, behavioral risk thresholds, geo/login anomaly thresholds, retention days, and screen capture policy toggles.

---

## 3. End-to-End Registration & Session Flow
1. **Client Collection (`AuthNotifier`):** Before posting credentials to `LoginAPIView`, `RegisterAPIView`, `GoogleLoginAPIView`, or `OneTimeLoginAPIView`, Flutter calls `DeviceSecurityService.instance.buildAuthSecurityPayload()`, attaching:
   - `installation_id` (`inst_<64-hex>` from `TokenStorage`)
   - `device_info` (15 permitted native Android traits + runtime integrity signals from `DeviceSecurityInspector.kt`)
2. **JWT JTI Generation (`generate_jwt_pair`):** Access and refresh JWTs embed unique UUID identifiers (`jti`).
3. **Server Validation & Policy Gate (`register_or_update_device` inside `@transaction.atomic`):**
   - Validates `installation_id` (rejecting email/username or malformed values).
   - Evaluates `get_active_device_block(installation_id)` — rejects blocked devices with HTTP 403 (`DEVICE_BLOCKED`) and logs `blocked_device_attempt`.
   - Acquires a row lock (`select_for_update()`) on active `RegisteredDevice` records for the user and checks `get_user_device_limit(user)` when registering a new slot (returns HTTP 403 `DEVICE_LIMIT_REACHED` without touching existing devices).
   - Normalizes traits, computes `fp_v1` fingerprint & drift, records a `DeviceFingerprint` row when traits evolve, analyzes IP transition, runs `evaluate_and_apply_risk`, creates/refreshes an active `DeviceSession`, and logs `DeviceActivity`.
4. **Continuous Session & Device Enforcement (`JWTAndTokenAuthentication`):**
   - Every authenticated API request checks `X-Device-Id` (or `HTTP_X_INSTALLATION_ID`) and JWT `jti`:
     - Any active `DeviceBlock` or `RegisteredDevice` in `blocked`/`revoked` status, or revoked/logged-out `DeviceSession`, immediately fails authentication (`AuthenticationFailed`).
   - `TokenRefreshAPIView` rejects refresh requests when the associated `DeviceSession` or `RegisteredDevice` is revoked/blocked, and checks rapid refresh frequency.
   - `LogoutAPIView` marks matching active `DeviceSession` records as `logged_out` with `ended_at` timestamp while retaining the `RegisteredDevice` slot for future legitimate re-logins from that installation.
5. **Startup Verification:** On app launch (`AuthNotifier.initialize`), if stored tokens exist, Flutter invokes `refreshProfile()` and `POST /api/v1/security/devices/register/`; if the server reports `DEVICE_BLOCKED`, `DEVICE_REVOKED`, or `DEVICE_LIMIT_REACHED` (403), local tokens are cleared safely.

