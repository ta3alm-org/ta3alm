# Anti-Account-Sharing System Report — Ta3alm Platform

## 1. Threat Model & Detection Strategy
Account sharing in educational platforms typically manifests not as a single anomalous login, but as overlapping usage across distinct physical devices or distant locations. Ta3alm avoids harsh false-positive auto-bans on weak signals (such as shifting mobile IPs) and instead correlates simultaneous session, playback, geographical, and revocation-cycling indicators.

---

## 2. Account-Sharing Indicators Monitored
Implemented in `detect_account_sharing` (`api_v1/device_security_service.py`) and integrated into protected lecture authorization (`VideoAuthorizeAPIView` in `api_v1/views_video.py`):

1. **Excessive Simultaneous Device Sessions:**
   - Queries active non-expired `DeviceSession` records for the user across distinct `installation_id` values and compares against `SecurityPolicyConfig.max_concurrent_sessions` (default `2`).
   - Exceeding this emits the `excessive_simultaneous_sessions` signal.
2. **Distant Simultaneous Active Locations:**
   - Aggregates server-observed country codes across currently active `DeviceSession` rows plus the incoming request's country code (`extract_network_context`).
   - Multiple active countries in overlapping sessions emits `distant_simultaneous_locations`.
3. **Concurrent Protected Playback Across Multiple Devices:**
   - Queries active `PlaybackSession` rows with heartbeats within the last 2 minutes (`last_heartbeat_at >= now - 2m`) and compares unique playback device IDs against `SecurityPolicyConfig.max_concurrent_playback` (default `1`).
   - Exceeding this emits `concurrent_playback_multiple_devices`.
4. **Account Switching & Revocation/Registration Churn:**
   - Evaluated inside `evaluate_and_apply_risk`:
     - `distinct_accounts_on_device >= 3` triggers `frequent_account_switching_on_device` (`+35`).
     - `>= 3` `device_revoked` / `device_limit_reached` events within 7 days triggers `repeated_registration_revocation_cycle` (`+25`).

---

## 3. Graduated Configurable Response Policies
Because false positives harm paying students on shared household Wi-Fi or mobile carriers, enforcement escalates proportionally with correlated evidence:

1. **Single Signal Detected (`len(signals) == 1`):**
   - Logs `DeviceSecurityEvent` (`event_type='account_sharing_suspected'`, `severity='medium'`, `action_taken='session_monitored_and_notified'`).
   - Sends an informative `Notification` advising the student of concurrent activity without breaking playback.
2. **Correlated Strong Evidence (`len(signals) >= 2` during protected video authorization):**
   - `VideoAuthorizeAPIView` logs the high-severity event and blocks protected stream issuance with **HTTP 403 (`code: 'ACCOUNT_SHARING_RESTRICTED'`)**.
   - Surfaces the alert in the Admin Security Dashboard (`sharing_alerts` panel on `/admin-panel/security/`).
3. **Additional Graduated Administrative & Automated Responses Supported:**
   - Individual session revocation (`POST /api/v1/security/sessions/` or admin `revoke_session`).
   - Reauthentication challenge (`force_reauth`, setting `requires_reauth=True` resolved via `SecurityDeviceVerifyAPIView`).
   - Temporary content restriction (`trust_status='restricted'`).
   - Administrator escalation and full session termination (`revoke_all_user_sessions` or temporary/permanent `DeviceBlock`).
   - Permanent account ban is **never** triggered automatically by `detect_account_sharing`.

