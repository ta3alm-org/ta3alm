# Security Administrator Operations Guide — Ta3alm Platform

## 1. Web Admin Security Center (`/admin-panel/security/`)
Accessible exclusively to authorized platform administrators (`@moderator_required` / `can_manage_users`), linked in the sidebar (`مركز أمان الأجهزة`) at:
- **Main Dashboard:** `/admin-panel/security/` (`dashboard_admin/views.py:security_dashboard`)
- **Device Forensic Detail View:** `/admin-panel/security/devices/<device_id>/` (`security_device_detail`)
- **Action Handler:** `POST /admin-panel/security/action/` (`security_admin_action`)

### Dashboard Sections & Capabilities
1. **KPI Overview:**
   - Total registered devices, active devices, suspicious/restricted devices, active admin blocks, active `DeviceSession` count, open security events, and open critical alerts.
2. **Configurable Security Policy Form (`update_policy`):**
   - Device slot limits: `student_device_limit`, `teacher_device_limit`, `assistant_device_limit`.
   - Concurrency caps: `max_concurrent_sessions`, `max_concurrent_playback`.
   - Risk score thresholds: `risk_threshold_medium`, `risk_threshold_high`, `risk_threshold_critical`.
   - Anomaly & retention parameters: `rapid_login_threshold_5m`, `rapid_geo_kmh_threshold`, `event_retention_days`.
   - Runtime toggles: `enforce_device_limits`, `enforce_screen_capture_policy`.
   - One-click **Prune Expired Telemetry** trigger (`prune_telemetry`).
3. **Search & Filtering:**
   - Search `RegisteredDevice` by username, email, device name, model, `installation_id`, or validated IPv4/IPv6 `last_ip` (validated via `ipaddress.ip_address()` prior to ORM filtering).
   - Filter devices by `trust_status` and security events by `severity` or `investigation_status`.
4. **Device Forensic Detail (`/admin-panel/security/devices/<id>/`):**
   - Inspect versioned `DeviceFingerprint` history (including `algorithm_version`, `core_hash`, `supporting_hash`, drifted fields, and `drift_score`).
   - Review `ip_history`, active/expired `DeviceSession` records, `DeviceActivity` ledger, `DeviceSecurityEvent` history, `DeviceBlock` records, and other devices owned by the same user.

---

## 2. REST Admin Security API (`/api/v1/security/admin/actions/`)
Protected by `IsPlatformAdmin`:
- **`GET /api/v1/security/admin/actions/`**: Returns aggregate metrics and serialized `SecurityPolicyConfig`.
- **`POST /api/v1/security/admin/actions/`**: Supported `action` values:
  - `block_device`: Temporary (`duration_hours`) or permanent `DeviceBlock` by `device_id` or `installation_id`; revokes all active `DeviceSession` & `PlaybackSession` rows.
  - `unblock_device`: Deactivates active `DeviceBlock` rows and restores blocked device trust status to `trusted`.
  - `revoke_session`: Terminates a specific `DeviceSession` (`session_uuid`).
  - `revoke_all_user_sessions`: Revokes all active `DeviceSession` and `PlaybackSession` rows for `user_id`.
  - `force_reauth`: Flags a device `requires_reauth=True`, sets `trust_status='pending'`, and ends active sessions until the user re-verifies.
  - `mark_false_positive` / `update_event_status`: Moves a `DeviceSecurityEvent` to `open`, `investigating`, `resolved`, or `false_positive` (false-positive resolution automatically reduces device risk score by 40 points and restores `trusted` status when not admin-blocked).
  - `update_policy_config`: Updates singleton `SecurityPolicyConfig` fields dynamically.
  - `prune_telemetry`: Deletes stale `DeviceActivity`, resolved/false-positive `DeviceSecurityEvent`, and `VideoSecurityAuditLog` entries older than `retention_days`.

All sensitive administrative actions (`block_device`, `unblock_device`, session/device revocation, policy updates, telemetry pruning) are recorded into `dashboard_admin.models.AuditLog` using `ACTION_BLOCK_DEVICE`, `ACTION_UNBLOCK_DEVICE`, `ACTION_REVOKE_SESSION`, and `ACTION_SECURITY_POLICY`.

