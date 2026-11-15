# Device Limits & Trusted-Device Management Report — Ta3alm Platform

## 1. Configurable Role-Based Device Limits
Limits are stored dynamically in PostgreSQL/SQLite via the singleton model `SecurityPolicyConfig` (`api_v1/models.py`), initialized from Django settings defaults when present and editable at runtime via:
- Django HTML Admin Security Dashboard (`/admin-panel/security/`)
- Admin REST API (`POST /api/v1/security/admin/actions/` with `action='update_policy_config'`)

Default role limits (`get_user_device_limit` in `api_v1/device_security_service.py`):
- **Student (`student`):** `student_device_limit` = **2 devices**
- **Teacher (`teacher`):** `teacher_device_limit` = **3 devices**
- **Assistant (`assistant`):** `assistant_device_limit` = **3 devices**
- **Platform Admin (`admin` / superuser):** configurable (`max(student_device_limit, 5)`)

Policy toggles (`SecurityPolicyConfig.enforce_device_limits`): allows administrators to enforce or temporarily relax device-slot locking during maintenance migrations without code redeployment.

---

## 2. Non-Destructive Limit Enforcement (No Silent Overwrite)
When an account attempts to authenticate from a new `installation_id` (or re-activate a previously revoked installation) and active non-revoked/non-blocked devices already equal or exceed `get_user_device_limit(user)`:
1. **No Silent Replacement:** Existing `RegisteredDevice` rows and their active `DeviceSession` rows remain completely untouched.
2. **Explicit Structured Denial:** Backend returns **HTTP 403 Forbidden** with:
   - `code: 'DEVICE_LIMIT_REACHED'`
   - `error`: Arabic guidance explaining the configured limit and how to remove an old device
   - `device_limit` and `active_devices_count`
   - `devices`: sanitized list of currently registered devices
3. **Audit & Notification:** Logs a `device_limit_reached` `DeviceSecurityEvent` and sends an in-app `Notification` informing the student of the attempted new device login.

---

## 3. Authorized Device Controls & Anti-IDOR Enforcement
Users manage their own devices via `GET /api/v1/security/devices/` and `POST /api/v1/security/devices/<device_id>/revoke/`:
- **`revoke`:** Marks `RegisteredDevice.trust_status = 'revoked'`, sets `is_active = False`, records `revoked_at` and `revoked_reason`, terminates all active `DeviceSession` rows (`status='revoked'`), frees the device slot immediately, and logs a `device_revoked` `DeviceSecurityEvent`.
- **`logout`:** Ends all active `DeviceSession` records (`status='logged_out'`) without permanently revoking the trusted slot.
- **`report_unfamiliar`:** Marks `unfamiliar_reported = True`, sets `trust_status = 'restricted'`, `requires_reauth = True`, revokes active sessions immediately, escalates a `high`-severity `unfamiliar_device_reported` `DeviceSecurityEvent`, and creates a `DeviceBlock` when appropriate or escalates to administrator review.
- **`verify` (`POST /api/v1/security/devices/<device_id>/verify/`):** Allows restoring a `restricted` or `suspicious` device (never an admin-`blocked` device) after verifying account password (or registered email for Google-only accounts).
- **Strict Anti-IDOR Check:** If an authenticated user attempts to revoke, log out, report, or verify a `device_id` belonging to another account without platform admin privileges, `SecurityDeviceRevokeAPIView` / `SecurityDeviceVerifyAPIView` immediately denies with **HTTP 403 (`FORBIDDEN_DEVICE_OWNER`)** and logs a `high`-severity `cross_account_device_idor_attempt` `DeviceSecurityEvent`.

---

## 4. Flutter Trusted-Device Management Screen
Implemented in `flutter_app/lib/features/settings/presentation/trusted_devices_screen.dart` (`TrustedDevicesScreen`), linked from `SettingsScreen` (`الأجهزة الموثوقة والأمان / Trusted Devices & Security`) and protected inside `ProtectedScreenWrapper`:
- **Overview Banner:** Displays `activeCount / deviceLimit` and explains that silent device overwrite is disabled.
- **Displayed Attributes per Device:**
  - Device name & manufacturer/model
  - Operating system (`osName androidVersion (API apiLevel)`)
  - First registration date & last active timestamp
  - Current session status (`Active Session` / `Inactive`)
  - Trust status pill (`Trusted`, `Pending`, `Suspicious`, `Restricted`, `Revoked`, `Blocked`)
  - Current-device badge (`هذا الجهاز / Current`), app version, and approximate region/country
- **User Actions:** Confirmation-guarded dialogs for **Logout Device**, **Revoke Device** (automatically logging out locally if the user revokes their current phone), **Report Unfamiliar Device** (with optional user note), and **Verify Device** when `requires_reauth` is flagged.

