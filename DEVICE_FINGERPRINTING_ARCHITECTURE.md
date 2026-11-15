# Device Fingerprinting Architecture — Ta3alm Platform

## 1. Design Principles
- **Multi-Layer Non-Restricted Identity:** Never rely on a single spoofable hardware trait, and never collect restricted Android identifiers (IMEI, IMSI, MAC address, SSAID/`ANDROID_ID`, serial numbers) or user emails/usernames as device IDs.
- **Installation-Anchored Primary Identity:** Every app install generates an opaque, cryptographically random installation identifier (`inst_<64 hex chars>`, 256-bit entropy via `Random.secure()` in Dart) stored inside Android Keystore-backed `FlutterSecureStorage` (`ta3alm_installation_id_v1`).
- **Server-Controlled Versioned Fingerprinting:** Clients submit normalized, permitted device characteristics; Django (`api_v1/device_security_service.py`) normalizes traits, computes keyed `HMAC-SHA256` fingerprints (`fp_v1`), detects benign vs suspicious drift, and preserves historical fingerprints across updates.

---

## 2. Layer 1 — Cryptographic Installation Identity
Implemented in:
- `flutter_app/lib/core/authentication/token_storage.dart` (`TokenStorage.getOrCreateInstallationId`)
- `flutter_app/lib/core/storage/preferences_storage.dart` (`PreferencesStorage.getOrCreateDeviceId` delegating to `TokenStorage`)
- `flutter_app/lib/core/networking/dio_client.dart` (injects `X-Device-Id` header on API calls and `installation_id` on token refresh)

Behavior:
1. Generated once on first app launch via 32 random bytes (`Random.secure()`) formatted as `inst_<64 lowercase hex characters>`.
2. Stored in `FlutterSecureStorage` (`EncryptedSharedPreferences`) under `_kInstallationIdKey = 'ta3alm_installation_id_v1'`.
3. **Preserved on logout:** `TokenStorage.clearTokens()` deletes JWT `access`, `refresh`, and `drf_token`, while intentionally retaining `_kInstallationIdKey` so the same physical installation keeps continuity across logouts/logins.
4. **Reset on uninstall / clear data:** Clearing app storage or reinstalling triggers a new `installation_id`, which Django handles via explicit device slot accounting rather than silent overwrites.
5. **Server Validation:** `validate_installation_id` in `api_v1/device_security_service.py` enforces regex `^[A-Za-z0-9._:-]+$`, length 8..128, rejects any value containing `@`, and explicitly rejects matching the user's `username` or `email`.

---

## 3. Layer 2 — Permitted Device Characteristics (15 Signal Groups)
Collected natively in Kotlin by `DeviceSecurityInspector.collectSignals(context)` (`flutter_app/android/app/src/main/kotlin/online/ta3alm/ta3alm_flutter/DeviceSecurityInspector.kt`) and transported via `DeviceTamperSignals.toDeviceInfoPayload()` (`flutter_app/lib/core/security/platform_security_service.dart`):

| # | Characteristic | Source / Android API | Classification |
|---|---|---|---|
| 1 | Manufacturer | `Build.MANUFACTURER` | Core hardware trait |
| 2 | Model | `Build.MODEL` | Core hardware trait |
| 3 | Android OS version | `Build.VERSION.RELEASE` | Benign update trait |
| 4 | Android API level | `Build.VERSION.SDK_INT` | Benign update trait |
| 5 | CPU architecture / ABIs | `Build.SUPPORTED_ABIS` | Core hardware trait |
| 6 | Available CPU summary | `/proc/cpuinfo` (Hardware / Processor / Core count) | Supporting signal |
| 7 | GPU renderer | Cached OpenGL ES (`EGL14` / `GLES20.GL_RENDERER`) | Supporting signal |
| 8 | GPU vendor | Cached OpenGL ES (`EGL14` / `GLES20.GL_VENDOR`) | Supporting signal |
| 9 | Screen resolution | `context.resources.displayMetrics` (`WxH@Ddp`) | Supporting signal |
| 10 | Application version | `PackageInfo.versionName` | Benign update trait |
| 11 | Application build number | `PackageInfoCompat` / `longVersionCode` | Benign update trait |
| 12 | Application package name | `context.packageName` | Integrity identity trait |
| 13 | App signing certificate digest | `PackageManager.GET_SIGNING_CERTIFICATES` (SHA-256) | Integrity identity trait |
| 14 | Installation source | `PackageManager.getInstallSourceInfo` / installer package | Integrity signal |
| 15 | Security & runtime signals | Debuggable, Debugger, Root indicators, Emulator heuristics, Frida/Xposed maps & ports, Active VPN interface, External/virtual displays | Risk signal |

Notice:
- CPU & GPU traits are treated strictly as **supporting risk signals** (never sole hardware locks), cached in memory (`@Volatile private var cachedGpuInfo`) to avoid main-thread EGL initialization overhead on repeat calls.
- Restricted identifiers (`imei`, `mac_address`, `android_id` / SSAID) are neither requested natively nor accepted into normalized trait storage (`normalize_device_info` drops unrecognized keys).

---

## 4. Layer 3 — Server-Side Versioned Fingerprint Engine (`fp_v1`)
Implemented in `api_v1/device_security_service.py` (`generate_versioned_fingerprint`) and persisted in `api_v1.models.DeviceFingerprint`:

- **Key Derivation:** `_fingerprint_secret()` computes SHA-256 over `ta3alm-device-fp-key:<DEVICE_FINGERPRINT_SECRET or SECRET_KEY>`.
- **Dual-Component Hashing:**
  - `core_hash = HMAC-SHA256(secret, "fp_v1|installation_id|manufacturer|model|cpu_arch|package_name")`
  - `supporting_hash = HMAC-SHA256(secret, "android_version|api_level|cpu_info|gpu_renderer|gpu_vendor|screen_resolution|app_version|app_build_number|signing_cert_sha256|installer_source")`
  - `fingerprint_hash = "fp_v1:" + HMAC-SHA256(secret, "fp_v1:{core_hash}:{supporting_hash}")`
- **Fingerprint Versioning & History:** Every change in normalized fingerprint creates a historical `DeviceFingerprint` record (preserving `is_current=False` prior rows rather than overwriting). When `algorithm_version` is upgraded (`fp_v2` in future releases), old records remain queryable alongside new records.

---

## 5. Drift Detection: Benign Changes vs Suspicious Mutations
When a new login or registration arrives for an existing `installation_id`, `generate_versioned_fingerprint` compares current normalized traits against the latest `DeviceFingerprint`:

- **Benign Drift (`BENIGN_DRIFT_FIELDS`):** Changes in `android_version`, `api_level`, `app_version`, `app_build_number`, `installer_source`, `screen_resolution`, `gpu_renderer`, `gpu_vendor`, or `cpu_info` without core mismatch add a minimal drift note (`drift_score <= 10`). They **never** flag the device as malicious or consume a new device slot.
- **Core Hardware / App Identity Mismatch:**
  - Changing `manufacturer`, `model`, or `cpu_arch` triggers `core_mismatch = True` (`+55` drift score, `+45` risk points).
  - Changing `signing_cert_sha256` adds `+45` drift points.
  - Changing `package_name` adds `+40` drift points.
- Suspicious transitions create a `DeviceSecurityEvent` (`core_hardware_fingerprint_mismatch`, `unexpected_signing_certificate`, or `unexpected_package_name`) for auditability while correlating with other risk signals before applying temporary restrictions.

