# Behavioral Analytics, IP Intelligence & Risk Scoring Report — Ta3alm Platform

## 1. Server-Side IP Intelligence & Network Analysis
Implemented in `api_v1/device_security_service.py` (`get_server_observed_ip`, `extract_network_context`, `analyze_ip_transition`):
- **Server-Observed Authority:** All IP addresses are extracted directly by Django from verified connection metadata (`REMOTE_ADDR`, reverse-proxy headers `HTTP_CF_IPCOUNTRY`, `HTTP_X_FORWARDED_FOR`, `HTTP_X_REAL_IP`). Self-reported client IP fields are ignored.
- **Persistent IP History:**
  - `DeviceActivity` logs connection IP, country, region, ISP, and VPN/proxy signal across authentication and educational actions (`device_registered`, `device_login`, `login_failed`, `token_refresh`, `lecture_access`, capture/integrity events).
  - `RegisteredDevice.ip_history` stores a bounded chronological history (up to 20 distinct network transitions with `ip`, `country`, `region`, `isp`, `vpn`, and ISO timestamp).
  - `DeviceSession` snapshots `ip_address`, `country_code`, `region_name`, `isp_name`, and `is_vpn_or_proxy` per authenticated session.
- **Mobile Network, Carrier-Grade NAT (CGNAT), Dynamic IP & VPN Resilience:**
  - `analyze_ip_transition` distinguishes between **same-country dynamic IP / cellular tower changes** (`same_country_dynamic_ip=True`) and **rapid cross-country geographical jumps** (`country != prev_country` within `<= 60` minutes -> `rapid_geo_transition=True`).
  - Users are **never** permanently banned solely for dynamic IPs or toggling a VPN (`vpn_or_proxy_signal` contributes only `+10` risk points, far below medium/high restriction thresholds).

---

## 2. Monitored Behavioral Signals
Engineered across `views_auth.py`, `views_video.py`, `views_security.py`, and `device_security_service.py`:

1. **Authentication Behavior:**
   - Repeated failed logins per user or source IP within 10/15 minutes (`login_failed` activity + `excessive_login_attempts` alert at `>= 5` failures).
   - Unusual device registration counts & device-limit hits (`device_limit_reached`).
   - Multiple simultaneous active `DeviceSession` records across different installations (`excessive_concurrent_sessions`).
   - Account hopping (`distinct_accounts_on_device >= 3` on a single `installation_id`).
   - Rapid token refresh loops (`token_refresh` velocity tracking).
2. **Educational Activity:**
   - High-frequency lecture authorization attempts (`detect_and_record_anomaly` rate anomaly -> HTTP 429).
   - Concurrent playback attempts across distinct devices (`PlaybackSession` checks in `detect_account_sharing`).
   - Repeated protected-stream requests and playback authorizations (`lecture_access` logging).
3. **Device & Application Runtime Behavior:**
   - Core hardware drift (`core_mismatch`: manufacturer, model, CPU architecture changes on the same installation).
   - Package name or signing certificate SHA-256 mismatch against expected production configuration (`ANDROID_APP_PACKAGE_NAME`, `ANDROID_SIGNING_CERT_SHA256`).
   - Debugger, root indicators, emulator environment, Xposed hooking, or Frida instrumentation indicators (`_verify_app_identity_signals`).
   - Client-reported screen capture/recording events (`SecurityEventReportAPIView`).

---

## 3. Correlated Risk Scoring Engine & Thresholds
Implemented in `evaluate_and_apply_risk` (`api_v1/device_security_service.py`), using runtime-configurable thresholds from `SecurityPolicyConfig`:

| Risk Level | Default Threshold | Weighted Multi-Signal Behavior | Automatic Response |
|---|---|---|---|
| **LOW** | `< 30` (`risk_threshold_medium = 30`) | Normal activity, OTA OS update, app version upgrade, same-country mobile IP change | Allowed (`trust_status = 'trusted'`), routine activity recorded |
| **MEDIUM** | `>= 30` and `< 60` (`risk_threshold_high = 60`) | Elevated weak signals (e.g., repeated failed logins, VPN + emulator, rapid geo jump) | Monitored (`DeviceSecurityEvent` severity `medium`), no lockout |
| **HIGH** | `>= 60` and `< 85` (`risk_threshold_critical = 85`) | Multiple correlated indicators (e.g., core fingerprint drift + geo jump, or debugger/capture warnings) | Flagged `suspicious` (`trust_status = 'suspicious'`), student alert created |
| **CRITICAL** | `>= 85` | Strong abuse/tamper evidence (Frida/hooking `+90`, cert mismatch `+85`, package mismatch `+85`, or combined multi-signal score `>= 85`) | Temporary restriction (`trust_status = 'restricted'`, `requires_reauth = True`), active playback sessions revoked, high/critical admin review event generated |

Notice: Single weak indicators (dynamic mobile IP change `+0`, isolated VPN `+10`, root alone `+20`, emulator alone `+15`, benign OTA OS/app update `+3..10`) stay well below `HIGH`/`CRITICAL` thresholds, preventing false-positive student lockouts.

---

## 4. Privacy & Data Minimization Boundaries
The analytics engine collects **zero** keystrokes, microphone audio, SMS, call logs, contacts, photos, or precise GPS coordinates (`ACCESS_FINE_LOCATION` is not used). All retention limits obey `SecurityPolicyConfig.event_retention_days` (default 90 days) via `prune_expired_telemetry()`.

