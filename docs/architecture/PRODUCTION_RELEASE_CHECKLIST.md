# Ta3alm Platform — Production Release Security & Video Checklist

Use this checklist before shipping the Android release to Google Play Console and promoting backend changes to production.

---

## 1. Backend Environment & Infrastructure
- [ ] Run database migrations: `python manage.py migrate`
- [ ] Verify Django system checks pass: `python manage.py check --deploy`
- [ ] Configure dedicated `VIDEO_SIGNING_SECRET` (distinct 64+ char random secret from `SECRET_KEY`).
- [ ] Configure private streaming provider credentials:
  - **Bunny Stream:** `BUNNY_STREAM_SECURITY_KEY`
  - **or Cloudflare Stream:** `CLOUDFLARE_STREAM_CUSTOMER_CODE`, `CLOUDFLARE_STREAM_KEY_ID`, `CLOUDFLARE_STREAM_PRIVATE_KEY_PEM`
  - **or HMAC/CloudFront CDN:** `CDN_SIGNING_SECRET`
- [ ] Configure Google Play Integrity verification credentials on Django server:
  - `PLAY_INTEGRITY_SERVICE_ACCOUNT_JSON` (or `GOOGLE_APPLICATION_CREDENTIALS`)
  - `PLAY_INTEGRITY_PACKAGE_NAME=online.ta3alm.ta3alm_flutter`
  - `PLAY_INTEGRITY_POLICY_MODE=balanced` (or `strict` after canary rollout)
  - `VIDEO_REQUIRE_PLAY_INTEGRITY=True`
  - `ANDROID_RELEASE_CERT_SHA256=<Play App Signing Certificate SHA-256>`
- [ ] Ensure `DEBUG=False`, `SECURE_SSL_REDIRECT=True`, and Redis `REDIS_URL` is active so rate-limiting/anomaly cache works across all gunicorn workers.
- [ ] Run initial video migration audit: `python manage.py audit_video_migration --create-placeholders`

---

## 2. Android & Play Console Configuration
- [ ] Generate private Upload Keystore (never stored in Git) and enable **Play App Signing** in Google Play Console.
- [ ] Link Google Cloud Project to Google Play Console and enable **Play Integrity API** + **Play Integrity Standard API** quota.
- [ ] Set `android/key.properties` or `TA3ALM_KEYSTORE_*` + `TA3ALM_REQUIRE_RELEASE_SIGNING=true` in CI.
- [ ] Pass `--dart-define=PLAY_CLOUD_PROJECT_NUMBER=<numeric-project-number>` in release builds.
- [ ] Verify `AndroidManifest.xml` keeps `android:usesCleartextTraffic="false"`, `android:allowBackup="false"`, and `res/xml/network_security_config.xml` allows HTTPS only.
- [ ] Build with `--obfuscate --split-debug-info=...` and R8 `isMinifyEnabled = true`, `isShrinkResources = true`.

---

## 3. Manual QA Device Matrix Before Go-Live
- [ ] **Group Lecture (Protected Native HLS):** Code prompt -> activation -> native player opens -> no YouTube UI -> `FLAG_SECURE` blocks screenshot -> dynamic watermark moves smoothly -> volume/brightness edge swipes work -> speed `0.5x–2.0x` persists -> quality switch preserves timestamp -> fullscreen enters landscape cleanly and prompts on exit.
- [ ] **Package Lecture:** View limit decrements safely, resume banner restores position, `Continue Watching` appears on `StudentDashboardScreen`, bookmarks seek accurately.
- [ ] **Concurrent Stream Test:** Opening the same account/lecture on Device B revokes Device A at next heartbeat (`SESSION_REVOKED`).
- [ ] **Legacy YouTube Separation Test:** Unmigrated YouTube lectures show `_LegacyYoutubeSeparatedCard` cleanly with no fake native overlay.
- [ ] **Play Integrity Internal Testing Track Test:** Verify Play Integrity returns `PLAY_RECOGNIZED` / `MEETS_DEVICE_INTEGRITY` on Google Play Internal Testing build, and verify replayed nonces return `400 NONCE_ALREADY_USED`.

