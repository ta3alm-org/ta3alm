# Ta3alm Platform — Security & Video System Test Report

**Report Date:** 2026-11-13  
**Important Execution Environment Note:** In this session, shell command execution (`run_command`) was unavailable because the harness working directory was mapped to non-existent `d:\work\ta3alm` while the repository resides at `F:\work\ta3alm`.
During user-executed runs prior to the final fixes:
- `flutter pub get` succeeded and `flutter test test/video_security_test.dart` passed (`+6` tests).
- Three blockers were identified and patched directly in source:
  1. `api_v1/views_admin.py`: replaced obsolete `ZohoMailToken` / `dashboard_admin.zoho_service` imports and usages with `ZohoMailConfig` and `services.zoho_mail_service.ZohoMailService`.
  2. `api_v1/migrations/0001_initial.py`: updated `('teachers', '__first__')` to `('teachers', '__latest__')` so `teachers.coursepackage` resolves during `migrate` and test DB creation.
  3. `flutter_app/lib/features/lectures/widgets/ta3alm_video_player.dart`: replaced invalid `Colors.black65` / `Colors.black70` constants with `const Color(0xA6000000)` and `const Color(0xB3000000)`.

Because `run_command` could not execute locally after these final patches, re-run the verification commands in Section 3 locally before tagging a production release.

---

## 1. Authored Django Security & Video Test Suite (`api_v1/tests_video_security.py`)

| Test Case | Security & Functional Coverage | Execution Status |
|---|---|---|
| `test_unenrolled_student_cannot_authorize_video` | Verifies unenrolled students receive `403` and generate `authorize_denied` audit logs. | Authored — Run Locally |
| `test_video_code_activation_and_raw_url_suppression` | Verifies VideoCode activation gating, raw `video_link` stripping (`""`), short-lived HS256 `playback_token` claims, and non-sensitive masked watermark payload. | Authored — Run Locally |
| `test_legacy_youtube_lecture_separated_explicitly` | Verifies unmigrated lectures return `source_type='ta3alm_shield'`, omit `youtube_video_id` (`None`) and `legacy_external_url` (`""`), hide `youtube.com` from serialized JSON, and seal the reference in `sealed_video_ref` verifiable only with the active `session_id` + `playback_token`. | Authored — Run Locally |
| `test_concurrent_session_revocation_on_second_device` | Verifies `device-B` login revokes `device-A`'s active `PlaybackSession`, `heartbeat` from `device-A` fails with `409 SESSION_REVOKED`, and `device-B` refreshes tokens cleanly. | Authored — Run Locally |
| `test_progress_resume_continue_watching_and_bookmarks` | Verifies `/progress/` auto-completion at `>= 90%`, preferred playback speed sync, `/continue-watching/`, and bookmark create/delete CRUD. | Authored — Run Locally |
| `test_play_integrity_challenge_replay_and_policy_enforcement` | Verifies single-use `PlayIntegrityNonce` (`NONCE_ALREADY_USED` on replay), `block` decision on Frida signal even in debug mode, and `403 INTEGRITY_REQUIRED` when blocked device attempts video playback. | Authored — Run Locally |
| `test_unenrolled_student_cannot_access_progress_or_bookmarks_and_position_is_clamped` | Verifies `_user_can_access_lecture_metadata` rejects unenrolled students with `403` on `/progress/` and `/bookmarks/`, and verifies `position_seconds` is clamped `<= duration_seconds`. | Authored — Run Locally |

---

## 2. Authored Flutter Unit & Widget Tests

### `flutter_app/test/video_security_test.dart`
- `formatVideoDuration`: Validates MM:SS and H:MM:SS output formatting.
- `ParsedSubtitleFile`: Validates WebVTT timestamp parsing, multi-line cues, and HTML tag stripping.
- `VideoAuthorizationPayload.fromJson`: Validates protected HLS authorization payload, `qualityVariants`, `subtitleTracks`, `introSkip`, `progress`, `bookmarks`, and previous/next lecture navigation.
- Legacy YouTube separation test: Validates `youtube_legacy` parsing with `isNativeProtected == false`, plus `progress` resume and `bookmarks` fields.
- `unsealVideoReference` & `resolveShieldedVideoId`: Validates HMAC-SHA256 + XOR CTR session-bound decryption of `sealed_video_ref` and rejection of mismatched sessions or tampered MAC tags.
- `extractYoutubeVideoId`: Validates 11-character YouTube ID extraction across `youtube.com/watch?v=`, `youtu.be/`, `/embed/`, `/shorts/`, raw IDs, and rejection of non-YouTube URLs.
- `Ta3almPlayerHandle`: Validates `attach`, `currentPosition`, `seekTo`, and `detach` delegation shared by `Ta3almNativeVideoPlayer` and `Ta3almYoutubePlayer` (`youtube_player_iframe`).
- `AppIntegrityGuard.buildRequestHash`: Validates deterministic SHA-256 hash generation matching backend expectation.
- `DynamicWatermarkOverlay`: Widget test confirming watermark text renders inside `IgnorePointer` without intercepting gestures.

### `flutter_app/test/widget_test.dart`
- Updated obsolete stock `MyApp` test to `Ta3almNativeApp` wrapped in `ProviderScope`.

---

## 3. Verification Commands to Run Locally

```powershell
# 1. Django migrations & video security tests
cd F:\work\ta3alm
python manage.py migrate
python manage.py check
python manage.py test api_v1.tests_video_security

# 2. Flutter dependencies, static analysis, unit/widget tests & APK build check
cd F:\work\ta3alm\flutter_app
flutter pub get
flutter analyze
flutter test
flutter build apk --release --dart-define=API_BASE_URL=https://www.ta3alm.online/api/v1
```

