# Ta3alm Platform — Video Player Security & Shielded Unlisted Playback Report

**Repository:** `F:\work\ta3alm` & `F:\work\ta3alm\flutter_app`  
**Scope:** Branded Ta3alm player shell over YouTube IFrame API, session-bound URL sealing (`sealed_video_ref`), raw URL suppression, playback session governance, and honest threat-model boundaries.

---

## 1. Custom Ta3alm Player Shell (`Ta3almYoutubePlayer`)

- **Widget:** `Ta3almYoutubePlayer` in [ta3alm_youtube_player.dart](file:///F:/work/ta3alm/flutter_app/lib/features/lectures/widgets/ta3alm_youtube_player.dart)
- **Underlying Engine:** `youtube_player_iframe: ^5.2.1` ([pubspec.yaml](file:///F:/work/ta3alm/flutter_app/pubspec.yaml#L32))
- **Player Isolation & Controls:**
  - Configured with `showControls: false`, `showFullscreenButton: false`, `playsInline: true`, `strictRelatedVideos: true` to hide native Share / Watch-on-YouTube / Copy-Link controls.
  - Transparent interactive tap-shield (`GestureDetector` over the 16:9 stage) captures single tap (play/pause), double tap left/right (`-10s` / `+10s`), and blocks long-press context actions inside the player frame.
  - Floating anti-screen-recording watermark (`DynamicWatermarkOverlay` displaying `studentCode • maskedPhone • sessionTag`) renders on top of the active player frame via `IgnorePointer`.
  - Complete custom Ta3alm control bar renders below the frame: interactive seek `Slider`, elapsed/total time, Play/Pause, `-10s` / `+10s` skip, Mute/Unmute, playback speed (`0.5x`–`2x` synced to `/progress/`), and custom Ta3alm Fullscreen landscape mode without reloading the iframe.
  - Zero external "Open on YouTube" links or buttons exist in `Ta3almYoutubePlayer` or `_ExternalVideoFallbackCard` ([lecture_player_screen.dart](file:///F:/work/ta3alm/flutter_app/lib/features/lectures/presentation/lecture_player_screen.dart)).

---

## 2. Session-Bound Reference Sealing (`sealed_video_ref`) & Backend Protections

Implemented in [video_security.py](file:///F:/work/ta3alm/api_v1/video_security.py), [views_video.py](file:///F:/work/ta3alm/api_v1/views_video.py), and [serializers.py](file:///F:/work/ta3alm/api_v1/serializers.py):

| Layer | Implementation Details |
|---|---|
| **Raw URL Suppression** | `resolve_signed_playback_source` returns `legacy_external_url: ''` and `youtube_video_id: None`. `LectureSerializer.to_representation` strips `video_link: ''` whenever `for_student=True` or `hide_raw_url_for_student=True`. |
| **Session-Bound Encryption & HMAC (`sealed_video_ref`)** | `seal_video_reference` encrypts `<video_id>|<exp>` using an HMAC-SHA256 CTR keystream keyed from `HMAC(playback_token, "ta3alm-yt-seal|<session_id>")` plus a 16-byte MAC tag. Flutter unseals strictly in RAM inside `unsealVideoReference` ([video_playback_models.dart](file:///F:/work/ta3alm/flutter_app/lib/features/lectures/models/video_playback_models.dart)). |
| **Entitlement & Code Gating** | `_user_can_access_lecture_metadata` and `_check_user_lecture_entitlement` enforce active enrollment / package ownership, `VideoCode` activation, per-code view limits, and `PlayIntegrity` checks before issuing sessions. |
| **Single-Device Enforcement** | Opening a lecture revokes prior active `PlaybackSession` rows; active periodic heartbeats return `409 SESSION_REVOKED` on superseded devices, pausing playback immediately. |
| **Rate Limiting & Progress Validation** | `VideoProgressThrottle` (`60/min`) limits `VideoProgressAPIView` and `VideoBookmarksAPIView`; `position_seconds` is clamped server-side to `duration_seconds`. |
| **Android Screen Security** | `PlatformSecurityService` applies Android `FLAG_SECURE` and `FLAG_KEEP_SCREEN_ON` during playback ([MainActivity.kt](file:///F:/work/ta3alm/flutter_app/android/app/src/main/kotlin/online/ta3alm/ta3alm_flutter/MainActivity.kt)). |

---

## 3. Honest Threat-Model Boundaries (No Budget / YouTube-Hosted Content)

- **What this strongly protects against:** Plaintext URL scraping from Django JSON APIs (`youtube.com` URLs do not appear in `/videos/<id>/authorize/` responses), casual UI sharing/copying inside the app, multi-device account sharing, unauthorized bookmark/progress tampering, and casual Android screen recording (`FLAG_SECURE` + moving `DynamicWatermarkOverlay`).
- **Inherent limitation while hosted on YouTube:** Because video bytes still stream from YouTube inside the iframe/WebView, a technical attacker inspecting low-level browser DevTools Network traffic on Web or instrumenting WebView traffic on a compromised rooted device can still observe the request to YouTube. Eliminating YouTube visibility at the network layer requires migrating master `.mp4` files to private HLS hosting (e.g., Bunny Stream or Cloudflare Stream) as documented in [VIDEO_MIGRATION_PLAN.md](file:///F:/work/ta3alm/VIDEO_MIGRATION_PLAN.md).
