# Ta3alm Platform — Native Secure Video Player Architecture

**Status:** Implemented across Django REST API (`api_v1/`) and Flutter Native Client (`flutter_app/`).

---

## 1. Core Architectural Principle: Strict Source Separation

Ta3alm enforces a strict boundary between **platform-owned protected streaming assets** and **unmigrated legacy YouTube lectures**:

1. **Protected Platform Native Content (`is_native_protected = true`):**
   - Rendered exclusively inside `Ta3almNativeVideoPlayer` (`flutter_app/lib/features/lectures/widgets/ta3alm_video_player.dart`) backed by `video_player` (AndroidX Media3 / ExoPlayer).
   - Zero YouTube branding, zero YouTube iframes/WebViews, zero external browser redirects, and raw origin URLs are stripped from student payloads (`LectureSerializer.to_representation`).
   - Delivered via short-lived signed HLS (`.m3u8`), DASH (`.mpd`), or private tokenized MP4 URLs issued by `/api/v1/videos/<lecture_id>/authorize/`.

2. **Legacy Unmigrated YouTube Lectures (`source_type = youtube_legacy`):**
   - Handled exclusively by `_LegacyYoutubeSeparatedCard` (`flutter_app/lib/features/lectures/presentation/lecture_player_screen.dart`).
   - Never overlays fake native controls on top of an embedded YouTube view and never strips YouTube branding, preserving compliance with YouTube API Terms of Service until each video is migrated via `VIDEO_MIGRATION_PLAN.md`.

---

## 2. Backend Streaming & Session Security (`api_v1/`)

### 2.1 Database Models (`api_v1/models.py`, `api_v1/migrations/0001_initial.py`)
- **`VideoAsset`:** Maps `teachers.Lecture` (OneToOne) to streaming provider metadata (`cloudflare_stream`, `bunny_stream`, `aws_cloudfront`, `internal`, or `youtube`), signed `manifest_url`, `quality_variants`, `subtitle_tracks`, optional DRM settings (`drm_enabled`, `drm_scheme`, `drm_license_url`), `intro_start_seconds`/`intro_end_seconds`, `duration_seconds`, and `migration_status`.
- **`PlaybackSession`:** UUID `session_id`, `user`, `lecture`, optional `course_package`, `device_id`, `token_jti`, `integrity_verdict`, `status` (`active`, `ended`, `revoked`, `expired`), `last_heartbeat_at`, `expires_at`, `ip_address`.
- **`VideoProgress`:** Per `(user, lecture)` resume cursor (`position_seconds`), `duration_seconds`, cumulative `watched_seconds`, `progress_percent`, `is_completed` (auto-marked at `>= 90%`), and `preferred_speed`.
- **`VideoBookmark`:** Personal timestamped bookmarks (`timestamp_seconds`, `title`, `note`).
- **`VideoSecurityAuditLog`:** Structured security audit trail for authorizations, denials, concurrent session revocations, token replays, rapid-request anomalies, and integrity blocks.

### 2.2 Authorization, Token Signing & Heartbeat Flow
```
Flutter Client                      Django API (/api/v1/)                  CDN / Private Origin
     │                                       │                                     │
     ├─1. Play Integrity Challenge & Verify─▶│ (Verifies token + nonce + policy)   │
     ├─2. POST /videos/{id}/authorize/ ─────▶│                                     │
     │    (lecture_id, package_id/code,      ├─ Checks VideoCode / PackageEnroll   │
     │     device_id)                        ├─ Anomaly check (5-min rate window)  │
     │                                       ├─ Revokes older active sessions (>1) │
     │◀── session_id, playback_token (180s), ┼─ Issues HS256 JWT + Signed HLS URL  │
     │    watermark, progress, bookmarks,    │                                     │
     │    attachments, prev/next lecture     │                                     │
     │                                       │                                     │
     ├─3. HLS/MP4 Stream Fetch ──────────────┼────────────────────────────────────▶│
     ├─4. Periodic POST /heartbeat/ (25s) ──▶├─ Validates session still active     │
     │◀── renewed playback_token / 409 REVOKED                                     │
     ├─5. Periodic POST /progress/ (15s) ───▶├─ Saves resume timestamp & speed     │
     └─6. Dispose: POST /sessions/{sid}/revoke/                                    │
```

### 2.3 Endpoints Exposed (`api_v1/urls.py`)
- `GET/POST /api/v1/videos/<lecture_id>/authorize/` (`VideoAuthorizeThrottle`: `30/min`)
- `POST /api/v1/videos/<lecture_id>/heartbeat/` (`VideoHeartbeatThrottle`: `120/min`)
- `GET/POST /api/v1/videos/<lecture_id>/progress/`
- `GET /api/v1/videos/continue-watching/`
- `GET/POST /api/v1/videos/<lecture_id>/bookmarks/` & `DELETE /api/v1/videos/bookmarks/<bookmark_id>/`
- `POST /api/v1/videos/sessions/<uuid:session_id>/revoke/`
- `GET /api/v1/videos/stream/<str:playback_token>/` (signed HTTP `Range` stream proxy for local/private media with `Cache-Control: no-store, private`)

---

## 3. Flutter Native Player Features & Controls

Implemented in `Ta3almNativeVideoPlayer` (`ta3alm_video_player.dart`) and `LecturePlayerScreen` (`lecture_player_screen.dart`):

| Feature | Implementation Detail |
|---|---|
| **Playback Core** | Play/Pause, Rewind 10s, Forward 10s, Interactive LTR Seek Bar, Current/Duration Timestamps |
| **Speed Control** | `0.5x`, `0.75x`, `1.0x`, `1.25x`, `1.5x`, `1.75x`, `2.0x` synced to `PreferencesStorage` and `/progress/` |
| **Fullscreen & Orientation** | Seamless shared-controller fullscreen push, locked landscape (`landscapeLeft`/`Right`), `immersiveSticky`, confirmation dialog (`PopScope`) on exit, orientation restored cleanly |
| **Volume & Brightness** | Inline volume slider + mute button; Android native `WindowManager` brightness & `AudioManager` stream volume via right/left vertical edge drag zones (`dx > 72%` / `dx < 28%`) with HUD indicator |
| **Adaptive & Manual Quality** | Auto adaptive `.m3u8` default + backend-provided `qualityVariants` (`360p`, `480p`, `720p`, `1080p`) preserving playback position & play state |
| **Subtitles** | `ParsedSubtitleFile` (`ClosedCaptionFile`) parsing WebVTT (`.vtt`) and SRT (`.srt`) files |
| **Educational UX** | Resume playback banner, Skip Intro button (`introSkip`), Progress % indicator, Continue Watching section on `StudentDashboardScreen`, Timestamped Bookmarks, Lecture Attachments (`PdfViewerScreen`), Previous/Next Lecture buttons |
| **Content Protection** | Android `FLAG_SECURE` + `FLAG_KEEP_SCREEN_ON` automatically enabled while mounted; `DynamicWatermarkOverlay` renders moving non-sensitive `student_code • ***phone • session_tag` |

---

## 4. DRM & Offline Reality Assessment

- **Signed HLS vs Widevine DRM:** Signed HLS URLs prevent trivial link sharing and hotlinking, while AES-128 HLS encrypts segments in transit/cache against casual downloaders. True hardware-backed key protection against memory dumping or HDMI capture requires **Widevine L1 / FairPlay DRM** (`VideoAsset.drm_enabled = True`, `drm_license_url` configured with Cloudflare Stream / Bunny / DRMtoday).
- **Offline Downloads:** Disabled by default for protected lessons (`Cache-Control: no-store`). No unencrypted MP4 download endpoint is exposed.

