# Ta3alm Platform — Video System & Security Audit

**Audit Date:** 2026-11-13  
**Scope:** Django Web Application (`teachers/`, `students/`, `core/`), Django REST Framework API (`api_v1/`), Django Templates (`templates/`), Flutter Mobile Client (`flutter_app/lib/`), and Android Build Configuration (`flutter_app/android/`).

---

## 1. Executive Summary

Prior to this remediation initiative, all lecture videos on Ta3alm relied on URL references stored directly on `teachers.models.Lecture.video_link`, primarily targeting YouTube links parsed by `Lecture.get_video_id()`. While the web template (`templates/includes/custom_video_player.html`) attempted to hide YouTube controls using click-blocking overlays and CSS watermarks, the REST API exposed raw `video_link` values to authenticated students after unlock, and the Flutter mobile app launched those URLs directly in the external browser or YouTube app via `url_launcher`.

Consequently:
- **Platform-owned video assets had zero stream protection, no DRM/signed-URL delivery, and no native player.**
- **Android builds lacked `FLAG_SECURE`, Google Play Integrity server verification, release keystore separation, R8/ProGuard obfuscation, and HTTPS-only enforcement.**

---

## 2. Django Video Models & Storage Audit

### 2.1 Existing Models Observed
| App | Model | Key Video-Related Fields | Observations |
|---|---|---|---|
| `teachers` | `Lecture` (`teachers/models.py#L99-L118`) | `group` (nullable FK), `title`, `video_link` (`URLField`), `description`, `is_active`, `created_at`; `get_video_id()` | `get_video_id()` only extracts 11-char IDs from `youtube` / `youtu.be` URLs. No native asset reference, manifest URL, duration, quality list, or subtitle fields exist. |
| `teachers` | `VideoCode` (`teachers/models.py#L123-L140`) | `lecture`, `code` (`max_length=10`, unique), `max_views`, `current_views`, `is_used`, `used_by`, `used_at` | Controls group-lecture access. Increments `current_views` on lecture load without verifying playback duration or session continuity. |
| `teachers` | `CoursePackage` (`teachers/models.py#L156-L175`) | `teacher`, `lectures` (M2M), `exams` (M2M), `pdfs` (M2M), `view_limit` (default 3) | Tracks per-package view limits across assigned lectures. |
| `students` | `PackageEnrollment` (`students/models.py#L44-L53`) | `student`, `package`, `is_paid` | Entitlement check for package purchases. |
| `students` | `VideoViewTracking` (`students/models.py#L56-L66`) | `student`, `package`, `lecture`, `views_count`, `is_completed`, `points_awarded` | Marks `is_completed = True` and awards `10` points immediately on first watch call rather than upon real watch progress (`>= 90%`). |
| `teachers` | `PDFFile` (`teachers/models.py#L142-L150`) | `group`, `title`, `link` (`URLField`) | External Drive/direct PDF links attached to groups or packages. |

### 2.2 Storage & Hosting Findings
In `ta3alm_project/settings.py#L301-L320`:
- `STORAGES["default"]` is `cloudinary_storage.storage.MediaCloudinaryStorage` (used for images such as `CoursePackage.image`, `TeacherProfile.image`, `ManualPayment.receipt_image`).
- `MEDIA_URL = '/media/'`, served locally only when `DEBUG` is enabled (`ta3alm_project/urls.py#L46-L47`).
- **Conclusion:** Videos are **not stored on disk, S3, HLS, or DASH** in the existing codebase; they are external URL strings stored in `Lecture.video_link` (almost exclusively YouTube links, or generic iframe links).

---

## 3. Existing Video API Endpoints & Permissions Audit

| Endpoint / View | Auth & Permissions | Observed Behavior & Security Gaps |
|---|---|---|
| `GET/POST /api/v1/student/lectures/<lecture_id>/watch/` (`StudentWatchGroupLectureAPIView`, `api_v1/views_student.py#L204-L286`) | `IsAuthenticated`, `IsStudentRole` + `check_student_access()` | 1. Activates `VideoCode` via `select_for_update()`.<br>2. **Gap:** Returns `LectureSerializer(lecture).data`, exposing raw `video_link` to the client.<br>3. **Gap:** Increments `current_views` unconditionally on `GET` (`record_view=true`) with no playback session token, heartbeat, or concurrent-device limit.<br>4. **Gap:** No video-specific rate limiting beyond global `3000/hour` `UserRateThrottle`. |
| `POST /api/v1/student/packages/<package_id>/lectures/<lecture_id>/watch/` (`StudentWatchPackageLectureAPIView`, `api_v1/views_student.py#L512-L551`) | `IsAuthenticated`, `IsStudentRole` + `PackageEnrollment(is_paid=True)` | 1. Checks `tracker.views_count >= package.view_limit`.<br>2. **Gap:** Exposes raw `video_link` via `LectureSerializer`.<br>3. **Gap:** Awards 10 points & consumes a view immediately before the student watches a single frame.<br>4. **Gap:** Note subtle access gap: does not verify `lecture in package.lectures` explicitly when fetching `get_object_or_404(Lecture, id=lecture_id)`! |
| `GET/POST /api/v1/teacher/groups/<group_id>/lectures/` (`TeacherGroupLecturesAPIView`, `api_v1/views_teacher.py#L173-L218`) | `IsAuthenticated`, `IsTeacherOrAssistantRole` | Accepts `title`, `video_link`, `description` (and attempts `lesson_id` reference). |
| `GET /api/v1/student/groups/<group_id>/content/` (`StudentGroupContentAPIView`) | `IsAuthenticated`, `IsStudentRole` | Uses `LectureStudentListSerializer` (`api_v1/serializers.py#L242-L253`), which omits `video_link` from the list view until watch unlock — good practice that broke once `/watch/` was called. |

---

## 4. Existing Web Template & YouTube Integration Audit

In `templates/includes/custom_video_player.html`:
- For lectures where `lecture.get_video_id` resolves a YouTube ID (`#L3`, `#L306-L347`):
  - Uses `https://www.youtube.com/iframe_api` (`YT.Player`) with `controls: 0`, `disablekb: 1`, `fs: 0`, `modestbranding: 1`, `rel: 0`.
  - Applies `.video-container { pointer-events: none; }` and an overlaid `.video-click-overlay` plus `.platform-watermark` and bouncing `.floating-watermark` (`request.user.custom_id`).
- For non-YouTube URLs (`#L496-L503`):
  - Embeds `{{ lecture.video_link }}` in a raw `<iframe src="...">` inside a 16:9 wrapper.
- **Compliance & Security Assessment:**
  - Attempting to obscure or disable YouTube player UI/branding overlays in mobile apps is fragile and violates YouTube API Services Terms of Service.
  - Unmigrated YouTube links cannot be protected from extraction even inside a WebView.
  - Platform-owned content MUST be hosted on private HLS/DASH infrastructure with signed short-lived delivery and played via a genuine native video player, while any unmigrated YouTube lectures must remain clearly separated and compliant until migrated.

---

## 5. Existing Flutter Video Player & Android Build Audit

### 5.1 Flutter Dependencies (`flutter_app/pubspec.yaml`)
- Existing packages: `dio`, `flutter_riverpod`, `flutter_secure_storage`, `shared_preferences`, `google_fonts`, `cached_network_image`, `image_picker`, `url_launcher`, `google_sign_in`, `intl`.
- **Missing:** Zero video playback packages (`video_player`, `media_kit`, etc.), zero screen brightness/wakelock utilities, zero Play Integrity SDK or native MethodChannel bindings.

### 5.2 Flutter Lecture Player (`flutter_app/lib/features/lectures/presentation/lecture_player_screen.dart`)
- Supports `VideoCode` input (`_unlockWithCode`) and package lecture calls (`_loadLecture`).
- `_buildPlayerView()` (`#L235-L341`) extracts `ytId` (`_extractYoutubeId`), displays a YouTube thumbnail (`https://img.youtube.com/vi/$ytId/hqdefault.jpg`), and clicking Play invokes `_openVideoUrl(videoUrl)` using `launchUrl(uri, mode: LaunchMode.externalApplication)` (`#L99-L105`).
- **Missing UI/UX:** No inline video player, no seek/speed/quality/subtitle/brightness/volume/fullscreen controls, no resume position, no watch history/continue watching, no bookmarks, no next/previous lecture navigation, no downloadable attachments tab in the player, and no watermark overlay.

### 5.3 Android Security & Build Audit
1. **`flutter_app/android/app/src/main/AndroidManifest.xml` (`#L8`):**
   - Explicitly sets `android:usesCleartextTraffic="true"` globally! Any HTTP call (instead of HTTPS) could travel unencrypted.
   - No `android:networkSecurityConfig`.
2. **`flutter_app/android/app/build.gradle.kts` (`#L28-L34`):**
   - Release buildType uses `signingConfig = signingConfigs.getByName("debug")`!
   - No `isMinifyEnabled = true`, no `isShrinkResources = true`, no `proguard-rules.pro`.
   - No Play Integrity library (`com.google.android.play:integrity`).
3. **`flutter_app/android/app/src/main/kotlin/online/ta3alm/ta3alm_flutter/MainActivity.kt` (`#L1-L5`):**
   - Empty `class MainActivity : FlutterActivity()` with zero `FLAG_SECURE`, zero Play Integrity channel, zero runtime tamper/debugger/root/signature signal inspection, and zero native brightness/volume channels.

---

## 6. Classification of Video Sources & Target Protection Matrix

| Content Source Type | Protection Capability | Target Flutter Handling | Target Backend Handling |
|---|---|---|---|
| **Migrated Platform Content** (`hls_protected`, `dash_protected`, `cloudflare_stream`, `bunny_stream`, `s3_cloudfront`, `mp4_private`) | **High:** Custom native player, no YouTube UI/URLs, short-lived signed playback URLs, optional Widevine L1/L3 DRM, server session heartbeat, single-device enforcement, `FLAG_SECURE`, dynamic watermark overlay. | `Ta3almNativeVideoPlayer` (`video_player` / Android Media3 ExoPlayer) with full custom controls & watermark. | Short-lived HMAC/JWT playback session token (`180s` TTL), signed CDN manifest URL, heartbeat validation, atomic view/progress tracking. |
| **Unmigrated Legacy YouTube** (`youtube_legacy`) | **Low (External Platform):** YouTube enforces its own terms/player; URLs cannot be DRM-protected or disguised cleanly. | Explicitly separated **Legacy YouTube Notice / Compliant External View** (does not pretend to be protected native streaming or strip YouTube branding). | Tagged `migration_status='legacy_youtube'` in `VideoAsset` and `VIDEO_MIGRATION_PLAN.md` for phased migration to Cloudflare Stream / Bunny Stream / AWS MediaConvert. |

