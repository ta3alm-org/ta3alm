# Screen Capture & Recording Protection Report — Ta3alm Platform

## 1. Mandatory Coverage Across Protected Screens
Screen capture restriction is enforced across all sensitive student & proprietary content routes in `flutter_app/lib/features/`:
1. **Video Player & Playback (`lecture_player_screen.dart` + `ta3alm_video_player.dart`):** Wrapped at the root outside fullscreen/portrait transitions with `blockOnExternalDisplay: true` so `FLAG_SECURE` stays continuously active into and out of fullscreen mode and orientation changes.
2. **Protected Course / Group Materials & Lecture Details (`pdf_viewer_screen.dart`, `student_group_detail_screen.dart`, `student_package_content_screen.dart`, `package_detail_screen.dart`):** Protected with `ProtectedScreenWrapper` (`FLAG_SECURE` + lifecycle re-assertion + capture logging).
3. **Sensitive Student Information (`profile_screen.dart`, `student_marks_screen.dart`, `trusted_devices_screen.dart`):** Protected against background recent-apps thumbnails and screen captures.
4. **Protected Examination Screens (`take_exam_screen.dart`):** Protected with `ProtectedScreenWrapper(..., blockOnExternalDisplay: true)` to block wireless/external display mirroring and capture attempts during live exams.

---

## 2. Native Android `FLAG_SECURE` Lifecycle Enforcement
Implemented in `flutter_app/android/app/src/main/kotlin/online/ta3alm/ta3alm_flutter/MainActivity.kt` and `AndroidManifest.xml`:
- **Persistent State Tracking:** `isSecureModeActive` is persisted across `onSaveInstanceState` / `onCreate` recreation and re-applied in `onResume`, `onWindowFocusChanged`, and `onConfigurationChanged` so orientation flips, activity recreation, and app switcher transitions cannot drop `WindowManager.LayoutParams.FLAG_SECURE`.
- **Recent-App Switcher Protection:** Applying `FLAG_SECURE` on `Window` blanks out Android's recent-apps overview preview whenever `MainActivity` moves into `inactive` or `paused` states (`ProtectedScreenWrapper.didChangeAppLifecycleState`).
- **Pre-Render & Reference-Counted Activation (`PlatformSecurityService`):**
  - `_activeProtectionTags` maintains a `Set<String>` of mounted protected widgets (`lecture_player_screen_<id>`, `video_player_widget`, `take_exam_<id>`, etc.).
  - `acquireSecureScreen(tag)` enforces `setSecureFlag(enabled: true)` before frame rendering (`initState`) and after the first frame (`addPostFrameCallback`).
  - `releaseSecureScreen(tag)` clears `FLAG_SECURE` **only** when `_activeProtectionTags` becomes completely empty, ensuring child widgets (such as `Ta3almVideoPlayer.dispose()`) cannot prematurely disable protection held by a parent screen.

---

## 3. Capture & Display Mirroring Detection
- **Android 14+ Screenshot Callback (`API 34+`):** `MainActivity.kt` declares `<uses-permission android:name="android.permission.DETECT_SCREEN_CAPTURE"/>` and dynamically registers `Activity.ScreenCaptureCallback` (via reflection to preserve lower `compileSdk` compatibility while supporting Android 14+). When triggered, `MainActivity` emits `"onScreenCaptureDetected"` (`event_type: "screenshot_attempt"`) to Flutter without capturing screenshots or personal data.
- **External & Virtual Display Listener:** `MainActivity` registers `DisplayManager.DisplayListener` (`onDisplayAdded`, `onDisplayChanged`) while `isSecureModeActive` is true and emits `"display_capture_detected"` whenever non-default/presentation/virtual displays appear.
- **Server Event Ingestion (`POST /api/v1/security/events/report/`):** `DeviceSecurityService` rate-limits identical bursts (4s debounce window) and logs `screenshot_attempt`, `screen_recording_detected`, and `display_capture_detected` events into `DeviceActivity`, `DeviceSecurityEvent`, and escalated risk scoring (`SecurityEventReportAPIView`).

---

## 4. Known Physical Limitations & Watermark Deterrence
- **External Camera Limitation:** No software or OS-level API (`FLAG_SECURE`, DRM, or Play Integrity) can prevent a person from pointing an external physical camera (e.g., another phone) at a screen.
- **Deterrence Layer (`build_watermark_payload` in `api_v1/views_video.py` & video player overlay):** Dynamic per-student non-sensitive attribution watermarks (name + `custom_id` + short session reference) remain rendered over video playback so leaked external recordings are traceable without exposing private phone/email PII.

