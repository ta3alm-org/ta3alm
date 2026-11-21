# Ta3alm Django Codebase Refactoring Audit (`REFACTORING_AUDIT.md`)

**Baseline commit:** `73f9a18` (`refs/backup/pre-refactor`; original audit started at `da7e63a`)  
**Scope reviewed:** 133 Python files across the Django project (excluding `venv/`, `flutter_app/`, `staticfiles/`, `media/`, and `migrations/`).

---

## 1. Current Architecture

The repository is a Django 6.0 / Django REST Framework 3.17 monolith (`ta3alm_project`) with the following apps and packages:

| App / Package | Primary Responsibility |
|---|---|
| `ta3alm_project/` | Root settings, root URL routing (non-i18n APIs + `i18n_patterns`), custom middleware stack (9 custom middlewares), WSGI/ASGI |
| `accounts/` | Custom `User` model (`AUTH_USER_MODEL = 'accounts.User'`), `StudentProfile`, email verification, manual signup, web trusted devices UI, legacy `/api/auth/login/` |
| `api_v1/` | REST API v1 (`/api/v1/`): auth, public/catalog, student, teacher/assistant, admin, protected video playback, Play Integrity, device security & AI behavioral security engine |
| `core/` | Shared `SiteSetting`, `Subject`, `CurriculumUnit`, `CurriculumLesson`, `ManualPayment`, `Notification`, `FCMDeviceToken`, FCM push service, notification service, platform-wide model signals, wallet credit/reconciliation helpers |
| `teachers/` | Web views & models for `TeacherProfile`, `SubscriptionPlan`, `Group`, `Lecture`, `VideoCode`, `PDFFile`, `CoursePackage`, `Wallet`, `WithdrawRequest`, Paymob checkout/callback |
| `students/` | Web views & models for `Enrollment`, `PerformanceLog`, `PackageEnrollment`, `VideoViewTracking`, `PackageExamResult`, web lecture watch & heartbeat |
| `dashboard_admin/` | Custom admin portal (`/admin-panel/` & `admin.*` subdomain) with `AdminProfile`, `AuditLog`, user management, finance, support inbox, notifications, security dashboard |
| `exams/` | `Exam`, `Question`, `ExamResult` models and teacher web exam-builder views |
| `assistants/` | `AssistantProfile`, `AssistantJob` models and assistant web views |
| `bot_api/` | Bot API endpoints and Egyptian phone helper |
| `centers/` | Empty/stub app structure |
| `services/` | Top-level external integration package (`services/zoho_mail_service.py`) |

No Celery or external job queue is installed; background tasks run either via daemon `threading.Thread` (`core.fcm_service`, `api_v1.security_engine.maybe_trigger_hourly_ai_audit_async`) or Django management commands (`core.management.commands.populate_curriculum`, `api_v1.management.commands.audit_video_migration`, `api_v1.management.commands.run_ai_security_audit`).

---

## 2. Critical Cross-App Dependency Graph

Static AST import analysis across all 133 Python files reveals dense bidirectional coupling between `api_v1`, web apps, `core`, and `ta3alm_project`:

- `api_v1` → `students.views` (`check_student_access`, `calculate_leaderboard`)
- `api_v1` → `teachers.views` (`legacy_teacher_views` in `api_v1/urls.py`; teacher permissions/helpers in `api_v1/views_teacher.py`)
- `api_v1` → `accounts`, `assistants`, `core`, `dashboard_admin`, `exams`, `services`
- `exams.views` → `teachers.views.get_group_permission`
- `core.signals` → `api_v1.video_security.clear_watch_window` (lazy) & `core.fcm_service.schedule_fcm_push_for_notifications` (lazy)
- `ta3alm_project.middleware` → `api_v1.device_security_service` (`evaluate_boot_security_gate`, `record_security_event`, `WEB_COOKIE_NAME`, `WEB_COOKIE_SALT`, etc.) & `api_v1.security_engine` (`record_behavioral_activity`, `verify_client_request_signature`, `maybe_trigger_hourly_ai_audit_async`) & `core.models.SiteSetting`
- `dashboard_admin.views` → `api_v1.device_security_service` (`build_unified_devices_registry`, `get_device_hardware_id`, etc.) & `core.notifications_service` & `services.zoho_mail_service`
- `accounts.views` & `accounts.api_views` → `api_v1.device_security_service`
- `students.views` → `api_v1.device_security_service` (`check_web_ios_only_lecture_access`, `enforce_web_lecture_playback`, `check_device_allowed`, `get_or_create_web_installation_id`) & `api_v1.video_security`
- `teachers.views` → `core.notifications_service`, `core.utils`, `core.models` (`reconcile_teacher_wallet` is imported from `teachers.views` by `api_v1/tests_video_security.py`)

---

## 3. Large Files Inventory (> 300 Lines, Excluding Tests & Migrations)

| File | Lines | Primary Issues |
|---|---:|---|
| `api_v1/device_security_service.py` | 3,180 | Monolith mixing fingerprinting, IP/network analysis, hardware IDs, device blocks, telemetry events, risk scoring, registration, web UA/spoofing, web playback gate, boot gate, and device selectors |
| `dashboard_admin/views.py` | 1,756 | 11 admin domains in one file; 262-line `security_admin_action` |
| `teachers/views.py` | 1,637 | Group/package CRUD, Paymob checkout/HMAC verification, wallet, PDFs, assistants, and legacy DRF views in one file; mid-file imports |
| `api_v1/views_auth.py` | 1,291 | Auth views mixed with helper business logic (`ensure_user_role_profile`, OTP/device helpers, Google verification) |
| `api_v1/views_teacher.py` | 1,177 | 19 teacher + assistant DRF views and permission helpers in one file |
| `api_v1/security_engine.py` | 1,139 | HMAC request signing, behavioral risk scoring, ban enforcement, telemetry selector, and LLM AI audit in one file |
| `api_v1/views_video.py` | 1,081 | Video entitlement/access helpers alongside 9 playback/progress/integrity API views |
| `api_v1/views_security.py` | 1,062 | Device, monitoring, and a 481-line `SecurityAdminActionAPIView` |
| `core/signals.py` | 1,045 | 8 distinct domains of `@receiver` signal handlers in one file |
| `students/views.py` | 1,022 | Student access checks, leaderboard helpers, dashboard, groups, packages, Paymob checkout |
| `api_v1/views_admin.py` | 996 | 7 admin DRF views (`AdminManageUsersAPIView` is 242 lines) |
| `core/notifications_service.py` | 794 | Notification delivery, background pull token signing, custom campaigns, and recipient selectors |
| `api_v1/models.py` | 772 | 16 models spanning video assets, Play Integrity, device security, and security policy |
| `api_v1/views_student.py` | 769 | Group and package student API views in one file |
| `api_v1/serializers.py` | 743 | 28 serializers spanning accounts, academics, packages, finance, staff, notifications, curriculum, catalog |
| `ta3alm_project/middleware.py` | 701 | 8 middleware classes spanning subdomain routing, auth/ban/email, maintenance/app version, API signing/audit, web device protection |
| `accounts/views.py` | 637 | Profile completion, manual signup/OTP verification, web trusted devices |
| `api_v1/video_security.py` | 577 | Watch-window caching, playback token/watermark/sessions, AES-like XOR/HMAC video ref sealing, CDN URL signing |
| `api_v1/views_public.py` | 538 | Cohesive public/metadata/notification endpoints (kept unified) |
| `ta3alm_project/settings.py` | 459 | Settings file (unchanged) |
| `core/models.py` | 415 | Contains wallet business logic functions `credit_teacher_wallet_for_sale` and `reconcile_teacher_wallet` |
| `services/zoho_mail_service.py` | 382 | Single cohesive Zoho service class (unchanged) |
| `core/fcm_service.py` | 361 | Single FCM push module with module-level lock/cache state (unchanged to protect mock patch targets) |
| `dashboard_admin/models.py` | 331 | Cohesive admin models (unchanged) |
| `api_v1/integrity_service.py` | 315 | Cohesive Play Integrity service (unchanged) |

*Large test files (`tests_device_security.py` 1,675 lines, `tests_notifications.py` 1,249 lines, `tests_video_security.py` 824 lines, `tests.py` 466 lines) are retained intact as the regression safety net.*

---

## 4. Utility Modules Assessment (Phase 3)

- `core/utils.py` (92 lines): cohesive helpers (`send_notification`, `get_optimized_group_leaderboard`, `get_optimized_package_leaderboard`).
- `bot_api/utils.py` (16 lines): single helper (`normalize_egypt_phone`).
- **Decision:** Neither utility file requires splitting.

---

## 5. God Functions, Misplaced Business Logic & Duplication Candidates

- **God functions:**
  - `api_v1.views_security.SecurityAdminActionAPIView` (481 lines, lines 582–1062)
  - `api_v1.device_security_service.register_or_update_device` (387 lines, lines 1280–1666)
  - `dashboard_admin.views.security_admin_action` (262 lines, lines 1333–1594)
  - `api_v1.views_video.VideoAuthorizeAPIView` (248 lines, lines 375–622)
  - `api_v1.views_admin.AdminManageUsersAPIView` (242 lines, lines 228–469)
  - `api_v1.device_security_service.evaluate_and_apply_risk` (195 lines, lines 962–1156)
  - `api_v1.views_video._check_user_lecture_entitlement` (191 lines, lines 144–334)
- **Misplaced business logic:**
  - `core/models.py` defines transactional wallet services `credit_teacher_wallet_for_sale` and `reconcile_teacher_wallet` directly inside `models.py` → move to `core/services/wallet.py` with re-exports in `core/models.py`.
  - `api_v1/views_auth.py` and `api_v1/views_video.py` contain non-view domain/entitlement helpers → extract to `api_v1/services/auth_service.py` and `api_v1/services/video_access.py`.
- **Duplication candidates (noted, not aggressively merged to preserve exact behavior):**
  - `calculate_leaderboard` exists identically in both `teachers/views.py` and `students/views.py` (both delegate to `core.utils.get_optimized_group_leaderboard`). Kept exported in both modules for compatibility.
  - Security admin actions (`ban_user`, `unban_user`, `block_device`, `unblock_device`, `revoke_device`, `revoke_session`, etc.) exist in both `api_v1.views_security.SecurityAdminActionAPIView` and `dashboard_admin.views.security_admin_action` with differing response shapes (JSON API vs HTML messages/redirects) — kept separate.

---

## 6. Circular Import Risks

- `core.models` ↔ `core.services.wallet`: `wallet.py` needs `SiteSetting`, `teachers.models`, `students.models`; `core/models.py` re-exports the wallet functions at the bottom after `SiteSetting` is defined, and `wallet.py` imports `SiteSetting` lazily or cleanly after `core.models` initializes.
- `api_v1.device_security_service` ↔ `api_v1.video_security`: `registration.py` / `web_playback.py` call `clear_watch_window`, `build_watermark_payload`, `create_or_rotate_playback_session` via function-local lazy imports (already lazy in source).
- `api_v1.services.device_security.*` internal cycles: carefully isolated via targeted lazy imports where mutually recursive helpers exist (e.g., `blocks` ↔ `events`/`hardware`/`risk`/`registration`).
- `core.signals` → `core.notifications_service` and `api_v1.video_security`: receiver registration order must match `CoreConfig.ready()` (`accounts` → `academics` → `results` → `packages_finance` → `staff` → `devices_security` → `site_settings` → `session_fcm`) so signal count and invocation order remain identical.

---

## 7. Proposed Modular Architecture

- **Services:** `api_v1/services/{device_security/,security_engine/,video_security/,auth_service.py,video_access.py}`, `core/services/{notifications/,wallet.py}`.
- **Selectors:** `api_v1/selectors/{device_selectors.py,security_selectors.py}`, `core/selectors/notification_selectors.py`.
- **API & Web Views:** `api_v1/views/{auth,teacher,admin,security,student,video}/`, `dashboard_admin/views/`, `teachers/views/`, `students/views/`, `accounts/views/`.
- **Models, Serializers, Signals, Middleware:** `api_v1/models/`, `api_v1/serializers/`, `core/signals/`, `ta3alm_project/middleware/`.
- **Compatibility Layer:** Every original flat module (`api_v1/device_security_service.py`, `api_v1/views_*.py`, `core/notifications_service.py`, package `__init__.py` files, etc.) re-exports all original public and private top-level symbols plus externally imported names.

---

## 8. Compatibility Risks & Pre-Existing Issues

1. **Mock patch paths in tests:**
   - `api_v1.views_video.get_integrity_policy_mode` (`_check_required_integrity`, `PlayIntegrityChallengeAPIView`, `PlayIntegrityVerifyAPIView` stay inside `api_v1/views_video.py`).
   - `core.fcm_service.schedule_fcm_push_for_notifications` (kept function-local in notification delivery and signals; `core/fcm_service.py` left untouched).
   - `services.zoho_mail_service.ZohoMailService.is_connected` and Google Auth SDK classes (untouched).
2. **Logger names (`__name__`):** `dashboard_admin/views.py`, `teachers/views.py` (`_pay_logger`), and `core/notifications_service.py` use `logging.getLogger(__name__)`. Moved code must pass literal `'dashboard_admin.views'`, `'teachers.views'`, and `'core.notifications_service'`.
3. **Relative imports:** Moving code into subpackages shifts `.` depth; every relative import (including lazy imports inside functions) is rewritten to absolute imports anchored to the original package.
4. **Pre-existing broken import in `accounts/api_views.py:15`:** Lazily imports `record_failed_login` from `api_v1.device_security_service`, which does not exist in `device_security_service.py` at baseline commit `da7e63a`. Left untouched (never fabricated) to avoid altering existing behavior; flagged for manual review.
5. **Pre-existing migrations resolved in `73f9a18`:** `api_v1/migrations/0004_securitypolicyconfig_ai_api_key_override_and_more.py` and `teachers/migrations/0017_teacherprofile_approved_at_and_more.py` were committed in `73f9a18`. `manage.py makemigrations --check --dry-run` now reports `No changes detected` (exit 0), and all refactor phases must maintain exit 0.
6. **Pre-existing test DB default (Neon Postgres danger):** `ta3alm_project/settings.py` connects to Neon Postgres unless `USE_SQLITE='true'` (or `IS_TEST_RUN` with empty `TEST_DATABASE_URL`). All verification scripts force `USE_SQLITE='true'` and assert `sqlite3`. (An initial baseline probe prior to forcing `USE_SQLITE` hit Neon's `test_neondb` test database; production tables were untouched.)
7. **Baseline test suite status (59 original tests on SQLite):** **53 passed, 6 failed, 0 errors** (updated after the user fixed the line-116 `{% endif %}` bug in `templates/admin_panel/security_dashboard.html`, which resolved the `test_16` `TemplateSyntaxError`). The remaining 6 pre-existing failures are:
   - `FAIL` `Ta3almAPIV1TestSuite.test_05_full_educational_workflow_teacher_and_student` (`AssertionError: 403 != 201`)
   - `FAIL` `Ta3almAPIV1TestSuite.test_06_packages_manual_payment_and_admin_approval` (`AssertionError: 403 != 201`)
   - `FAIL` `PlatformNotificationCoverageTests.test_security_account_events_and_background_pull_endpoint` (`AssertionError: 503 != 200`)
   - `FAIL` `PlatformFinancialAndContentFixesTests.test_commission_setting_manual_payment_credit_and_wallet_reconcile` (`AssertionError: 403 != 200`)
   - `FAIL` `PlatformFinancialAndContentFixesTests.test_pdf_file_upload_and_question_image_upload` (`AssertionError: 403 != 201`)
   - `FAIL` `PlatformFinancialAndContentFixesTests.test_withdraw_request_three_state_approve_reject_refund_and_reconcile` (`AssertionError: 403 != 201`)
   Plus 4/4 passing baseline contract tests in `api_v1/tests_refactor_contracts.py` (total: 63 tests, 57 ok, 6 FAIL, 0 ERROR).
