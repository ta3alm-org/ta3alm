# Refactoring Changelog (`REFACTORING_CHANGELOG.md`)

**Baseline commit:** `73f9a18` (`refs/backup/pre-refactor`)  
**Scope:** Internal modularization & separation of concerns across 18 large source modules (+ wallet extraction from `core/models.py`), preserving 100% of external URLs, API contracts, HTTP status codes, database schemas, migrations, signal ordering, permissions, and mock patch targets.

---

## 1. Summary of Refactored Modules

| Phase | Original Module | Lines Before | New Package / Modules | Compatibility Facade / Shim |
|---|---|---:|---|---|
| 4a & 5 | `api_v1/device_security_service.py` | 3,180 | `api_v1/services/device_security/{constants,fingerprint,network,hardware,web,events,blocks,risk,registration,web_playback,boot_gate,__init__}.py` + `api_v1/selectors/device_selectors.py` | `api_v1/device_security_service.py` (118 lines) |
| 4b & 5 | `api_v1/security_engine.py` | 1,139 | `api_v1/services/security_engine/{constants,request_signing,behavioral,enforcement,ai_audit,__init__}.py` + `api_v1/selectors/security_selectors.py` | `api_v1/security_engine.py` |
| 4b | `api_v1/video_security.py` | 577 | `api_v1/services/video_security/{constants,watch_window,playback,sealing,cdn_signing,__init__}.py` | `api_v1/video_security.py` |
| 4b & 5 | `core/notifications_service.py` | 794 | `core/services/notifications/{constants,delivery,pull_tokens,campaigns,__init__}.py` + `core/selectors/notification_selectors.py` | `core/notifications_service.py` |
| 4b | `core/models.py` (wallet helpers) | 415 | Extracted `credit_teacher_wallet_for_sale` and `reconcile_teacher_wallet` to `core/services/wallet.py` | Re-exported in `core/models.py` (354 lines) |
| 6 | `api_v1/views_auth.py` | 1,291 | `api_v1/services/auth_service.py` + `api_v1/views/auth/{login,registration,profile,google,otp,__init__}.py` | `api_v1/views_auth.py` |
| 6 | `api_v1/views_teacher.py` | 1,177 | `api_v1/views/teacher/{dashboard,lectures,exams,students,packages,wallet,assistants,__init__}.py` | `api_v1/views_teacher.py` |
| 6 | `api_v1/views_admin.py` | 996 | `api_v1/views/admin/{dashboard,users,finance,plans_staff,support,notifications,__init__}.py` | `api_v1/views_admin.py` |
| 6 | `api_v1/views_security.py` | 1,062 | `api_v1/views/security/{helpers,devices,monitoring,admin_actions,__init__}.py` | `api_v1/views_security.py` |
| 6 | `api_v1/views_student.py` | 769 | `api_v1/views/student/{groups,packages,__init__}.py` | `api_v1/views_student.py` |
| 6 | `api_v1/views_video.py` | 1,081 | Extracted `api_v1/services/video_access.py`, `api_v1/views/video/throttles.py`, `api_v1/views/video/progress.py`; retained `Authorize`/`Heartbeat`/`SessionRevoke`/`StreamProxy`/`PlayIntegrity*` in `api_v1/views_video.py` (730 lines) | Re-exported in `api_v1/views_video.py` |
| 6 | `dashboard_admin/views.py` | 1,756 | `dashboard_admin/views/{base,home,users,finance,plans,audit,staff,curriculum,support,security,notifications}.py` (deleted flat `views.py`) | `dashboard_admin/views/__init__.py` |
| 6 | `teachers/views.py` | 1,637 | `teachers/views/{permissions,dashboard,groups,account,payments,packages,wallet,files,legacy_api}.py` (deleted flat `views.py`) | `teachers/views/__init__.py` (includes `reconcile_teacher_wallet`) |
| 6 | `students/views.py` | 1,022 | `students/views/{access,dashboard,groups,packages}.py` (deleted flat `views.py`) | `students/views/__init__.py` |
| 6 | `accounts/views.py` | 637 | `accounts/views/{profile,signup,devices}.py` (deleted flat `views.py`) | `accounts/views/__init__.py` |
| 7 | `api_v1/models.py` | 772 | `api_v1/models/{video,integrity,devices,policy}.py` (deleted flat `models.py`) | `api_v1/models/__init__.py` |
| 7 | `api_v1/serializers.py` | 743 | `api_v1/serializers/{catalog,accounts,academics,packages,finance,staff,notifications,curriculum}.py` (deleted flat `serializers.py`) | `api_v1/serializers/__init__.py` |
| 7 | `core/signals.py` | 1,045 | `core/signals/{accounts,academics,results,packages_finance,staff,devices_security,site_settings,session_fcm}.py` (deleted flat `signals.py`) | `core/signals/__init__.py` (imports in exact original order) |
| 7 | `ta3alm_project/middleware.py` | 701 | `ta3alm_project/middleware/{routing,auth,platform,api_audit,web_device}.py` (deleted flat `middleware.py`) | `ta3alm_project/middleware/__init__.py` |

### Unchanged Cohesive Modules
- `core/utils.py` (92 lines) and `bot_api/utils.py` (16 lines) — assessed in Phase 3, already minimal and cohesive.
- `api_v1/views_public.py` (538 lines) — cohesive public endpoints.
- `core/fcm_service.py` (361 lines) — preserved intact because tests patch `core.fcm_service.schedule_fcm_push_for_notifications` and it owns module-level lock/credential cache state.
- `services/zoho_mail_service.py` (382 lines), `api_v1/integrity_service.py` (315 lines), `api_v1/authentication.py`, `api_v1/permissions.py`, `api_v1/admin.py`, `api_v1/urls.py`, `ta3alm_project/settings.py`.

---

## 2. Internal Compatibility & Cycle-Prevention Details

- **Absolute import normalization:** All relative imports inside moved modules (including function-local lazy imports) were converted to absolute imports anchored to their original top-level package.
- **Duplicate top-level imports deduplicated:** Original files (`teachers/views.py`, `students/views.py`) had mid-file duplicate imports; moved modules keep a single deduplicated top-level import block with unused imports pruned.
- **Logger name preservation:** Replaced `logging.getLogger(__name__)` with explicit original logger names:
  - `dashboard_admin/views/*.py` → `'dashboard_admin.views'`
  - `teachers/views/payments.py` → `'teachers.views'` (`_pay_logger`)
  - `core/services/notifications/*.py` → `'core.notifications_service'`
  - `core/signals/*.py` → `'core.signals'`
- **Intentional lazy imports to maintain clean layering (no cycles):**
  - `api_v1/services/device_security/registration.py`: `get_user_device_limit` imported lazily from `api_v1.selectors.device_selectors` inside `register_or_update_device` and `check_device_allowed`.
  - `api_v1/services/security_engine/behavioral.py`: `enforce_security_ban` imported lazily from `api_v1.services.security_engine.enforcement` inside `record_behavioral_activity`.
  - `api_v1/services/security_engine/ai_audit.py`: `collect_user_today_telemetry` imported lazily from `api_v1.selectors.security_selectors` inside `analyze_user_with_ai`.
  - `core/services/notifications/campaigns.py`: `_count_fcm_enabled_users` imported lazily from `core.selectors.notification_selectors` inside `send_custom_notification`.
  - `core/services/wallet.py`: `SiteSetting` imported lazily from `core.models` inside `credit_teacher_wallet_for_sale` and `reconcile_teacher_wallet`.
- **Mock patch compatibility:** `get_integrity_policy_mode`, `_check_required_integrity`, `PlayIntegrityChallengeAPIView`, and `PlayIntegrityVerifyAPIView` remain in `api_v1/views_video.py` so `patch('api_v1.views_video.get_integrity_policy_mode')` continues to intercept live lookups. `schedule_fcm_push_for_notifications` remains lazily imported inside notification and signal functions.

---

## 3. Contract Regression Suite Added

- Added `api_v1/tests_refactor_contracts.py` (`RefactorContractsTests`) verifying:
  - Reversal and view callback resolution of all **452** named URLs.
  - Presence of every baseline top-level symbol across all **20** audited compatibility facades/packages.
  - Exact signal receiver counts per `(signal, sender)` across `pre_save`, `post_save`, `pre_delete`, `post_delete`, `m2m_changed`, `user_logged_in`, `user_logged_out`, `user_login_failed`.
  - Baseline HTTP status codes for **120** anonymous `/api/v1/` requests and status codes + sorted top-level JSON keys for **34** authenticated parameter-less `/api/v1/` GET requests.

---

## 4. Deferred Internal Decompositions (Needs Manual Review)

To guarantee strict behavior preservation, the bodies of the following large functions/classes were moved verbatim without internal helper extraction and are recommended for targeted follow-up refactoring with dedicated unit tests:

1. `api_v1/services/device_security/registration.py` → `register_or_update_device` (~387 lines)
2. `api_v1/services/device_security/risk.py` → `evaluate_and_apply_risk` (~195 lines)
3. `api_v1/views/security/admin_actions.py` → `SecurityAdminActionAPIView` (~481 lines, multi-branch action dispatch)
4. `dashboard_admin/views/security.py` → `security_admin_action` (~262 lines, HTML counterpart to `SecurityAdminActionAPIView`)
5. `api_v1/views_video.py` → `VideoAuthorizeAPIView` (~248 lines)
6. `api_v1/views/admin/users.py` → `AdminManageUsersAPIView` (~242 lines)
7. `api_v1/services/video_access.py` → `_check_user_lecture_entitlement` (~191 lines)
8. `calculate_leaderboard` remains identically defined in both `teachers/views/groups.py` and `students/views/access.py` (both delegate to `core.utils.get_optimized_group_leaderboard`) for compatibility.

---

## 5. Pre-Existing Issues Observed (Left Untouched)

1. **`accounts/api_views.py:15`:** Lazily imports `record_failed_login` from `api_v1.device_security_service`; this function was absent in baseline commit `73f9a18` and causes `ImportError` on invalid credentials at `/api/auth/login/`. Left untouched per behavior-preservation rules.
2. **`accounts/views/profile.py` (originally `accounts/views.py:118`):** `User.objects.filter(Q(is_superuser=True) | Q(role='admin'), ...)` inside `try/except Exception` uses `Q` without importing `django.db.models.Q` (silently swallowed in the `except`). Preserved verbatim.
3. **Dead / unreachable code detected by `pyflakes` in original files (preserved verbatim):**
   - `teachers/views/groups.py` (`group_students`, `group_requests`): `if 'lectures' in locals():` / `exams` / `pending_enrollments` / `enrollments` blocks referencing unbound locals.
   - `teachers/views/payments.py` (`paymob_checkout`) and `students/views/packages.py` (`paymob_package_checkout`): unreachable legacy Paymob code after `return redirect(...)` referencing commented-out variables (`amount_cents`, `wallet_number`, `integration_id`, `method`).
   - Unused local assignments (`is_owner`, `source_group_id`, `enrollment`) in `teachers/views/packages.py` and `students/views/access.py`.
4. **6 pre-existing test failures** (observed identically before and after refactoring):
   - `Ta3almAPIV1TestSuite.test_05_full_educational_workflow_teacher_and_student` (`403 != 201`)
   - `Ta3almAPIV1TestSuite.test_06_packages_manual_payment_and_admin_approval` (`403 != 201`)
   - `PlatformNotificationCoverageTests.test_security_account_events_and_background_pull_endpoint` (`503 != 200`)
   - `PlatformFinancialAndContentFixesTests.test_commission_setting_manual_payment_credit_and_wallet_reconcile` (`403 != 200`)
   - `PlatformFinancialAndContentFixesTests.test_pdf_file_upload_and_question_image_upload` (`403 != 201`)
   - `PlatformFinancialAndContentFixesTests.test_withdraw_request_three_state_approve_reject_refund_and_reconcile` (`403 != 201`)
