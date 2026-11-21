# Ta3alm Platform — Modular Architecture Guide (`ARCHITECTURE.md`)

This document describes the modular Django architecture of `ta3alm_project` after the codebase refactoring, including package responsibilities, dependency rules, extension guidelines, and safe test execution.

---

## 1. High-Level Directory Structure

```text
ta3alm/
├── ta3alm_project/
│   ├── settings.py
│   ├── urls.py
│   └── middleware/              # Modular middleware package (re-exported via __init__.py)
│       ├── __init__.py
│       ├── routing.py           # SubdomainAdminMiddleware
│       ├── auth.py              # TokenAuthMiddleware, BanMiddleware, EmailVerificationMiddleware
│       ├── platform.py          # MaintenanceMiddleware, AppVersionEnforcementMiddleware
│       ├── api_audit.py         # ApiSecurityAndActivityAuditMiddleware
│       └── web_device.py        # WebDeviceSecurityMiddleware
│
├── api_v1/
│   ├── urls.py                  # /api/v1/ URL routing (unchanged)
│   ├── schema.py                # OpenAPI & Swagger UI
│   ├── authentication.py        # JWTAndTokenAuthentication
│   ├── permissions.py           # Role & ban DRF permissions
│   ├── pagination.py
│   ├── integrity_service.py     # Google Play Integrity challenge & verification
│   ├── models/                  # Modular ORM models package (re-exported via __init__.py)
│   │   ├── __init__.py
│   │   ├── video.py             # VideoAsset, PlaybackSession, VideoProgress, VideoBookmark
│   │   ├── integrity.py         # PlayIntegrityNonce, DeviceIntegrityRecord, VideoSecurityAuditLog
│   │   ├── devices.py           # DeviceTrustStatus, RegisteredDevice, DeviceFingerprint, ...
│   │   └── policy.py            # SecurityPolicyConfig, UserSecurityProfile
│   ├── serializers/             # Modular DRF serializers package (re-exported via __init__.py)
│   │   ├── __init__.py
│   │   ├── catalog.py           # Subject, SubscriptionPlan, TeacherCard
│   │   ├── accounts.py          # UserPublic, UserDetail
│   │   ├── academics.py         # Group, Lecture, VideoCode, PDFFile, Question, Exam, ...
│   │   ├── packages.py          # CoursePackage, PackageEnrollment
│   │   ├── finance.py           # Wallet, WithdrawRequest, ManualPayment
│   │   ├── staff.py             # AssistantJob, AdminProfile, AuditLog
│   │   ├── notifications.py     # Notification, FCMDeviceToken
│   │   └── curriculum.py        # CurriculumUnit, CurriculumLesson
│   ├── services/                # Business logic layer (domain services)
│   │   ├── __init__.py
│   │   ├── auth_service.py      # Auth/OTP/Google/device registration helpers
│   │   ├── video_access.py      # Lecture metadata access & entitlement checks
│   │   ├── device_security/     # Split from device_security_service.py
│   │   │   ├── __init__.py
│   │   │   ├── constants.py
│   │   │   ├── fingerprint.py
│   │   │   ├── network.py
│   │   │   ├── hardware.py
│   │   │   ├── web.py
│   │   │   ├── events.py
│   │   │   ├── blocks.py
│   │   │   ├── risk.py
│   │   │   ├── registration.py
│   │   │   ├── web_playback.py
│   │   │   └── boot_gate.py
│   │   ├── security_engine/     # Split from security_engine.py
│   │   │   ├── __init__.py
│   │   │   ├── constants.py
│   │   │   ├── request_signing.py
│   │   │   ├── behavioral.py
│   │   │   ├── enforcement.py
│   │   │   └── ai_audit.py
│   │   └── video_security/      # Split from video_security.py
│   │       ├── __init__.py
│   │       ├── constants.py
│   │       ├── watch_window.py
│   │       ├── playback.py
│   │       ├── sealing.py
│   │       └── cdn_signing.py
│   ├── selectors/               # Read-only query & telemetry aggregation layer
│   │   ├── __init__.py
│   │   ├── device_selectors.py  # get_user_device_limit, build_unified_devices_registry
│   │   └── security_selectors.py# collect_user_today_telemetry
│   ├── views/                   # Modular API v1 endpoint views
│   │   ├── __init__.py
│   │   ├── auth/                # login, registration, profile, google, otp
│   │   ├── teacher/             # dashboard, lectures, exams, students, packages, wallet, assistants
│   │   ├── admin/               # dashboard, users, finance, plans_staff, support, notifications
│   │   ├── security/            # helpers, devices, monitoring, admin_actions
│   │   ├── student/             # groups, packages
│   │   └── video/               # throttles, progress
│   ├── views_public.py          # Public home, metadata, plans, app updates, assetlinks
│   ├── views_video.py           # Real module keeping PlayIntegrity & Authorize/Heartbeat/Stream views
│   ├── device_security_service.py  # Compatibility facade
│   ├── security_engine.py          # Compatibility facade
│   ├── video_security.py           # Compatibility facade
│   ├── views_{auth,teacher,admin,security,student}.py  # Compatibility facades
│   └── management/commands/     # audit_video_migration, run_ai_security_audit
│
├── core/
│   ├── models.py                # SiteSetting, Notification, FCMDeviceToken, Subject, ManualPayment, Curriculum*
│   ├── fcm_service.py           # Firebase Cloud Messaging HTTP v1 push thread dispatcher
│   ├── utils.py                 # send_notification, optimized leaderboard queries
│   ├── services/
│   │   ├── __init__.py
│   │   ├── wallet.py            # credit_teacher_wallet_for_sale, reconcile_teacher_wallet
│   │   └── notifications/       # constants, delivery, pull_tokens, campaigns
│   ├── selectors/
│   │   ├── __init__.py
│   │   └── notification_selectors.py
│   ├── signals/                 # Ordered domain signal receivers (connected once by CoreConfig.ready)
│   │   ├── __init__.py
│   │   ├── accounts.py
│   │   ├── academics.py
│   │   ├── results.py
│   │   ├── packages_finance.py
│   │   ├── staff.py
│   │   ├── devices_security.py
│   │   ├── site_settings.py
│   │   └── session_fcm.py
│   └── notifications_service.py # Compatibility facade
│
├── dashboard_admin/views/       # base, home, users, finance, plans, audit, staff, curriculum, support, security, notifications
├── teachers/views/              # permissions, dashboard, groups, account, payments, packages, wallet, files, legacy_api
├── students/views/              # access, dashboard, groups, packages
├── accounts/views/              # profile, signup, devices
├── exams/                       # Exam & Question models/views
├── assistants/                  # AssistantProfile & AssistantJob models/views
├── bot_api/                     # Bot integration endpoints
├── centers/                     # Stub app
└── services/                    # Top-level ZohoMailService package (do not shadow)
```

---

## 2. Layer Responsibilities & Dependency Rules

1. **Views (`api_v1/views/`, `<app>/views/`)**
   - Parse and validate incoming HTTP requests (forms / DRF serializers / permissions / throttles).
   - Call Services for state mutations and Selectors for complex reads.
   - Return `Response` / `render` / `redirect`. Avoid embedding multi-step domain orchestration in views.

2. **Services (`api_v1/services/`, `core/services/`)**
   - Encapsulate domain rules, transactional mutations (`transaction.atomic`), security evaluations, and external integrations.
   - **Layering rule:** Services must **not** import views, and must **not** import selectors at module import time. When a service needs a selector (e.g., `registration.py` -> `get_user_device_limit`, `ai_audit.py` -> `collect_user_today_telemetry`, `campaigns.py` -> `_count_fcm_enabled_users`), import it inside the calling function.

3. **Selectors (`api_v1/selectors/`, `core/selectors/`)**
   - Encapsulate read-only ORM aggregations, multi-table filters, and UI/API read models (`build_unified_devices_registry`, `collect_user_today_telemetry`, `preview_custom_notification_audience`, etc.).
   - Selectors may import models and lower-level service helpers/constants, never views.

4. **Models (`api_v1/models/`, `<app>/models.py`)**
   - Define ORM schemas, field validations, indexes, and lightweight model methods only. Keep transactional cross-model business logic in `services/` (e.g., `core/services/wallet.py`).

5. **Signals (`core/signals/`)**
   - Organized by domain and imported once in deterministic order inside `core/signals/__init__.py`, triggered by `CoreConfig.ready()`. Never import `core.signals` repeatedly or connect duplicate `@receiver` handlers.

6. **Compatibility Facades**
   - Legacy import paths (`api_v1.device_security_service`, `api_v1.security_engine`, `api_v1.video_security`, `api_v1.views_*`, `core.notifications_service`, and package `__init__.py` modules for `views/`, `models/`, `serializers/`, `signals/`, `middleware/`) explicitly re-export all public and private symbols for backward compatibility.
   - **New code should import from the concrete domain submodule** (e.g., `from api_v1.services.device_security.blocks import block_device_admin`) rather than facades.

---

## 3. How to Extend the Platform

- **Adding a new feature:**
  1. Add/update models in `<app>/models.py` or `api_v1/models/<domain>.py` (and re-export in `api_v1/models/__init__.py`), then generate a migration (`python manage.py makemigrations`).
  2. Put read queries in `<app>/selectors/<domain>_selectors.py` and mutations/business rules in `<app>/services/<domain>.py`.
  3. Add serializers in `api_v1/serializers/<domain>.py` (re-export in `api_v1/serializers/__init__.py` if needed) and view classes in `api_v1/views/<domain>/<module>.py` (or `<app>/views/<domain>.py` for HTML views).
  4. Wire routes in `api_v1/urls.py` or `<app>/urls.py`.
- **Adding a new API endpoint:**
  - Create or extend a focused `APIView` in `api_v1/views/<domain>/`, keep `permission_classes` / `authentication_classes` / `throttle_classes` explicit, import into `api_v1/views_<domain>.py` if needed, and register the route in `api_v1/urls.py`.
  - Keep `api_v1/views_video.py` intact for Play Integrity / Video Authorization views patched at `api_v1.views_video.get_integrity_policy_mode`.
- **Adding background tasks / management commands:**
  - Periodic/CLI jobs belong under `<app>/management/commands/<command_name>.py` (delegating business logic to `services/`).
  - Async in-process threads (like `fcm_service` or `maybe_trigger_hourly_ai_audit_async`) live in their dedicated service module; if Celery is added later, place thin `@shared_task` wrappers in `<app>/tasks/<domain>_tasks.py` delegating to `services/`.
- **Adding signals:**
  - Place `@receiver` handlers in the matching `core/signals/<domain>.py` module and import it in `core/signals/__init__.py` so `CoreConfig.ready()` registers it exactly once.

---

## 4. Import Rules

- Always use **absolute imports** across packages (e.g. `from api_v1.models import RegisteredDevice`), especially inside subpackages where `.` depth differs from root modules.
- **Never** use `from module import *`.
- Keep lazy (function-local) imports where they prevent circular dependencies or preserve `unittest.mock.patch` targets (such as `core.fcm_service.schedule_fcm_push_for_notifications`).
- Never create a module or package named `services` inside `api_v1` that is imported with a bare `import services`, as the repository already has a top-level `services/` package (`services.zoho_mail_service`).

---

## 5. Running Checks & Tests Safely

> [!CAUTION]
> `ta3alm_project/settings.py` reads `.env` and connects to remote PostgreSQL (`neondb`) whenever `DATABASE_URL` / `TEST_DATABASE_URL` is configured and `USE_SQLITE` is not set. **Always force SQLite for local checks and tests** so you never touch remote databases.

### PowerShell setup before any `manage.py` command
```powershell
$env:USE_SQLITE = 'true'
$env:USE_POSTGRES_FOR_TESTS = 'false'
$env:DATABASE_URL = ''
$env:POSTGRES_URL = ''
$env:TEST_DATABASE_URL = ''
$env:DB_HOST = ''
```

### Standard verification commands
```powershell
# Django system check
venv\Scripts\python.exe manage.py check

# Verify no pending model/migration drift
venv\Scripts\python.exe manage.py makemigrations --check --dry-run

# Full Django test suite on local in-memory SQLite (with migrations)
venv\Scripts\python.exe manage.py test --noinput -v 2
```

When running fast regression checks without applying migrations, the scratch runner builds the SQLite `:memory:` schema directly from models (`MIGRATION_MODULES = DisableMigrations()`), asserting `DATABASES['default']['ENGINE'] == 'django.db.backends.sqlite3'` prior to `django.setup()`.
