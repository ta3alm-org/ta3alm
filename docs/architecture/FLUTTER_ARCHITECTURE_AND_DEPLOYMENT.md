# Ta3alm Platform — Django REST API v1 & Native Flutter Application Guide

## 1. Architecture Overview

The **Ta3alm** platform now operates as a unified dual-interface ecosystem backed by a single source of truth (Django + PostgreSQL/Cloudinary):

1. **Web Interface (Preserved 100%)**:
   - Existing Django Templates (`templates/`), HTML/CSS/JS views, i18n (`ar`/`en`), and `/admin-panel/` remain completely intact.
2. **REST API Layer (`/api/v1/`)**:
   - Modular Django REST Framework package (`api_v1/`) providing 52 endpoints across Authentication, Public/Metadata, Student, Teacher, Assistant, Payments, Notifications, and Platform Admin.
   - Dual Authentication (`api_v1/authentication.py`):
     - **JWT (`Authorization: Bearer <access_token>`)** with 12-hour access tokens and 30-day refresh tokens (`/api/v1/auth/refresh/`), powered by `PyJWT`.
     - **Legacy DRF Token (`Authorization: Token <key>`)** for backward compatibility.
   - Interactive OpenAPI 3.0 Documentation:
     - **Swagger UI**: `https://ta3alm.online/api/v1/docs/`
     - **OpenAPI JSON Schema**: `https://ta3alm.online/api/v1/schema/`
3. **Native Flutter Application (`flutter_app/`)**:
   - Feature-first Clean Architecture built with Flutter 3, Riverpod (`flutter_riverpod`), Dio (`dio` with auto token-refresh interceptor), and `FlutterSecureStorage`.
   - Centralized Design System (`flutter_app/lib/core/theme/`) reproducing Ta3alm's Royal Maroon (`#800000`), Deep Maroon Hero Gradient (`#520000` → `#170000`), Gold (`#FFD700`), Cairo Arabic typography, Dark & Light modes, and responsive Phone (`NavigationBar`) + Tablet (`NavigationRail` + multi-column) layouts.

---

## 2. Backend Setup & Running Automated API Tests

### Environment Variables (`.env`)
```env
SECRET_KEY=your-production-secret-key
DEBUG=False
ALLOWED_HOSTS=ta3alm.online,www.ta3alm.online,admin.ta3alm.online,localhost,127.0.0.1
DATABASE_URL=postgresql://user:password@host:5432/dbname?sslmode=require
CLOUDINARY_URL=cloudinary://api_key:api_secret@cloud_name
```

### Run Automated API Test Suite (`api_v1/tests.py`)
```powershell
F:
cd F:\work\ta3alm
python manage.py test api_v1
```

### Run Local Development Server
```powershell
F:
cd F:\work\ta3alm
python manage.py runserver 0.0.0.0:8000
```
- Web Platform: `http://127.0.0.1:8000/`
- Swagger API Docs: `http://127.0.0.1:8000/api/v1/docs/`

---

## 3. Native Flutter Application Setup & Build Guide

### Directory Structure (`flutter_app/lib/`)
```text
lib/
  core/
    api/api_endpoints.dart
    authentication/token_storage.dart
    constants/app_constants.dart
    errors/api_exception.dart
    networking/dio_client.dart
    routing/app_router.dart
    storage/preferences_storage.dart
    theme/app_colors.dart
    theme/app_theme.dart
    utils/l10n.dart
    widgets/adaptive_scaffold.dart
    widgets/state_views.dart
  shared/
    models/platform_models.dart
    widgets/ta3alm_cards.dart
  features/
    auth/
    profile/
    home/
    students/
    courses/
    lectures/
    exams/
    grades/
    payments/
    notifications/
    messaging/
    settings/
  main.dart
```

### Running the Flutter App

1. **Install Dependencies**:
   ```powershell
   F:
   cd F:\work\ta3alm\flutter_app
   flutter pub get
   ```

2. **Run Connected to Production (`https://ta3alm.online/api/v1`)**:
   ```powershell
   flutter run
   ```

3. **Run Connected to Local Django Server**:
   - Android Emulator:
     ```powershell
     flutter run --dart-define=API_BASE_URL=http://10.0.2.2:8000/api/v1
     ```
   - Physical Device / Windows / Web:
     ```powershell
     flutter run --dart-define=API_BASE_URL=http://127.0.0.1:8000/api/v1
     ```

### Building Production Android Release (APK & App Bundle)

1. **Build Split-per-ABI Release APK**:
   ```powershell
   cd F:\work\ta3alm\flutter_app
   flutter build apk --release --split-per-abi --dart-define=API_BASE_URL=https://ta3alm.online/api/v1
   ```
   Output APKs: `flutter_app/build/app/outputs/flutter-apk/`

2. **Build Google Play App Bundle (AAB)**:
   ```powershell
   cd F:\work\ta3alm\flutter_app
   flutter build appbundle --release --dart-define=API_BASE_URL=https://ta3alm.online/api/v1
   ```
   Output AAB: `flutter_app/build/app/outputs/bundle/release/app-release.aab`

---

## 4. Deploying Backend Updates to GitHub & Vercel

```powershell
F:
cd F:\work\ta3alm
git add .
git commit -m "feat: add complete DRF API v1 (/api/v1/), automated test suite, and native Flutter mobile/tablet application"
git push origin main
```

