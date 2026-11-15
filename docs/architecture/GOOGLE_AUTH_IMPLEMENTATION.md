# GOOGLE_AUTH_IMPLEMENTATION — توثيق تسجيل الدخول عبر Google وروابط الدخول المباشر

## 1. نظرة عامة
تم تنفيذ مصادقة Google في تطبيق Flutter بحيث تعمل **بنفس منطق الموقع الأصلي (Django Allauth)** وتصدر **رموز JWT + DRF Token** للمستخدم مع ربط حسابه بـ `SocialAccount` في قاعدة البيانات.

---

## 2. مسارات الخادم (`api_v1/views_auth.py` & `api_v1/urls.py`)

### أ. تسجيل الدخول الأصلي بالتوكن (`POST /api/v1/auth/google/`)
- **الكلاس**: `GoogleLoginAPIView`
- **المدخلات**:
  - `id_token`: توكن الهوية من `google_sign_in` على Android/iOS/Web.
  - `access_token`: توكن الوصول من Google كبديل احتياطي.
  - `role`: الدور المطلوب في حالة إنشاء حساب جديد (`student` | `teacher` | `assistant`، الافتراضي `student`).
- **التحقق الأمني على الخادم**:
  1. إذا أُرسل `id_token`، يتحقق الخادم عبر `https://oauth2.googleapis.com/tokeninfo?id_token=...` ويتأكد من `email_verified`.
  2. إذا أُرسل `access_token`، يتحقق الخادم عبر `https://www.googleapis.com/oauth2/v3/userinfo`.
  3. يبحث عن المستخدم بالبريد الإلكتروني (`email__iexact`)؛ وإن لم يوجد يُنشئ مستخدماً جديداً بالدور المحدد (`role`) مع توليد `custom_id` تلقائياً، ويربطه بسجل `SocialAccount(provider='google')`.
  4. يتحقق من `user.is_banned`: إذا كان محظوراً يرفض الدخول برسالة واضحة (`403 Forbidden`).
  5. يُرجع `{ "access": ..., "refresh": ..., "token": ..., "user": UserDetailSerializer }`.

### ب. جسر المتصفح الاحتياطي (`GET /api/v1/auth/google/callback/`)
- **الكلاس**: `GoogleMobileCallbackView`
- **الاستخدام**: إذا لم يكن `google_sign_in` مضبوطاً بعد بـ `SHA-1` على جهاز التطوير، يفتح التطبيق رابط Google OAuth عبر المتصفح على الخادم (`https://www.ta3alm.online/accounts/google/login/?next=/api/v1/auth/google/callback/?role=...`).
- بعد تسجيل الدخول عبر Google في المتصفح، يُنشئ الخادم رمز `OneTimeLoginLink` صالحاً لمدة 15 دقيقة ولمرة واحدة ويعرضه للمستخدم لنسخه ولصقه في شاشة الدخول المباشر بالتطبيق.

### ج. الدخول بالرابط أو الكود المؤقت (`POST /api/v1/auth/one-time-login/`)
- **الكلاس**: `OneTimeLoginAPIView`
- يقبل الكود (`UUID`) أو الرابط الكامل (`https://ta3alm.online/login/auto/<uuid>/`) ويستخرج الـ `UUID`، يتحقق من `OneTimeLoginLink.is_valid()`، يعلّمه كمستخدم (`is_used = True`)، ويُسجّل دخول المستخدم ويعيد نفس استجابة JWT.

---

## 3. التنفيذ في تطبيق Flutter (`flutter_app`)

1. **`flutter_app/pubspec.yaml`**:
   - تمت إضافة حزمة `google_sign_in: ^6.2.1`.
2. **`flutter_app/lib/core/api/api_endpoints.dart`**:
   - `googleLogin = '/auth/google/'`
   - `oneTimeLogin = '/auth/one-time-login/'`
   - `googleCallbackUrl({String role = 'student'})`
3. **`flutter_app/lib/features/auth/providers/auth_provider.dart`**:
   - `loginWithGoogle({String role = 'student'})`: يستدعي `GoogleSignIn(scopes: ['email', 'profile']).signIn()` ثم يرسل `idToken` و `accessToken` إلى `POST /api/v1/auth/google/` ويحفظ التوكنات وبيانات المستخدم.
   - `loginWithOneTimeToken(String tokenOrUrl)`: يرسل الرمز إلى `POST /api/v1/auth/one-time-login/`.
4. **`flutter_app/lib/features/auth/presentation/login_screen.dart` و `register_screen.dart`**:
   - زر **المتابعة باستخدام Google** في تسجيل الدخول وفي التسجيل مع اختيار الدور (`طالب` / `معلم` / `مساعد`).
   - نافذة احتياطية للدخول عبر المتصفح + إدخال كود/رابط الدخول المباشر في حال تعذر Google Play Services أو عدم إضافة بصمة SHA-1.

---

## 4. خطوات التفعيل النهائية على Google Cloud Console (للنشر على Android)
1. استخراج بصمة `SHA-1` لمفتاح التوقيع (`debug` و `release`).
2. إضافة عميل **Android OAuth 2.0 Client ID** في Google Cloud Console بنفس الـ `package name` و `SHA-1`.
3. التأكد من وجود **Web Client ID** في نفس المشروع حتى يعود `googleAuth.idToken` غير فارغ على Android.

