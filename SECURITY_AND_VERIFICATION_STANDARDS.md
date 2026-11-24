# المعايير الشاملة للأمن والأمان والتشفير والتحقق — منصة تعلّم (Ta3alm Platform)

> **مرجع هندسي وأمني موثّق من الشيفرة المصدرية الفعلية للمنصة**  
> يوثّق هذا المستند جميع معايير وسياسات الدفاع الأمني، والتشفير، والتوقيع الرقمي، والتحقق من الهوية، وسلامة التطبيق والأجهزة، وحماية المحتوى المرئي، ومكافحة التلاعب، والضوابط المالية والرقابية المطبّقة فعلياً في **الخادم (Django 6.0 / DRF)**، و**تطبيق الموبايل (Flutter / Android Kotlin)**، و**بوابة الويب (Web / HTML / JS)**.

---

## فهرس الأقسام

1. [الفلسفة الأمنية وترتيب طبقات الوسائط (Middleware Stack)](#1-الفلسفة-الأمنية-وترتيب-طبقات-الوسائط-middleware-stack)
2. [أمن طبقة النقل والشبكة ومقاومة MITM](#2-أمن-طبقة-النقل-والشبكة-ومقاومة-mitm)
3. [التشفير، اشتقاق المفاتيح، وتوقيع الطلبات (HMAC & Anti-Replay)](#3-التشفير-اشتقاق-المفاتيح-وتوقيع-الطلبات-hmac--anti-replay)
4. [المصادقة، الجلسات، التحقق بالـ OTP، و OAuth](#4-المصادقة-الجلسات-التحقق-بالـ-otp-و-oauth)
5. [بصمة الجهاز، ربط العتاد العابر للمنصات، وبوابة الإقلاع (Boot Gate)](#5-بصمة-الجهاز-ربط-العتاد-العابر-للمنصات-وبوابة-الإقلاع-boot-gate)
6. [سلامة التطبيق، فحص وقت التشغيل الأصلي، و Play Integrity](#6-سلامة-التطبيق-فحص-وقت-التشغيل-الأصلي-و-play-integrity)
7. [حماية الفيديو، منع التقاط الشاشة، والعلامة المائية](#7-حماية-الفيديو-منع-التقاط-الشاشة-والعلامة-المائية)
8. [محرك المخاطر السلوكي والتدقيق الأمني بالذكاء الاصطناعي](#8-محرك-المخاطر-السلوكي-والتدقيق-الأمني-بالذكاء-الاصطناعي)
9. [ضوابط الصلاحيات والوصول المبنية على الأدوار (RBAC)](#9-ضوابط-الصلاحيات-والوصول-المبنية-على-الأدوار-rbac)
10. [محرك مكافحة الألفاظ القبيحة والشتائم المموّهة](#10-محرك-مكافحة-الألفاظ-القبيحة-والشتائم-المموّهة)
11. [الأمن المالي (Paymob HMAC)، واجهة البوت، وتحصين الويب (F12)](#11-الأمن-المالي-paymob-hmac-واجهة-البوت-وتحصين-الويب-f12)
12. [الأمن في تحديثات التطبيق (APK SHA-256 & EOCD & FileProvider Jail)](#12-الأمن-في-تحديثات-التطبيق-apk-sha-256--eocd--fileprovider-jail)
13. [أمن قاعدة البيانات والوسائط والخصوصية ومراجعات الإنتاج](#13-أمن-قاعدة-البيانات-والوسائط-والخصوصية-ومراجعات-الإنتاج)

---

## 1. الفلسفة الأمنية وترتيب طبقات الوسائط (Middleware Stack)

تعتمد المنصة مبدأ **الدفاع متعدد الطبقات (Defense-in-Depth)** مع قاعدة صارمة: **Zero Client Trust**؛ فلا يُؤتمن أي بيان أو عنوان IP أو بصمة أو صلاحية يرسلها العميل إلا بعد التحقق التشفيري أو المطابقة الخادمية.

### تسلسل الـ 21 طبقة وسائط في Django (`ta3alm_project/settings.py`)
تُنفَّذ الطبقات بهذا الترتيب المُلزم لكل طلب وارد:

| # | الوسيط (Middleware) | المصدر | الوظيفة الأمنية |
|---|---|---|---|
| 1 | `SubdomainAdminMiddleware` | `ta3alm_project/middleware/routing.py` | عزل وتوجيه نطاق الإدارة الفرعي `admin.*` داخلياً نحو `/admin-panel/` |
| 2 | `FrontendHardeningMiddleware` | `ta3alm_project/middleware/platform.py` | إزالة تعليقات HTML ديناميكياً + حقن ترويسات الحماية الأمنية وإزالة بصمة الخادم |
| 3 | `SecurityMiddleware` | Django Core | فرض HTTPS / HSTS وترويسات الحماية الافتراضية |
| 4 | `CorsMiddleware` | `django-cors-headers` | تطبيق سياسة CORS حصراً على `/api/.*` مع حصر الترويسات المسموحة |
| 5 | `WhiteNoiseMiddleware` | WhiteNoise | تقديم الملفات الثابتة بأمان دون كشف المجلدات |
| 6 | `SessionMiddleware` | Django Core | إدارة الجلسات المحمية |
| 7 | `LocaleMiddleware` | Django Core | ضبط اللغة دون التأثير على مسارات الحماية |
| 8 | `CommonMiddleware` | Django Core | تنسيق المسارات الآمن |
| 9 | `CsrfViewMiddleware` | Django Core | منع تزوير الطلبات عبر المواقع (CSRF) على الويب |
| 10 | `AuthenticationMiddleware` | Django Core | تحميل هوية المستخدم المصادق من الجلسة |
| 11 | `TokenAuthMiddleware` | `ta3alm_project/middleware/auth.py` | توثيق طلبات الويب القادمة بتوكن من التطبيق أو الجسر |
| 12 | `BanMiddleware` | `ta3alm_project/middleware/auth.py` | عزل الحساب المحظور فوراً (`403` أو `core/security_boot_gate.html`) |
| 13 | `EmailVerificationMiddleware` | `ta3alm_project/middleware/auth.py` | إجبار جميع الحسابات غير الإدارية على تفعيل البريد بالـ OTP قبل أي استخدام |
| 14 | `GenderCompletionMiddleware` | `ta3alm_project/middleware/auth.py` | إجبار الحسابات (الجديدة والقديمة) على استكمال حقل النوع (`male`/`female`) |
| 15 | `WebDeviceSecurityMiddleware` | `ta3alm_project/middleware/web_device.py` | توثيق متصفح الويب بكوكي مُوقّع `ta3alm_web_inst_id` وفحص بوابة الإقلاع وتماسك `fp_v1` |
| 16 | `AppVersionEnforcementMiddleware` | `ta3alm_project/middleware/platform.py` | مقارنة `X-App-Build` بالحد الأدنى وإرجاع `426 APP_UPDATE_REQUIRED` عند القدم |
| 17 | `ApiSecurityAndActivityAuditMiddleware` | `ta3alm_project/middleware/api_audit.py` | فحص بوابة الإقلاع على الـ API، التحقق من توقيع HMAC، تسجيل النشاط، وتشغيل الفحص الساعي للـ AI |
| 18 | `MessageMiddleware` | Django Core | رسائل النظام |
| 19 | `XFrameOptionsMiddleware` | Django Core | فرض `X_FRAME_OPTIONS = 'DENY'` لمنع Clickjacking |
| 20 | `AccountMiddleware` | `django-allauth` | إدارة حسابات OAuth |
| 21 | `MaintenanceMiddleware` | `ta3alm_project/middleware/platform.py` | قفل المنصة في وضع الصيانة (`503`) مع استثناء الإدارة والأجهزة المعتمدة في `maintenance_approved_devices` |

---

## 2. أمن طبقة النقل والشبكة ومقاومة MITM

### 2.1 إعدادات الخادم في الإنتاج (`not DEBUG` — `ta3alm_project/settings.py`)
- **التحويل الإجباري لـ HTTPS:**
  - `SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')`
  - `SECURE_SSL_REDIRECT = True`
  - **الاستثناء الوحيد:** `SECURE_REDIRECT_EXEMPT = [r'^\.well-known/assetlinks\.json$']` لضمان عمل فحص Android App Links عبر المسار القياسي إذا لزم.
- **سياسة HSTS الصارمة:**
  - `SECURE_HSTS_SECONDS = 31536000` (سنة كاملة)
  - `SECURE_HSTS_INCLUDE_SUBDOMAINS = True`
  - `SECURE_HSTS_PRELOAD = True`
- **تأمين الكوكيز ومنع التضمين:**
  - `SESSION_COOKIE_SECURE = True`
  - `CSRF_COOKIE_SECURE = True`
  - `X_FRAME_OPTIONS = 'DENY'`
- **ترويسات تحصين المتصفح (`FrontendHardeningMiddleware`):**
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Permissions-Policy: camera=(), microphone=(), geolocation=()`
  - إزالة ترويسات `Server` و `X-Powered-By` من جميع الاستجابات لمنع بصمة الخادم (Server Fingerprinting).

### 2.2 إعدادات CORS وحدود المعدل (Rate Limiting — `ta3alm_project/settings.py`)
- `CORS_URLS_REGEX = r'^/api/.*$'`
- `CORS_ALLOW_CREDENTIALS = True`
- `CORS_ALLOW_HEADERS` تقتصر على القائمة القياسية مضافاً إليها **18 ترويسة أمنية مخصّصة**:
  - `x-device-id`, `x-installation-id`, `x-hardware-id`, `x-device-model`, `x-device-gpu`
  - `x-vpn-active`, `x-dev-options`, `x-adb-enabled`, `x-proxy-detected`, `x-port-forwarding`, `x-abnormal-dns`
  - `x-app-build`, `x-app-version`, `x-client-platform`
  - `x-ta3alm-ts`, `x-ta3alm-nonce`, `x-ta3alm-sig`, `x-ta3alm-client`
- **تحديد المعدل (DRF Throttling):**
  - الزوار المجهولون (`anon`): `300/hour`
  - المستخدمون المصادقون (`user`): `3000/hour`
  - تقسيم الصفحات (`PAGE_SIZE`): `20` عنصراً لمنع سحب قواعد البيانات (Scraping).

### 2.3 سياسة أمان شبكة أندرويد (`network_security_config.xml` & `AndroidManifest.xml`)
- منع كامل للاتصالات غير المشفرة: `android:usesCleartextTraffic="false"` و `cleartextTrafficPermitted="false"`.
- **رفض شهادات المستخدم (Anti-MITM على مستوى النظام):**
  ```xml
  <trust-anchors>
      <certificates src="system" />
  </trust-anchors>
  ```
  لا يقبل التطبيق أي شهادة جذر مثبتة في مخزن المستخدم (`user`) سواء على النطاق العام أو على `ta3alm.online` (بما فيها النطاقات الفرعية `includeSubdomains="true"`).

### 2.4 محوّل الشبكة المحصّن في فلاتر (`flutter_app/lib/core/security/secure_http_adapter_io.dart`)
- فرض الاتصال المباشر وتجاوز إعدادات بروكسي الجهاز أو الشبكة:
  - `httpClient.findProxy = (Uri _) => 'DIRECT';`
- رفض أي شهادة TLS غير صالحة قطعياً (`badCertificateCallback` يرجع `false`).
- فحص **Issuer** و **Subject** للشهادة ضد **12 بصمة لأدوات اعتراض الشبكة والتنصت**:
  - `portswigger`, `burp`, `charles`, `fiddler`, `mitmproxy`, `reqable`, `httpcanary`, `proxyman`, `packet capture`, `do_not_trust`, `adguard`, `fiddlerroot`.

### 2.5 رصد عنوان IP الحقيقي على الخادم (`api_v1/services/device_security/network.py`)
- يُستخرج عنوان IP للمستخدم حصراً من ترويسات الخادم الموثوقة بالترتيب:
  1. `HTTP_CF_CONNECTING_IP`
  2. `HTTP_X_REAL_IP`
  3. `HTTP_X_FORWARDED_FOR`
  4. `REMOTE_ADDR`
- لا يُعتد مطلقاً بأي IP يُرسل داخل جسم JSON، وتتم معالجة الشبكات المتنقلة (CGNAT) بوعي دون حظر على تغيّر IP منفرد بل بفحص الانتقالات الجغرافية السريعة (أكثر من `800 km/h` خلال 60 دقيقة).

---

## 3. التشفير، اشتقاق المفاتيح، وتوقيع الطلبات (HMAC & Anti-Replay)

### 3.1 التوقيع التشفيري لجميع طلبات الـ API (`request_signing.py` & `request_signer.dart`)
- **الفرض الإلزامي:** يُفرض توقيع HMAC بدءاً من رقم البناء `MIN_SIGNED_NATIVE_BUILD = 6` (`SecurityPolicyConfig.enforce_request_signatures = True`). تجريد التوقيع من بناء `>= 6` يُرجع فوراً `403 MISSING_REQUEST_SIGNATURE` ويرفع المخاطرة إلى مستوى حرج.
- **اشتقاق المفتاح السري المشترك (`Key Derivation`):**
  - يتكوّن المفتاح في التطبيق والخادم من 4 شظايا (`_SHARD_A`..`_SHARD_D`) يُفك قناعها عبر:
    `raw_byte = enc_byte ^ _MASK_SEQ[i] ^ ((shard_idx * 19 + i * 7) & 0xFF)`
  - يُدمج الناتج مع الملح الثابت `b'ta3alm.edge.hmac.v2'` ويُختزل عبر `SHA-256` للحصول على مفتاح HMAC من 256-bit (مع إمكانية تجاوزه أو تعزيزه بيئياً عبر `TA3ALM_CLIENT_SIGNING_SECRET`).
- **الترويسات المطلوبة في كل طلب موقّع:**
  - `X-Ta3alm-Ts`: الطابع الزمني Unix بالثواني.
  - `X-Ta3alm-Nonce`: قيمة عشوائية تشفيرية بطول **16 بايت** (`Random.secure()` في التطبيق).
  - `X-Ta3alm-Sig`: التوقيع التشفيري.
  - `X-Ta3alm-Client`: معرّف العميل.
- **بناء السلسلة القانونية والتوقيع:**
  ```text
  Canonical String = "{METHOD}|{PATH}|{ts}|{nonce}|{body_sha256}|{device_id}"
  Signature        = HMAC-SHA256(key, Canonical String).hexdigest()
  ```
  يُقارن التوقيع على الخادم بزمن ثابت عبر `hmac.compare_digest`.
- **منع إعادة الإرسال (Anti-Replay Protection):**
  - نافذة الانحراف الزمني المسموحة: `max(request_signature_max_skew_seconds, 60)` والافتراضي **`300 ثانية` (5 دقائق)**.
  - يُسجَّل كل `nonce` في الـ Cache فور استخدامه عبر `cache.add` (ذرية: تُرجع `False` إن وُجد مسبقاً) بالمفتاح:
    `ta3alm:sig_nonce:{sha256(device_id:nonce)}` لمدة `max_skew + 30` ثانية.
  - أي تكرار للـ Nonce أو إخفاق في التوقيع يسجّل حدث `replay_attack` أو `request_tamper` بدرجة خطر `risk_score = 95` ويزيد العداد `risk_delta = 90`.

### 3.2 جدول المفاتيح والأملاح التشفيرية المستقلة في المنصة

| الغرض | آلية الاشتقاق / الخوارزمية | الملح (Salt / Context) | المصدر |
|---|---|---|---|
| توقيع طلبات الـ API | `HMAC-SHA256` من شظايا مقنّعة أو `TA3ALM_CLIENT_SIGNING_SECRET` | `ta3alm.edge.hmac.v2` | `api_v1/services/security_engine/request_signing.py` |
| بصمة الجهاز والعتاد `fp_v1` / `DEV-XXXXXXXX` | `HMAC-SHA256` بمفتاح `SHA-256` لـ `DEVICE_FINGERPRINT_SECRET \|\| SECRET_KEY` | `ta3alm-device-fp-key:` و `hw_id_v1:` | `api_v1/services/device_security/fingerprint.py`, `hardware.py` |
| توكنات JWT للمصادقة | `HS256` باستخدام `settings.SECRET_KEY` + `UUID4 jti` | — | `api_v1/authentication.py` |
| توكنات تشغيل الفيديو | `HS256` بمفتاح `VIDEO_SIGNING_SECRET` أو `SHA-256` مشتق | `ta3alm-video-jwt-v1:` | `api_v1/services/video_security/playback.py` |
| تشفير/ختم مرجع الفيديو (Stream XOR + MAC) | Keystream `HMAC-SHA256` بالعداد + وسم `16 bytes` | `ta3alm-yt-seal\|{session_id}` | `api_v1/services/video_security/sealing.py` |
| توقيع كوكي متصفح الويب | `django.core.signing.TimestampSigner` | `ta3alm-web-device-v1` | `ta3alm_project/middleware/web_device.py` |
| رمز سحب الإشعارات بالخلفية | `TimestampSigner` مربوط ببصمة كلمة المرور `sha256(password)[:12]` | `_PULL_SIGNER` | `core/services/notifications/pull_tokens.py` |
| رمز الرد السريع للدعم (Android) | `TimestampSigner` مقيد بـ `(uid, thread_id, password_epoch)` | `ta3alm.support.quick_reply.v1` | `core/services/notifications/pull_tokens.py` |
| رمز تغيير كلمة المرور عبر البوت | `django.core.signing.dumps/loads` | `bot-action-v1` | `bot_api/views.py` |
| التحقق المالي Paymob Callback | `HMAC-SHA512` باستخدام `settings.PAYMOB_HMAC_SECRET` | 20 حقلاً متسلسلاً | `teachers/views/payments.py` |

---

## 4. المصادقة، الجلسات، التحقق بالـ OTP، و OAuth

### 4.1 دورة حياة JWT و DRF Token (`api_v1/authentication.py`, `api_v1/views/auth/login.py`)
- **صلاحية الرموز:**
  - `ACCESS_TOKEN_LIFETIME = timedelta(hours=12)` (12 ساعة)
  - `REFRESH_TOKEN_LIFETIME = timedelta(days=30)` (30 يوماً)
  - الخوارزمية: `HS256` عبر `PyJWT`.
  - كل إصدار يحمل معرّفين فريدين `access_jti` و `refresh_jti` (`UUID4`) مع ربطهما الفوري بجدول `DeviceSession`.
- **التحقق عند كل طلب (`JWTAndTokenAuthentication`):**
  1. قراءة `Bearer <jwt>` أو `Token <drf_key>`.
  2. رفض الحساب المحظور فوراً (`403 ACCOUNT_BANNED`, `is_banned: True`).
  3. فحص حظر الجهاز عبر `get_active_device_block` باستخدام `installation_id` و `hardware_id`.
  4. فحص `RegisteredDevice.trust_status`:
     - `BLOCKED` ⬅️ `403 DEVICE_BLOCKED`
     - `REVOKED` ⬅️ `401 DEVICE_REVOKED`
  5. فحص حالة `DeviceSession` للـ `token_jti`: إذا كانت `revoked` أو `logged_out` يُرفض فوراً (`401 SESSION_REVOKED`).
- **تدوير رمز التحديث (`TokenRefreshAPIView`):** يتحقق مجدداً من عدم حظر الحساب أو الجهاز وعدم إبطال `refresh_jti` وعدم سحب ثقة الجهاز قبل تدوير الرموز إلى `access_jti` و `refresh_jti` جديدين.

### 4.2 التخزين الآمن على تطبيق أندرويد (`flutter_app/lib/core/authentication/token_storage.dart`)
- يُستخدم `FlutterSecureStorage` مع تفعيل تشفير عتاد/نظام أندرويد:
  `AndroidOptions(encryptedSharedPreferences: true)`.
- تُولَّد هوية التثبيت عبر مولّد عشوائي تشفيري `Random.secure()` بطول 256 بت (`inst_<64hex>`) وتبقى ثابتة في التخزين المشفّر حتى بعد تسجيل الخروج لمنع التهرب من حدود الأجهزة أو الحظر.

### 4.3 المصادقة متعددة الحقول والحماية من هجمات التوقيت (`accounts/backends.py`)
- يدعم `MultiFieldAuthBackend` الدخول بـ: `username__iexact`، أو `email__iexact`، أو `phone` (بالإضافة للدعم في `LoginAPIView` لـ `custom_id`).
- **الحماية من Timing Attacks:** عند عدم العثور على المستخدم يتم تشغيل `User().set_password(password)` وهمياً لتنفيذ نفس زمن دالة التجزئة ومنع المهاجم من استنتاج وجود الحساب عبر قياس زمن الاستجابة.
- **مدققات كلمة المرور (`ta3alm_project/settings.py`):** تفعيل المدققات الأربعة في Django (`UserAttributeSimilarityValidator`, `MinimumLengthValidator`, `CommonPasswordValidator`, `NumericPasswordValidator`).
- **تحقيق التسجيل الإلزامي (`api_v1/views/auth/registration.py`, `accounts/models.py`):**
  - إلزامية اختيار النوع (`gender`: `male` / `female`) عند التسجيل أو عبر الوسيط `GenderCompletionMiddleware` للمستخدمين القدامى غير الإداريين.
  - اشتراط رقم قومي مصري فريد من `14 رقماً` (`national_id`) ورقم هاتف فريد لا يقل عن `11 رقماً` عند استكمال الملف الشخصي (`CompleteProfileAPIView`).
- **حماية فشل الدخول المتكرر (`LoginAPIView`):** تسجيل حدث `login_failed` (`risk_delta=10`) ومراقبة بلوغ `>= 5` محاولات فاشلة خلال `10 دقائق` لتوليد إنذار أمني `excessive_login_attempts` (`risk_score=35`, `severity='medium'`).

### 4.4 التحقق من البريد الإلكتروني بالـ OTP (`accounts/email_verification.py` & `api_v1/views/auth/otp.py`)
- **إلزامية التفعيل:** لجميع الحسابات غير الإدارية عبر `EmailVerificationMiddleware` و `IsNotBanned` (`403 EMAIL_VERIFICATION_REQUIRED`).
- **توليد الرمز والرابط:**
  - رمز مكوّن من 6 أرقام عبر مولّد الأرقام العشوائية التشفيري `secrets.randbelow(900000) + 100000`.
  - معرّف رابط `uuid.uuid4()`.
  - مدة الصلاحية: `VERIFICATION_TTL_MINUTES = 30` دقيقة.
- **الحماية أثناء التفعيل وإعادة الإرسال:**
  - تنفيذ التحقق داخل معاملة ذرية `@transaction.atomic` مع قفل صفّي (`select_for_update()`) ومقارنة الرمز بزمن ثابت `secrets.compare_digest(raw_code, verification.code)`.
  - التحقق من عدم استخدام رابط يخص مستخدماً آخر (`403 INVALID_TOKEN`).
  - فرض فترة تهدئة لإعادة الإرسال: `60 ثانية` افتراضياً (`429 RESEND_COOLDOWN`).
  - تنقية النصوص والروابط بالـ `html.escape` داخل قالب رسالة التفعيل.

### 4.5 تسجيل الدخول عبر Google OAuth (`api_v1/views/auth/google.py` & `auth_service.py`)
- لا يكتفي الخادم ببيانات الحساب المرسلة من التطبيق بل يتحقق مباشرة من صحة الرموز عبر خوادم Google الرسمية:
  - فحص `id_token` عبر `https://oauth2.googleapis.com/tokeninfo` مع اشتراط `email_verified` (`True`/`'true'`/`'1'`).
  - أو فحص `access_token` عبر `https://www.googleapis.com/oauth2/v3/userinfo`.
- الحسابات المنشأة عبر Google تحصل على `set_unusable_password()` حتى يختار المستخدم تعيين كلمة مرور.
- **جسر الموبايل (`GoogleMobileCallbackView`):** يصدر رمز دخول أحادي الاستخدام `OneTimeLoginLink` (`UUID` صالح لمدة `15 دقيقة` ويُستهلك لمرة واحدة فقط `is_used=True`).

---

## 5. بصمة الجهاز، ربط العتاد العابر للمنصات، وبوابة الإقلاع (Boot Gate)

### 5.1 تنقية هوية التثبيت (`validate_installation_id` — `device_security/fingerprint.py`)
- يُشترط أن يتراوح طول `installation_id` بين **8 و 128 حرفاً** ويطابق التعبير النمطي:
  `^[A-Za-z0-9._:-]+$`
- يُرفض نهائياً أي معرّف يحتوي على `@` أو صيغة بريد إلكتروني أو اسم مستخدم لمنع استخدام الهويات المقروءة كبصمة جهاز.

### 5.2 البصمة التشفيرية المُرقّمة الإصدار `fp_v1` (`device_security/fingerprint.py`)
- يُشتق المفتاح عبر `SHA-256("ta3alm-device-fp-key:" + (DEVICE_FINGERPRINT_SECRET or SECRET_KEY))`.
- تُبنى ثلاثة توقيعات `HMAC-SHA256`:
  1. `core_hash`: المكونات الصلبة غير المتغيرة (المُصنّع، الموديل، معمارية المعالج، GPU، دقة الشاشة، الحزمة، وشهادة التوقيع).
  2. `supporting_hash`: السمات التكميلية القابلة للتحديث (نسخة النظام، API level، نسخة التطبيق والمثبّت).
  3. `combined_hash`: `fp_v1:<hexdigest>` يجمع البصمتين مع `installation_id`.
- **قياس الانحراف (`Drift Score`):**
  - تغيّر السمات الجوهرية للويب (`WEB_STRICT_CORE_FIELDS`): `+90`
  - تغيّر السمات الجوهرية للموبايل: `+55`
  - تغيّر شهادة توقيع الـ APK (`signing_cert_sha256`): `+45`
  - تغيّر اسم الحزمة (`package_name`): `+40`
  - التحديثات الطبيعية للنظام أو نسخة التطبيق تُحتسب بانحراف منخفض (`<= 10`) دون عقوبة.
  - معالجة استثناء واحد آمن عند ترقية تصفح `Apple Safari` على iPad من وضع macOS إلى iPadOS عند تأكيد `maxTouchPoints`.

### 5.3 معرّف العتاد الموحد العابر للمنصات `DEV-XXXXXXXX` (`device_security/hardware.py`)
- يحسب الخادم معرّفاً موحداً بصيغة `DEV-XXXXXXXX` (`HMAC-SHA256` مقطوع إلى 8 خانات سداسية عشرية كبيرة).
- في كروميوم والويب، ينزع `_normalize_gpu_core` غلاف `ANGLE (...)` لتطابق GPU مع التبليغ الأصلي على أندرويد.
- يربط هذا المعرّف **سجل تطبيق الأندرويد وسجل متصفح الويب لنفس الهاتف المادي** معاً؛ لذا فإن حظر هاتف من أي جهة (`DeviceBlock`) يغلق تلقائياً كلا من التطبيق والمتصفح على نفس الجهاز.

### 5.4 كشف تزوير المتصفح وبصمة الويب (`device_security/web.py` & `web_device.py`)
- يُخصَّص لكل متصفح كوكي مُوقّع تشفيرياً `ta3alm_web_inst_id` عبر `TimestampSigner(salt='ta3alm-web-device-v1')` بخيارات `HttpOnly`, `SameSite=Lax`, صلاحية سنة، و`Secure` في الإنتاج.
- يتحقق `detect_web_fingerprint_spoofing` من:
  - وجود أداة أتمتة (`navigator.webdriver`).
  - تعارض `Sec-CH-UA-Platform` مع `User-Agent` و `navigator.platform`.
  - ظهور معالجات رسوميات مكتبية أو محاكاة (`NVIDIA`, `GeForce`, `Direct3D`, `Intel`, `SwiftShader`, `llvmpipe`, `VMware`, `VirtualBox`) خلف هوية متصفح يدّعي أنه iPhone/iPad.
  - التحقق من `maxTouchPoints` لكشف محاكاة أجهزة الجوال من خلال F12 DevTools.

### 5.5 بوابة الأمان قبل التحميل (`Pre-Load Boot Security Gate` — `device_security/boot_gate.py`)
تُفحَص هذه البوابة في كل من الويب والـ API وتطبيق فلاتر **قبل تجاوز شاشة التحميل الأولى**:

1. **فحص حظر الجهاز (`DEVICE_BLOCKED`):** مطابقة عبر `installation_id` و `hardware_id` وسمات العتاد العابرة للمنصات. (الحظر المؤقت `temporary` يُفك تلقائياً فور انتهاء `expires_at`).
2. **فحص حظر الحساب (`ACCOUNT_BANNED`):** عبر جلسة/توكن المستخدم أو عبر وجود أي حساب محظور مرتبط بنفس الجهاز.
3. **فحص الـ VPN (`VPN_DETECTED`):** عبر كشف الخادم لموفري Cloudflare WARP / VPN ISP / ترويسات `Via` أو إبلاغ العميل عن واجهة VPN نشطة (يتبع إعداد `block_vpn_connections`).
4. **فحص خيارات المطور و USB Debugging (`DEV_OPTIONS_ENABLED`):** رصد `DEVELOPMENT_SETTINGS_ENABLED` أو `ADB_ENABLED` (يتبع إعداد `block_developer_options`).
5. **فحص الشبكة والبروكسي و DNS الشاذ (`ABNORMAL_NETWORK_OR_DNS`):** رصد `proxy_detected`, `port_forwarding_detected`, أو `abnormal_dns_detected` (يتبع إعداد `block_abnormal_dns_or_ports`).
6. **وضع الصيانة (`MAINTENANCE_MODE`):** يُرجع HTTP `503` لغير الإداريين، مع استثناء الأجهزة المضافة لقائمة السماح `maintenance_approved_devices` (`DEV-...`).

### 5.6 حدود الأجهزة المسجّلة (`SecurityPolicyConfig` — `api_v1/models/policy.py`)
- حد أجهزة الطالب: **`2` جهاز** (`student_device_limit`)
- حد أجهزة المساعد: **`3` أجهزة** (`assistant_device_limit`)
- حد أجهزة المعلم: **`5` أجهزة** (`teacher_device_limit`)
- الحد الأقصى للجلسات المتزامنة النشطة: **`2`** (`max_concurrent_sessions`)
- الحد الأقصى لجلسات تشغيل الفيديو المتزامنة: **`1`** (`max_concurrent_playback`)

---

## 6. سلامة التطبيق، فحص وقت التشغيل الأصلي، و Play Integrity

### 6.1 خدمة Google Play Integrity (`api_v1/integrity_service.py` & `PlayIntegrityBridge.kt`)
- **النونْس أحادي الاستخدام (`PlayIntegrityNonce`):**
  - صلاحية النونْس قبل الاستهلاك: `NONCE_TTL_SECONDS = 300` ثانية.
  - أقصى عمر مسموح لتوكن التحقق: `MAX_TOKEN_AGE_SECONDS = 300` ثانية.
  - ربط التشفير عبر `requestHash = sha256("ta3alm|{action}|{binding_data}|{nonce_id}")`.
  - استهلاك النونْس داخل `transaction.atomic()` مع `select_for_update()`؛ أي محاولة لإعادة تقديم التوكن تُرفض بـ `NONCE_ALREADY_USED` وتُقيّد كحادث حرج `token_replayed`.
- **فك التشفير والتحقق على الخادم:**
  - استدعاء `playintegrity` v1 `decodeIntegrityToken` باستخدام حساب خدمة Google (`PLAY_INTEGRITY_SERVICE_ACCOUNT_JSON`).
  - مقارنة بصمة شهادة توقيع الحزمة المستلمة مع `ANDROID_RELEASE_CERT_SHA256`.
  - العمل وفق 4 أوضاع سياسة (`strict`, `balanced`, `audit`, `dev_bypass`) وإصدار قرار `allow` / `warn` / `step_up` / `block` مع حفظ السجل في `DeviceIntegrityRecord`.

### 6.2 مفتّش الأمان الأصلي على أندرويد (`DeviceSecurityInspector.kt` & `risk.py`)
يفحص التطبيق أصلياً على مستوى Kotlin ويرسل الإشارات موقّعة إلى الخادم:

| فئة الفحص | الآلية التقنية في `DeviceSecurityInspector.kt` | رد الفعل في الخادم (`risk.py` & `registration.py`) |
|---|---|---|
| **أدوات الحقن و Frida** | فحص `/proc/self/maps` (`frida`, `gum-js-loop`, `gmain`, `xposed`, `edxposed`, `lsposed`, `substrate`) + فحص StackTrace لـ Xposed + فحص منافذ Frida TCP (`27042`, `27043`) | إضافة **`+90`** نقطة مخاطر + إبطال الجلسة فوراً (`APP_INTEGRITY_FAILED`) |
| **التوقيع والحزمة** | مقارنة شهادة الـ APK بـ `SHA-256`، واسم الحزمة (`online.ta3alm.ta3alm_flutter`)، و `installer_source` | إضافة **`+85`** نقطة مخاطر + رفض التشغيل (`APP_INTEGRITY_FAILED`) |
| **التنقيح (Debugger/Debug)** | فحص `FLAG_DEBUGGABLE` و `Debug.isDebuggerConnected()` | Debugger في Release **`+65`**، Debug build في الإنتاج **`+35`** |
| **كسر الحماية (Root)** | فحص 10 مسارات لـ `su` + وسوم البناء `test-keys` + 8 حزم (Magisk/SuperSU/Xposed/LSPosed) | إضافة **`+20`** نقطة مخاطر |
| **المحاكيات (Emulator)** | مؤشرات العتاد والبناء الوهمية للمحاكيات | إضافة **`+15`** نقطة مخاطر |
| **بروكسي وشهادات MITM** | قراءة `AndroidCAStore` والبحث عن 12 كلمة MITM CA + بروكسي النظام و PAC | رفع إنذار MITM وتفعيل `auto_block_on_proxy_mitm` (الحظر التلقائي) |
| **توجيه المنافذ المحلي و VPN و DNS** | فحص واجهات الشبكة (`tun`, `tap`, `ppp`, `wg`, `ipsec`, `pptp`, `l2tp`, `utun`) + مسح 8 منافذ بروكسي (`8080`, `8888`, `8889`, `8443`, `9090`, `9999`, `1080`, `3128`) + فحص `/proc/net/tcp{,6}` في حالة `0A` LISTEN + فحص `LinkProperties.dnsServers` و `private_dns_specifier` | حجب من بوابة الإقلاع (`VPN_DETECTED` / `ABNORMAL_NETWORK_OR_DNS`) |
| **جمع عتاد آمن (Privacy-Safe)** | استخدام `EGL14` / `GLES20` لاستخراج بصمة GPU فقط **دون جمع** IMEI أو MAC أو SSAID | تغذية معادلة `DEV-XXXXXXXX` |

### 6.3 تعمية وبناء نسخة الإصدار (`build.gradle.kts`, `proguard-rules.pro`, `AndroidManifest.xml`)
- **R8 / ProGuard:** `isMinifyEnabled = true` و `isShrinkResources = true` مع الإبقاء على نقطة ربط قنوات فلاتر و Play Integrity و ExoPlayer/Media3 فقط، وتعمية باقي الفئات.
- **تجريد السجلات الحساسة (`proguard-rules.pro`):** استخدام `-assumenosideeffects` لحذف كافة استدعاءات `android.util.Log.{isLoggable, v, d, i}` في نسخ Release.
- **التوقيع الإجباري:** دعم تواقيع `v1 + v2 + v3` مع إفشال البناء إذا فُعّل `TA3ALM_REQUIRE_RELEASE_SIGNING=true` دون توفر keystore الإصدار الرسمي.
- **حماية البيانات والروابط (`AndroidManifest.xml`):**
  - `android:allowBackup="false"` لمنع استخراج بيانات التطبيق عبر `adb backup`.
  - روابط التطبيق العميقة (App Links) مقصورة على HTTPS فقط مع `android:autoVerify="true"` وربطها بنقطة `/.well-known/assetlinks.json`.

---

## 7. حماية الفيديو، منع التقاط الشاشة، والعلامة المائية

### 7.1 منع تسجيل الشاشة والبث الخارجي (`MainActivity.kt` & `protected_screen_wrapper.dart`)
- **نظام FLAG_SECURE الدائم:**
  - يفرض `ProtectedScreenWrapper` تطبيق `FLAG_SECURE` قبل البناء الأول للشاشة المحمية، ويعيد فرضه عند `inactive` / `paused` / `resumed` و `didChangeMetrics`.
  - يثبّت `MainActivity.kt` الخاصية داخل `onSaveInstanceState`، `onResume`، `onWindowFocusChanged`، و `onConfigurationChanged`.
- **رصد التصوير (Screen Capture Callback — Android 14+ / API 34):**
  - صلاحية `android.permission.DETECT_SCREEN_CAPTURE` وربط `Activity.ScreenCaptureCallback` لإيقاف التشغيل فوراً وتسجيل حادث أمني على `/security/events/report/`.
- **منع الشاشات الخارجية واللاسلكية والافتراضية (Scrcpy / Miracast / HDMI):**
  - مراقب `DisplayManager.DisplayListener` في `MainActivity.kt` يكشف أي شاشة عرض ثانوية أو افتراضية (`Presentation` / Virtual Display) ويغلق المحتوى بواجهة تحذير مع تبليغ الخادم.

### 7.2 تشفير مراجع الفيديو ومنع تسريب الروابط (`api_v1/services/video_security/`)
- **توكن التشغيل قصير العمر:** `PLAYBACK_TOKEN_TTL_SECONDS = 180` ثانية (3 دقائق) يحمل `token_type='video_playback'`, `sub`, `lec`, `pkg`, `sid`, `dev`, `jti`, `iat`, `exp` موقعاً بـ `HS256`.
- **ختم معرّفات الفيديو (`seal_video_reference`):**
  - لا يُرسل معرّف يوتيوب أو الرابط السري مكشوفاً في استجابات الـ API.
  - يُشتق مفتاح تشفير مؤقت للجلسة: `HMAC-SHA256(playback_token, "ta3alm-yt-seal|{session_id}")`.
  - يُشفَّر النص `"{video_id}|{exp}"` بتدفق keystream مولَّد بالعداد (`HMAC-SHA256(key, counter)`) ثم يُلحق به وسم مصادقة **HMAC بطول 16 بايت** ويُرمّز بـ `urlsafe_b64`؛ وتُفك صحته بزمن ثابت `hmac.compare_digest` داخل السياق المصرّح له فقط.
- **توقيع بث CDN والوكيل الداخلي (`cdn_signing.py` & `views_video.py`):**
  - **Cloudflare Stream:** توقيع JWT بخوارزمية غير متماثلة `RS256` (`kid`, `exp`).
  - **Bunny Stream:** توقيع URL بخوارزمية `SHA-256` لمسار الفيديو وزمن الانتهاء.
  - **الوكيل الداخلي المحمي (`ProtectedVideoStreamProxyAPIView`):** بث مباشر من `/api/v1/videos/stream/<playback_token>/` مع التحقق الصارم من عدم خروج المسار عن المجلد المحمي (Anti-Path-Traversal: `target_path.startswith(private_root)`)، دعم `HTTP Range 206`، ومنع التخزين المؤقت (`Cache-Control: no-store, no-cache, must-revalidate, private` و `X-Content-Type-Options: nosniff`).
- **دعم جميع مصادر الفيديو المنظّفة (`Lecture.classify_video_source`):** YouTube / Shorts / Live، روابط بث مباشر (MP4, HLS `.m3u8`, DASH `.mpd`, WebM, Cloudinary)، Cloudflare Stream، Dropbox، GitHub Raw، Google Drive، Vimeo، Dailymotion، Loom وغيرها، مع تنظيف `<iframe>` قبل التخزين.

### 7.3 التزامن، النبضات، العلامة المائية، وقاعدة iOS فقط على الويب
- **تفرّد جلسة التشغيل (`MAX_CONCURRENT_SESSIONS = 1`):** تشغيل أي محاضرة يُبطل فوراً أي جلسة مشاهدة نشطة أخرى لنفس الحساب أو يتطلب الالتزام بالحد المسموح (`max_concurrent_playback = 1`).
- **النبض القلبي وكشف الشذوذ (`playback.py` & `constants.py`):**
  - فاصل النبضات: `HEARTBEAT_INTERVAL_SECONDS = 25` ثانية (مع إرسال Beacon عند الإغلاق `pagehide` / `beforeunload` في الويب).
  - نافذة استئناف المشاهدة دون خصم رصيد جديد: `VIEW_WINDOW_MINUTES = 20` دقيقة.
  - عتبة الشذوذ للمصادقة: `ANOMALY_AUTH_THRESHOLD = 25` طلباً خلال `ANOMALY_WINDOW_SECONDS = 300` ثانية.
- **العلامة المائية الديناميكية غير الكاشفة للهوية:**
  - تعرض: `student_code • ***last4phone • session_tag_8` بشفافية `0.28` وتتحرك موضعياً كل **`9 ثوانٍ`** لردع التصوير بكاميرا خارجية **مع عدم إظهار البريد الإلكتروني أو الرقم القومي لحماية الخصوصية**.
- **قصر تشغيل المحاضرات عبر الويب على أجهزة iPhone و iPad فقط:**
  - يتحقق كل من الخادم (`check_web_ios_only_lecture_access`) وواجهة فلاتر ويب (`WebPlatformGuardImpl`) من User-Agent، و`navigator.platform`، و`maxTouchPoints` (لدعم iPadOS Desktop Safari بلمس `>= 2` فقط)، ومعالج WebGL (`UNMASKED_RENDERER_WEBGL`) لمنع Windows/Linux/Android/macOS ومحاكاة F12 من تشغيل الفيديوهات عبر الويب.
- **الاستهلاك الذري لأكواد المشاهدة والباقات (`students/views/groups.py`, `packages.py`):**
  - قفل صفّي عبر `transaction.atomic()` + `select_for_update()` على سجل `VideoCode` و `VideoViewTracking` لمنع تكرار فتح المشاهدة مجاناً عبر الطلبات المتوازية (Race Condition Prevention).

---

## 8. محرك المخاطر السلوكي والتدقيق الأمني بالذكاء الاصطناعي

### 8.1 أوزان حساب المخاطر الفورية (`evaluate_and_apply_risk` & `behavioral.py`)
لا يُبنى الحظر على مؤشر ضعيف واحد (مثل VPN منفرد أو تغيّر IP متحرك)، بل يتراكم التقييم من عدة طبقات:

| المؤشر الأمني | نقاط الخطورة (Score Delta) | المصدر |
|---|---|---|
| تلاعب أو تزوير بصمة الويب (`web_spoof_reasons`) | **`+95`** (أو فشل توقيع/Replay **`+90`**) | `risk.py` / `api_audit.py` |
| رصد Frida أو Hooking أو تزوير حزمة/شهادة APK | **`+90` / `+85`** | `risk.py` |
| فشل فحص Play Integrity (`policy_decision == 'block'`) | **`+75`** | `risk.py` |
| اكتشاف Debugger في إصدار Release | **`+65`** | `risk.py` |
| تغيّر العتاد الأساسي في البصمة (`core_mismatch`) | **`+90`** (ويب) / **`+45`** (موبايل) | `risk.py` |
| تكرار التبديل (3+ حسابات على نفس الجهاز) أو Debug في الإنتاج | **`+35`** | `risk.py` |
| انتقال جغرافي سريع (`>= 800 km/h`) أو تعدد IP في ساعة (`>=4`) | **`+35`** / **`+20`** | `risk.py` / `behavioral.py` |
| جلسات أو دول متزامنة زائدة، أو فشل دخول متكرر | **`+30`** | `risk.py` |
| تدفق طلبات مفرط (`>= 65` طلب/دقيقة) | **`+20`** | `behavioral.py` |

- **عتبات مستويات الخطورة الافتراضية (`SecurityPolicyConfig`):**
  - `medium`: **`>= 30`**
  - `high`: **`>= 60`** (تفعيل طلب إعادة المصادقة `requires_reauth = True` + وضع `SUSPICIOUS` + إشعار المستخدم)
  - `critical`: **`>= 85`** (تقييد مؤقت `RESTRICTED` أو حظر تلقائي عند توافر مؤشرات التلاعب)

### 8.2 التدقيق الساعي بالذكاء الاصطناعي (`api_v1/services/security_engine/ai_audit.py`)
- يُستدعى في الخلفية آلياً كل ساعة عبر أقفال Cache مانعة للتكرار (`ta3alm:ai_hourly_audit_probe` لمدة `180s` و `ta3alm:ai_hourly_audit_running` لمدة `3500s`).
- يدعم 4 مزودي AI عبر واجهة REST الموحدة:
  - Google Gemini (`gemini-2.5-flash`)
  - OpenAI (`gpt-4o-mini`)
  - Groq (`llama-3.3-70b-versatile`)
  - DeepSeek (`deepseek-chat`)
- **حماية المفاتيح:** تُقنّع مفاتيح API في كافة الواجهات الإدارية (`first4...last4`).
- **مسار الطوارئ المحلي:** عند عدم ضبط مفتاح AI خارجي أو تعذر الاتصال، يعمل المحلل السلوكي المحلي `_derive_heuristic_action` تلقائياً.
- **التنفيذ الذري للحظر (`enforce_security_ban`):** يدعم 3 أوضاع: `device_only`، أو `user_only`، أو `device_and_user` مع حماية إلزامية لحسابات الإدارة و `is_superuser` عبر `is_protected_admin_user` ومنع تعديلها، وإبطال كافة `DeviceSession` و `PlaybackSession` وحذف مفاتيح DRF `Token` في نفس المعاملة الذرية.
- **الاحتفاظ بالسجلات (`prune_expired_telemetry`):** حذف دوري للسجلات المغلقة الأقدم من **`event_retention_days = 90 يوماً`**.

---

## 9. ضوابط الصلاحيات والوصول المبنية على الأدوار (RBAC)

### 9.1 هيكل الصلاحيات الإدارية (`dashboard_admin/models.py`, `decorators.py`, `api_v1/permissions.py`)
يُقسم الإشراف الإداري وفق `AdminRole` داخل نموذج `AdminProfile`:

| الدور (`AdminRole`) | الحماية في الديكوريتورز | صلاحيات DRF | النطاق المسموح |
|---|---|---|---|
| `owner` (أو `is_superuser`) | `@owner_required` + `@admin_required` | `IsPlatformOwner` | كامل الصلاحيات، إدارة الخطط، حذف المستخدمين، سجل التدقيق `AuditLog`، وإدارة الطاقم |
| `moderator` | `@moderator_required` + `@admin_required` | `IsPlatformModerator` | إدارة المستخدمين (`can_manage_users`) والمجموعات والمحتوى والدعم |
| `finance` | `@finance_required` + `@admin_required` | `IsPlatformFinance` | التقارير والعمليات المالية (`can_view_finance`) |
| `support` | `@admin_required` | `IsPlatformAdmin` | الدعم الفني ومتابعة التذاكر والشات المباشر |

### 9.2 حراس صلاحيات الأدوار التعليمية والشات
- **حارس الأساس (`IsNotBanned`):** يمنع أي مستخدم `is_banned` أو غير مُفعّل البريد (`requires_email_verification`) من استهلاك أي نقطة API محمية.
- **صلاحية المعلم (`IsTeacherRole`):** تشترط `role == 'teacher'` **واعتماد الإدارة** `teacher_profile.is_approved == True` (وإلا يُرجع `403 TEACHER_APPROVAL_PENDING`).
- **صلاحيات المجموعات والحزم (`teachers/views/permissions.py`):**
  - `get_group_permission` و `get_package_permission` تمنحان صلاحية إدارة كاملة لأي أدمن نشط (`is_platform_content_admin`).
  - تشترط على المعلم: `is_approved=True`، هاتف `>= 11` رقماً، وصورة شخصية، والالتزام بحد المجموعات المسموح في خطته (`get_allowed_group_ids()`).
  - تشترط على المساعد (`AssistantJob`): أن يكون نشطاً (`is_active=True`) ويمتلك الصلاحية النوعية المناسبة (`can_manage_students`, `can_manage_exams`, `can_manage_videos`, `can_manage_packages`).
- **صلاحية شات المجموعة (`api_v1/views/group_chat.py`):** التحقق عبر `resolve_group_chat_access` من كون المستخدم أدمن، أو معلم المجموعة، أو مساعداً مقبولاً لديه، أو طالباً مشتركاً اشتراكاً فعّالاً (`Enrollment(is_active=True)`)، مع احترام حالة قفل الشات `group.is_chat_locked` للمشرفين فقط.

---

## 10. محرك مكافحة الألفاظ القبيحة والشتائم المموّهة

يعتمد شات المجموعات وشات الدعم الفني (API + Quick Reply + Web Support) على محرك `core/profanity_filter.py` ذي الـ 5 طبقات:

1. **تطبيع Unicode وتفكيك الزخرفة (`normalize_unicode_and_decorations`):**
   - تطبيق `unicodedata.normalize('NFKC')`.
   - إزالة حروف العرض الصفرية والرموز الخفية والمدّ (الكشيدة `_ZERO_WIDTH_OR_TATWEEL_RE`) وجميع علامات التشكيل (`Mn`, `Me`, `Cf`).
   - توحيد 38 حرفاً عربياً ومتغيراً (`_AR_CHAR_MAP`: أ/إ/آ ⬅️ ا، ة ⬅️ ه، ي/ى/ئ/ی ⬅️ ي، گ/ک ⬅️ ك، پ ⬅️ ب، چ ⬅️ ج، ڤ ⬅️ ف، إلخ).
   - استبدال 28 حرفاً من السيريلي/اليوناني/الرموز المتشابهة شكلاً (`_LATIN_CONFUSABLES_MAP`: مثل Cyrillic `а/е/о/р/с`, `@->a`, `$->s`, `€->e`).
2. **القائمة البيضاء العلمية الآمنة (`_mask_safe_content`):**
   - استثناء `18` عبارة تعليمية صريحة (`_SAFE_PHRASES` مثل «قضيب مغناطيسي»، «لا نافية للجنس»، «عنصر النيكل»، «عملية الإحلال») و `27` كلمة علمية مفردة (`_SAFE_EXACT_TOKENS`) لمنع ظلم الطالب في الشرح العلمي.
3. **3 عروض تحليل متوازية (Multi-View):**
   - `raw`: النص المطبّع.
   - `inline_ar`: تحويل الأرقام المدمجة داخل الكلمات العربية عبر `_INLINE_AR_DIGIT_MAP` (10 أرقام فرانكو-عربية: `3->ع`, `7->ح`, `5->خ`, `2->ا`, `6->ط`, `8->ق`, `9->ص`...).
   - `latin_leet`: تحويل 8 أرقام Leet (`0->o, 1->i, 3->e, 4->a, 5->s, 7->t, 8->b, 9->g`) و `!|` ⬅️ `i`.
4. **كشف الجذور والتقليص والصوتيات والتشابه التقريبي (`detect_profanity`):**
   - فحص `22` عبارة مركبة مسيئة (`_AR_BAD_PHRASES`).
   - دمج الحروف المفصولة بمسافات (`_merge_single_char_tokens` مثل `ش ر م و ط`).
   - تقليص الأحرف المكررة (`_dedup_n` لمستويين 1 و 2).
   - تجريد `16` سابقة و `16` لاحقة عربية (`_strip_arabic_affixes`).
   - المطابقة ضد `221` جذراً عربياً و `148` جذراً إنجليزياً/فرانكو و `36` بديل تبديل حروف صريح (`_EXPLICIT_SWAP_VARIANTS`).
   - الكشف الصوتي عبر `_PHONETIC_AR_MAP` (8 إبدالات مثل `ط->ت, ص->س, ض->د, ق->ك`) على `185` جذراً صوتياً (`>= 4` أحرف).
   - الكشف عن تحريف/تبديل/نقص/زيادة حرف واحد عبر خوارزمية **Damerau-Levenshtein** بمسافة <= 1 (`_damerau_within_one`) على `109` جذر عربي و `108` جذر لاتيني (`>= 5` أحرف).
5. **مضاد الفواصل والتقطيع:** استخلاص دفق الحروف المتصلة الخالي من كل الرموز والشرط والنقاط (`شـ.ر.مـ*ـو.ط`) وفحصه ضد `60` سلسلة عربية غير ملتبسة و `45` سلسلة لاتينية/فرانكو.

### الاستجابة الفورية عند المخالفة (`handle_chat_profanity_violation`)
عند اكتشاف أي لفظ مسيء من طالب في أي شات:
- يُنفَّذ **حظر فوري ودائم للحساب والجهاز معاً** (`enforce_security_ban` بوضع `mode='device_and_user'` و `block_type='permanent'`).
- يُرسَل إشعار فوري للإدارة (`owner`, `moderator`, `support`) على `/admin-panel/security/`.
- تُرجَع استجابة `403` برمز `DEVICE_BLOCKED` لإجبار المتصفح أو التطبيق على الخروج الفوري إلى شاشة الحظر قبل التحميل ومنعه تماماً من البقاء داخل المنصة.

---

## 11. الأمن المالي (Paymob HMAC)، واجهة البوت، وتحصين الويب (F12)

### 11.1 التحقق المالي عبر Paymob (`teachers/views/payments.py`)
- يتحقق `_verify_paymob_hmac` من صحة كل إشعار دفع وارد في `payment_callback`:
  1. جمع القيم النصية لـ **20 حقلاً قياسياً بالترتيب الإلزامي** (`amount_cents`, `created_at`, `currency`, `error_occured`, `has_parent_transaction`, `id`, `integration_id`, `is_3d_secure`, `is_auth`, `is_capture`, `is_refunded`, `is_standalone_payment`, `is_voided`, `order`, `owner`, `pending`, `source_data.pan`, `source_data.sub_type`, `source_data.type`, `success`).
  2. احتساب `HMAC-SHA512` باستخدام `getattr(django_settings, 'PAYMOB_HMAC_SECRET', '')`.
  3. المقارنة بزمن ثابت عبر `hmac.compare_digest`؛ وعند الإخفاق (أو غياب `PAYMOB_HMAC_SECRET` من إعدادات Django) يُرفض الطلب بـ **`403`** مع تسجيل تحذير أمني.
  4. فحص عدم تكرار `transaction_id` وتنفيذ إضافة الرصيد أو تفعيل الحزمة/الاشتراك داخل `transaction.atomic()`.

### 11.2 تأمين واجهة البوت (`/api/bot/` — `bot_api/permissions.py` & `views.py`)
- **المفتاح الإلزامي:** يُشترط وجود `BOT_API_KEY` غير فارغ في بيئة الإنتاج (يرفض الخادم الإقلاع بدونه في `settings.py`)، ويُفحص عبر ترويسة `X-BOT-KEY` في `IsBotService`.
- **حماية التحقق بالرقم القومي (`VerifyNationalIdView`):**
  - اشتراط رقم هاتف مصري (11 رقماً يبدأ بـ `01`) ورقم قومي مطابق من 14 رقماً.
  - **تقييد المحاولات (Brute-Force Protection):** حد أقصى **`5` محاولات خاطئة خلال ساعة** (`NID_MAX_ATTEMPTS = 5`, `NID_ATTEMPTS_TTL = 3600s` في Cache) وبعدها يُرجع **`429 too_many_attempts`**.
- **رمز الإجراء الموقّع (`ChangePasswordView`):** يعتمد على `signing.dumps/loads` بملح `"bot-action-v1"` وصلاحية `600s` (10 دقائق)، مع مطابقة `uid` من الرمز ضد `user_id` المرسل لمنع استغلال التوكن لحساب آخر، واشتراط كلمة مرور لا تقل عن `8` أحرف.

### 11.3 تحصين واجهة الويب ومقاومة الفحص (`static/js/web_shield.js` & `FrontendHardeningMiddleware`)
- **نزع التعليقات من الاستجابات:** `FrontendHardeningMiddleware` يزيل تلقائياً جميع تعليقات HTML (`<!--...-->`) قبل إرسال الصفحات، مع إبقاء ملفات `templates/` و `static/` خالية من التعليقات التقنية.
- **حماية المتصفح من الفحص عبر F12 (`web_shield.js`):**
  - تعطيل دوال الطرفية `console.{log, debug, info, warn, dir, table, trace}` في المتصفح.
  - تعطيل النقر الأيمن (`contextmenu`) والسحب واختصارات لوحة المفاتيح (`F12`, `Ctrl+Shift+I/J/C/K`, `Ctrl+U/S/P`, وبدائل Cmd على macOS).
  - كاشف حجم نافذة المطورين (DevTools Viewport Delta **`> 190px`**) الذي يوقف أي فيديو فوراً ويغطي الصفحة بحاجز أمني.
  - تغليف `window.fetch` لمراقبة استجابات الـ API وإعادة توجيه المتصفح تلقائياً إلى بوابة الحظر 403 فور استلام `DEVICE_BLOCKED` أو `ACCOUNT_BANNED`.
  - إخفاء كامل المحتوى عند محاولة الطباعة (`@media print { display: none !important }`) وحجب الشاشة عند فقدان التركيز (`blur` / `visibilitychange`).

---

## 12. الأمن في تحديثات التطبيق (APK SHA-256 & EOCD & FileProvider Jail)

يتبع محرّك التحديث الذاتي في `flutter_app/lib/core/update/app_update_service.dart` و `MainActivity.kt` مسار تحقق صارم قبل تثبيت أي حزمة APK:

1. **إلزام التحديث من الخادم:** تمنع طبقة `AppVersionEnforcementMiddleware` العميل الأقدم من `get_effective_min_version_code()` وتعيد `426 APP_UPDATE_REQUIRED`، مع التحقق كذلك في `_handle_auth_device_registration` أثناء الدخول والتسجيل.
2. **معزل التخزين (Cache Directory Jail):**
   - تُنزَّل ملفات التحديث داخل المسار الخاص `cacheDir/app_updates` وتُمرَّر للنظام عبر `ApkUpdateFileProvider` المعرّف بـ `android:exported="false"` و `grantUriPermissions="true"`.
   - يتحقق `MainActivity.kt` في `installApk` أن `targetFile.canonicalFile.parentFile == appUpdatesDir.canonicalFile` لمنع أي هجوم **Path Traversal** نحو ملفات أخرى.
3. **التحقق التشفيري والهيكلي الثلاثي قبل التثبيت (`_validateCompletedApk`):**
   - **فحص الترويسة السحرية:** التأكد من بداية الملف ببايتي ZIP (`0x50 0x4B` = `PK`) لرفض صفحات HTML أو JSON المخادعة.
   - **فحص نهاية الدليل المركزي (`ZIP EOCD`):** المسح العكسي لآخر 65,557 بايت للتحقق من وجود توقيع النهاية الكامل (`0x50 0x4B 0x05 0x06`) لضمان عدم تثبيت ملف مقطوع أو تالف.
   - **مطابقة SHA-256 الكاملة:** حساب تجزئة الملف بالكامل عبر `_hashFileSha256TopLevel` في `Isolate` مستقل ومطابقته حرفياً مع `apk_sha256` المسجَّل في `SiteSetting` (وعند الإخفاق يُحذف الملف فوراً).

---

## 13. أمن قاعدة البيانات والوسائط والخصوصية ومراجعات الإنتاج

### 13.1 أمن قاعدة البيانات والتخزين (`ta3alm_project/settings.py`)
- **PostgreSQL SSL الإلزامي:**
  - `OPTIONS = {'sslmode': 'require', 'connect_timeout': 10}`
  - `CONN_MAX_AGE = 60` و `CONN_HEALTH_CHECKS = True`.
- **تشفير نقل الوسائط (`Cloudinary`):** `SECURE: True` لضمان تقديم كافة الملفات والصور عبر HTTPS فقط.
- **حذف آلي للرموز والتوكنات:** كل كلمة مرور تُحفظ بخوارزميات Django Hashing المعتمدة، ويتم تدوير `jti` وإبطال `Pull/Reply Tokens` تلقائياً بمجرد تغيّر بصمة كلمة المرور `_password_epoch_digest`.

### 13.2 متغيرات البيئة وإعدادات الإنتاج الأمنية
*(أسماء المتغيرات والإعدادات فقط — يجب حفظ قيمها في مدير الأسرار ببيئة التشغيل وعدم تضمينها داخل الكود مطلقاً)*

- **أساسية وإلزامية:** `SECRET_KEY`, `BOT_API_KEY`, `DATABASE_URL` (أو `POSTGRES_URL` / `DB_HOST`)
- **الدفع، OAuth، البريد والإشعارات:** `PAYMOB_API_KEY`, `PAYMOB_INTEGRATION_ID`, `PAYMOB_IFRAME_ID`, `PAYMOB_WALLET_INTEGRATION_ID` (مع ضبط `PAYMOB_HMAC_SECRET` في إعدادات Django عند تفعيل بوابة Paymob), `GOOGLE_OAUTH_CLIENT_ID` (أو `GOOGLE_CLIENT_ID`), `ZOHO_CLIENT_ID`, `ZOHO_CLIENT_SECRET`, `ZOHO_REFRESH_TOKEN`, `FIREBASE_SERVICE_ACCOUNT_JSON` / `FIREBASE_SERVICE_ACCOUNT_FILE`
- **التشفير والبصمة والفيديو:** `TA3ALM_CLIENT_SIGNING_SECRET`, `DEVICE_FINGERPRINT_SECRET`, `VIDEO_SIGNING_SECRET`, `CDN_SIGNING_SECRET`, `CLOUDFLARE_STREAM_CUSTOMER_CODE` / `CLOUDFLARE_STREAM_KEY_ID` / `CLOUDFLARE_STREAM_PRIVATE_KEY_PEM`, `BUNNY_STREAM_SECURITY_KEY`
- **تكامل أندرويد و Play Integrity:** `PLAY_INTEGRITY_SERVICE_ACCOUNT_JSON`, `GOOGLE_APPLICATION_CREDENTIALS`, `PLAY_INTEGRITY_PACKAGE_NAME`, `PLAY_INTEGRITY_POLICY_MODE`, `PLAY_CLOUD_PROJECT_NUMBER`, `ANDROID_RELEASE_CERT_SHA256`, `ANDROID_ASSETLINKS_SHA256`, `ANDROID_DEBUG_CERT_SHA256`, `TA3ALM_REQUIRE_RELEASE_SIGNING`
- **المحلل الأمني AI:** `AI_SECURITY_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_API_KEY`, `OPENAI_API_KEY`, `GROQ_API_KEY` (مع `AI_SECURITY_PROVIDER`, `AI_SECURITY_MODEL`, `AI_SECURITY_HOURLY_ENABLED`, أو الضبط من `SecurityPolicyConfig.ai_api_key_override`)

### 13.3 قائمة التحقق الأمنية (Audit Checklist) قبل أي نشر جديد
1. التأكد من `DEBUG = False` ومنع انطلاق الخادم دون `SECRET_KEY` و `BOT_API_KEY`، والتحقق من ضبط `PAYMOB_HMAC_SECRET` في إعدادات Django عند تفعيل الدفع عبر Paymob.
2. التحقق من وصول `/.well-known/assetlinks.json` محتويةً على بصمات `SHA-256` الحقيقية لتطبيق أندرويد.
3. بناء حزمة Release من أندرويد بتفعيل `TA3ALM_REQUIRE_RELEASE_SIGNING=true` وبقاء R8/ProGuard نشطاً مع تطابق شهادة التوقيع في `ANDROID_RELEASE_CERT_SHA256` داخل لوحة الإدارة.
4. التأكد من بقاء `SecurityPolicyConfig` مفعّلة لـ: `enforce_request_signatures`, `enforce_device_limits`, `enforce_screen_capture_policy`, `auto_block_on_proxy_mitm`, `auto_ban_on_tamper`, و `ai_hourly_schedule_enabled`.
5. مراجعة ألا تحتوي مجلدات `templates/` أو `static/` على تعليقات مكشوفة، وأن اختبارات الأمان (`api_v1.tests_device_security`, `api_v1.tests_video_security`, `api_v1.tests_new_features`, `dashboard_admin.tests`) تجتاز بالكامل دون تعطيل أي تأكيد.
