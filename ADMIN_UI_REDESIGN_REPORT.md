# تقرير إعادة بناء واجهة لوحة الإدارة (`ADMIN_UI_REDESIGN_REPORT.md`)

**تاريخ التنفيذ:** 2026-11-22  
**النطاق:** إعادة بناء واجهة لوحة التحكم الإدارية (`dashboard_admin` و `templates/admin_panel/`) بالكامل بنظام تصميم موحّد هادئ مستلهم من فلسفة Shopify Admin مع تحويل التفاعلات الإدارية إلى تجربة تشبه تطبيقات الصفحة الواحدة (SPA-Like AJAX / Fetch API) مع الحفاظ الكامل على عقود الخلفية والـ Backend وقاعدة البيانات.

---

## 1. الصفحات المعاد تصميمها بالكامل (All 21 Templates + 8 Partials)

تمت إعادة بناء جميع قوالب `templates/admin_panel/` دون استثناء وإزالة الاعتماد الكامل على `bootstrap.rtl.min.css` و `bootstrap.bundle.min.js`:

1. `templates/admin_panel/base_admin.html` — الهيكل الرئيسي الموحّد (RTL-native، قائمة جانبية قابلة للطي ومقسمة وظيفياً، شريط علوي بنظام مسار تنقل نظيف + بحث انتقال سريع `Ctrl+K` + زر الصيانة + قائمة الحساب، نظام Toast Notifications، نافذة تأكيد/إدخال سبب مخصصة، نافذة معاينة الإيصالات).
2. `templates/admin_panel/dashboard.html` — لوحة القيادة الرئيسية (بطاقات مؤشرات هادئة، الوصول السريع، آخر الأحداث، تحديث نسبة عمولة المنصة ووضع الصيانة وتحديث إعدادات APK عبر AJAX).
3. `templates/admin_panel/manage_users.html` + `partials/_users_table.html` — إدارة المستخدمين (تبويبات المعلمين/الطلاب/المساعدين، بحث حي بالخادم، قائمة إجراءات منسدلة منظمة لكل صف، درج جانبي موحّد لتجديد الاشتراك).
4. `templates/admin_panel/edit_user.html` — تعديل بيانات المستخدم (تقسيم إعدادات ثنائي الأعمدة، حفظ البيانات عبر AJAX، توليد رابط الدخول المباشر ونسخه بنقرة واحدة، تحديث كلمة المرور).
5. `templates/admin_panel/send_notifications.html` + `partials/_notification_dispatches.html` — إرسال إشعارات مخصصة (بطاقات تحديد الاستهداف، البحث المباشر عن المستخدمين، معاينة الهاتف، سجل أحدث الإرسالات المحدّث تلقائياً بعد الإرسال عبر AJAX).
6. `templates/admin_panel/finance_report.html` + `partials/_finance_table.html` — التقارير المالية مع بحث حي وتحديث لحظي لعداد المعاملات وإجمالي الإيرادات.
7. `templates/admin_panel/withdrawals.html` — طلبات السحب مع فلاتر حالة، موافقة وتأكيد عبر مربع الحوار المخصص، ورفض مع حقل سبب الرفض (بدلاً من `prompt()`) مع تحديث الصف فورياً.
8. `templates/admin_panel/student_payments.html` — مبيعات الحزم (3 بطاقات إحصائية هادئة، فرز أعمدة الجدول وبحث فوري).
9. `templates/admin_panel/manual_payments.html` — طلبات الدفع اليدوي (فلاتر الحالة، معاينة الإيصالات داخل Lightbox، اعتماد أو رفض عبر AJAX وتحديث الصف فوراً).
10. `templates/admin_panel/manage_plans.html` + `_plan_form_fields.html` + `partials/_plans_grid.html` — إدارة الباقات (شبكة باقات نظيفة، درج جانبي موحد للإضافة والتعديل بدلاً من تكرار المودالات، حذف بتأكيد مخصص وتحديث الشبكة تلقائياً).
11. `templates/admin_panel/manage_staff.html` + `partials/_staff_table.html` — فريق الإدارة (تعيين/إنشاء مسؤول عبر نافذة مبوّبة، إزالة مسؤول وتحديث الجدول عبر AJAX).
12. `templates/admin_panel/audit_log.html` + `partials/_audit_list.html` — سجل الأحداث الإدارية مع تصفية فورية عبر AJAX حسب نوع الإجراء.
13. `templates/admin_panel/curriculum_list.html` — قائمة المناهج الدراسية مع بحث فوري وفرز وحذف الوحدة عبر AJAX.
14. `templates/admin_panel/curriculum_form.html` — إضافة وتعديل وحدة ودروسها (إدارة سطور Formset ديناميكياً وحفظ عبر AJAX مع إعادة التوجيه عند النجاح أو عرض أخطاء التحقق).
15. `templates/admin_panel/support_inbox.html` + `partials/_support_inbox_table.html` — صندوق الدعم الفني (Zoho Mail) مع بحث حي ودرج جانبي لإنشاء رسالة جديدة وقوالب ردود سريعة.
16. `templates/admin_panel/support_message_detail.html` — عرض الرسالة المعزولة داخل `iframe` مع نموذج الرد المباشر عبر AJAX.
17. `templates/admin_panel/support_settings.html` — إعدادات ربط Zoho Mail (حفظ المفاتيح وقطع الاتصال عبر AJAX، وإبقاء مسار OAuth 2.0 كتوجيه متصفح كامل).
18. `templates/admin_panel/security_dashboard.html` + `partials/_security_panels.html` — مركز الأمان والحماية مقسّم إلى 5 تبويبات واضحة (الأجهزة الموحدة / الأحداث والتهديدات / الجلسات النشطة والحظر / تقارير AI / السياسات وإعدادات AI) مع تحديث فوري عبر AJAX لكل من الـ 13 إجراء أمني.
19. `templates/admin_panel/security_device_detail.html` — تفاصيل الجهاز وسجل البصمات والـ IP مع حظر/فك حظر وإلزام إعادة التحقق عبر AJAX.
20. `templates/admin_panel/app_release.html` — إصدارات الأندرويد ورابط GitHub APK ومعاينة `assetlinks.json` مع تحديث البطاقات والمعاينة تلقائياً بعد الحفظ عبر AJAX (يدعم رفع ملف APK عبر `FormData`).

---

## 2. نظام التصميم الجديد والمكونات القابلة لإعادة الاستخدام

### A. طبقات التصميم CSS (`static/admin_panel/css/`)
- `tokens.css`: متغيرات الألوان الهادئة المستلهمة من Shopify (`--bg-main: #f6f6f4`, `--bg-surface: #ffffff`, `--accent: #303f3a`, `--border-default: #e5e7e8`)، الظلال الخفيفة، نصف الأقطار، وطبقات Z-index.
- `base.css`: إعادة ضبط حديثة، أنماط RTL الافتراضية، حالات التركيز الوصولية (`:focus-visible`)، ومساعدات التباعد والمحاذاة.
- `layout.css`: الشبكة الهيكلية، القائمة الجانبية القابلة للطي (`256px` / `72px`) مع Tooltips عند الطي، شريط التنقل العلوي، ودرج الموبايل، والشبكات المتجاوبة (`.ap-kpi-grid`, `.ap-split-8-4`, `.ap-split-7-5`).
- `components.css`: الأزرار، البطاقات، بطاقات المؤشرات (`.ap-stat`)، عناصر النماذج (مع دعم مباشر لكلاسات `.form-control` و `.form-select` المستخدمة في `dashboard_admin/forms.py`)، المفاتيح (`.ap-switch`)، الشارات، التبويبات، التنبيهات، القوائم المنسدلة، الجداول الزمنية، وهياكل التحميل.
- `tables.css`: شريط الأدوات (`.ap-toolbar`)، حبوب التصفية، صناديق البحث، والجداول المريحة للقراءة.
- `overlays.css`: النوافذ المنبثقة (`.ap-modal`)، مربعات التأكيد والإدخال (`.ap-confirm`)، الأدراج الجانبية (`.ap-drawer`)، حزمة الإشعارات الفورية (`.ap-toast-stack`)، ومعاينة الصور.
- `pages.css`: أنماط مخصصة لبطاقات استهداف الإشعارات ومعاينة الهاتف، معاينة الكود، عارض البريد المعزول، ومواصفات الجهاز.

### B. البنية البرمجية لجافاسكريبت (`static/admin_panel/js/`)
- `core/`: `csrf.js`, `events.js`, `notifications.js`, `loading.js`, `api.js`, `modal.js`, `drawer.js`.
- `components/`: `sidebar.js`, `dropdown.js` (بحساب `position: fixed` ديناميكي لمنع قص القوائم المنسدلة داخل الجداول القابلة للتمرير أفقياً)، `tabs.js`, `form-handler.js`, `search.js`, `data-table.js`.
- `pages/`: `dashboard.js`, `users.js`, `finance.js`, `plans.js`, `staff.js`, `curriculum.js`, `support.js`, `security.js`, `notifications.js`, `app-release.js`، بالإضافة لنقطة الدخول `app.js`.

---

## 3. حصر الملفات المضافة والمعدلة للوحة الإدارة

- **ملفات خلفية مضافة/معدلة (`dashboard_admin/`):**
  - مضاف: `dashboard_admin/views/ajax.py`
  - معدل: `dashboard_admin/decorators.py`، `dashboard_admin/tests.py`، وجميع وحدات العرض العشر: `home.py`, `users.py`, `finance.py`, `plans.py`, `audit.py`, `staff.py`, `curriculum.py`, `support.py`, `security.py`, `notifications.py`.
  - *(تم الحفاظ التام على تعديلات المستخدم السابقة في `dashboard_admin/views/home.py` و `core/models.py`، دون أي تعديل على `models.py` أو `migrations` أو `dashboard_admin/urls.py` أو `api_v1/`).*
- **ملفات الواجهة الثابتة (`static/admin_panel/`):** 31 ملفاً جديداً (7 ملفات CSS و 24 وحدة JavaScript ES Modules) مفصولة تماماً عن `static/admin/` الخاص بـ Django Admin.
- **القوالب (`templates/admin_panel/`):** 21 قالباً معاداً بالكامل + 8 قوالب جزئية جديدة داخل `templates/admin_panel/partials/`.

---

## 4. العمليات المحولة إلى AJAX مقابل العمليات المحتفظة بالتنقل الكامل

| العملية / المسار | الآلية المستخدمة | السبب / الملاحظة |
|---|---|---|
| تبديل الصيانة، تحديث العمولة، إعدادات APK | **AJAX (Fetch POST -> JSON)** | مع إبقاء Redirect fallback لطلبات POST العادية |
| بحث وتصفية المستخدمين، الإجراءات، تجديد الاشتراك، تعديل المستخدم، توليد رابط مباشر، تغيير كلمة المرور | **AJAX (Partial HTML + JSON POST)** | منع إعادة تحميل الصفحة وتحديث الصفوف/الأعداد فوراً |
| البحث المالي، تسديد/رفض السحوبات، قبول/رفض الدفع اليدوي | **AJAX (Partial HTML + JSON POST)** | تحديث الصفوف وإظهار سبب الرفض في Dialog مخصص |
| إضافة/تعديل/حذف الباقات، تعيين/إزالة فريق الإدارة | **AJAX (JSON POST + HTML Grid/Table swap)** | تحديث مباشر للشبكة والجدول دون فقد السياق |
| إضافة/تعديل/حذف المناهج الدراسية | **AJAX (JSON POST)** | التحقق المباشر وعرض الأخطاء أو التوجيه بعد الحفظ |
| تصفية سجل الأحداث الإدارية | **AJAX (Partial HTML GET)** | تصفية فورية للجدول الزمني |
| صندوق الدعم: البحث، التحديث، الإنشاء، الرد، حفظ مفاتيح Zoho وقطع الاتصال | **AJAX (Partial HTML + JSON POST)** | عدم انقطاع العمل عند إرسال الرسائل أو البحث |
| جميع الإجراءات الأمنية الـ 13 وتصفية مركز الأمان | **AJAX (Partial HTML + JSON POST)** | تحديث اللوحات والجدول مع الحفاظ على التبويب النشط |
| إرسال الإشعارات المخصصة ومعاينة المستلمين والبحث | **AJAX (JSON POST + Dispatches swap)** | تحديث سجل الإرسالات المرسلة فوراً |
| **بدء وتخويل Zoho OAuth 2.0** (`support_oauth_connect`, `support_oauth_callback`) | **توجيه متصفح كامل (Full Page Redirect)** | يتطلب إعادة توجيه خارجية لخوادم Zoho ثم العودة بالـ Authorization Code |
| **تسجيل الخروج** (`account_logout`) والروابط الخارجية (`home`, Django Admin) | **توجيه متصفح كامل** | ينقل المستخدم لسياق خارج لوحة الإدارة |

---

## 5. نتائج الفحوصات والاختبارات المنفذة (SQLite)

تم تنفيذ جميع أوامر Django على بيئة **SQLite معزولة** (`USE_SQLITE='true'`) دون أي اتصال بـ Neon Postgres:

1. **فحص النظام (`manage.py check`):** `System check identified no issues (0 silenced)`.
2. **فحص الترحيلات (`manage.py makemigrations --check --dry-run`):** `No changes detected`.
3. **حزمة الاختبارات الشاملة (`manage.py test` — 16 اختباراً، 0 أخطاء، 0 إخفاقات):**
   - `dashboard_admin.tests.AdminPanelRebuildTests` (8 اختبارات):
     - عرض جميع صفحات الإدارة الـ 19 بحالة 200 OK للمالك مع التحقق من وجود ملفات التصميم والـ JS.
     - مصفوفة الصلاحيات الكاملة (مجهول -> 401 AJAX / 302 HTML، طالب -> 403 AJAX / 302 HTML، أدوار المالي/المشرف/الدعم -> 403 على الأقسام غير المصرحة).
     - فرض التحقق من CSRF (`Client(enforce_csrf_checks=True)`) على طلبات AJAX POST (403 عند غياب التوكن، 200 عند وجوده).
     - اختبارات AJAX لكل من: الرئيسية، العمولة، APK، المستخدمين، تعديل المستخدم، المالية، السحب (مع إعادة الرصيد ومنع التكرار 409)، الدفع اليدوي، الباقات، الفريق، المناهج، سجل الأحداث، إعدادات الدعم، الأمان، والإشعارات المخصصة + التوافق العكسي مع POST غير AJAX.
   - `api_v1.tests_refactor_contracts.RefactorContractsTests` (4 اختبارات): نجاح 100% لجميع عقود المسارات (URL Contracts) والتوافق الاستيرادي والـ Signals.
   - `api_v1.tests_device_security.DeviceSecuritySystemTests` (`test_16_admin_block_unblock_and_html_dashboard_rendering` و `test_23_app_links_assetlinks_and_github_release_apk_settings`): نجاح 100%.
   - `api_v1.tests_notifications.AdminCustomNotificationTests` (`test_web_admin_notifications_page_and_preview` و `test_permissions_for_admin_custom_notifications`): نجاح 100%.
4. **فحص الملفات الثابتة والصياغة (Static & Syntax Check):**
   - `django.contrib.staticfiles.finders`: العثور على جميع الـ 31 ملفاً تحت `static/admin_panel/` دون نقص.
   - `node --check` على جميع الـ 24 ملف JavaScript: 0 أخطاء صياغة، وجميع مسارات الاستيراد النسبية (`import ...`) صحيحة.
   - توازن أقواس CSS على جميع الـ 7 ملفات: 0 أخطاء.
   - `manage.py collectstatic --dry-run --noinput`: نجاح تام دون تعارضات.
   - فحص بقايا Bootstrap القديمة في القوالب المعاد بناؤها: 0 بقايا (`data-bs-`, `bootstrap.rtl`, `bootstrap.bundle`, `alert(`, `prompt(`).

---

## 6. المشكلات المكتشفة والمُصلَحة أثناء التنفيذ

1. **`ManualPayment` ForeignKey in `select_related`:** كان التعديل الأولي في `dashboard_admin/views/finance.py` يمرر `'teacher_plan'` و `'student_package'` داخل `select_related()` بينما هما خصائص تعتمد على `target_id` في النموذج؛ تم التصحيح بإبقاء `.select_related('user')`.
2. **`TeacherProfile.days_remaining` كدالة وليس خاصية:** في `dashboard_admin/views/users.py`، كانت القيمة تُمرر كمرجع دالة إلى `JsonResponse` مما سبب `TypeError`؛ تم التصحيح باستدعائها بأمان `tp.days_remaining()`.
3. **ذاكرة التخزين المؤقت `SiteSetting.load()` بين الاختبارات:** تم تنظيف الـ Cache في `setUp()` داخل `dashboard_admin/tests.py` لضمان عزل اختبارات تبديل الصيانة.
4. **توافق نماذج Django (`dashboard_admin/forms.py`):** تم تنسيق كلاسات `.form-control` و `.form-select` داخل `components.css` كي ترث كل حقول Django Forms المظهر الهادئ الموحد تلقائياً دون تعديل ملف `forms.py`.

---

## 7. حدود التحقق الحي عبر المتصفح (ما لم يتم تنفيذه آلياً)

- عند محاولة تشغيل الفحص الحي عبر وكيل المتصفح (`chrome_devtools` MCP)، تعذّر الاتصال بمتصفح Chrome على الجهاز المضيف بسبب عدم تفعيل منفذ التصحيح البعيد (`Could not find DevToolsActivePort at C:\Users\HP\AppData\Local\Google\Chrome\User Data\DevToolsActivePort`).
- بناءً على ذلك: تم التحقق الآلي الكامل من الخلفية، عرض القوالب، الصلاحيات، CSRF، عقود API، صياغة JS/CSS، وتجميع الملفات الثابتة، بينما يوصى بإجراء معاينة بصرية سريعة في المتصفح على المقاسات الثلاثة (Desktop / Tablet / Mobile) بعد تشغيل الخادم المحلي للتأكد البصري النهائي من محاذاة الشاشات والخطوط.
