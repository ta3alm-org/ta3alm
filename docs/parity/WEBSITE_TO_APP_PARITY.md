# WEBSITE_TO_APP_PARITY — مصفوفة التطابق الشامل (منصة تعلّم: الويب ← تطبيق Flutter)

تُوثّق هذه المصفوفة التطابق الكامل (عنصراً بعنصر وشاشةً بشاشة) بين **منصة Django Templates** الأصلية، و**واجهة البرمجة Django REST Framework (`api_v1`)**، و**تطبيق Flutter الأصلي (`flutter_app`)**.

---

## 1. المصادقة والحساب (Auth, Google Sign-In, Profile, Settings)

| الشاشة / العنصر في الويب | المصدر في Django | نقطة النهاية (`api_v1`) | الشاشة / العنصر في Flutter | الحالة |
|---|---|---|---|---|
| تسجيل الدخول (البريد / الهاتف / الكود `#123456`) | `templates/account/login.html` | `POST /api/v1/auth/login/` | `LoginScreen` (`login_screen.dart`) | COMPLETE |
| تسجيل الدخول بواسطة **Google** | `account/login.html` (Allauth Google OAuth2) | `POST /api/v1/auth/google/` + `GET /api/v1/auth/google/callback/` | زر **المتابعة باستخدام Google** (`LoginScreen` & `RegisterScreen`) | COMPLETE |
| رابط / كود الدخول المباشر المؤقت (One-Time Login) | `accounts/views.py` (`one_time_login`) | `POST /api/v1/auth/one-time-login/` | زر **رابط دخول مباشر** في `LoginScreen` | COMPLETE |
| استعادة كلمة المرور بالرقم القومي | `accounts/views.py` (`password_reset_nid`) | `POST /api/v1/auth/reset-password-nid/` | `ForgotPasswordScreen` (`forgot_password_screen.dart`) | COMPLETE |
| إنشاء حساب مع اختيار الدور (`طالب` / `معلم` / `مساعد`) | `templates/account/role_signup.html` | `POST /api/v1/auth/register/` | `RegisterScreen` مع شرائح اختيار الدور (`student` / `teacher` / `assistant`) | COMPLETE |
| استكمال البيانات بعد التسجيل عبر Google | `templates/accounts/complete_profile.html` | `POST /api/v1/auth/complete-profile/` | `CompleteProfileScreen` (`complete_profile_screen.dart`) | COMPLETE |
| شاشة المستخدم المحظور | `templates/core/banned.html` | `user.is_banned` في `GET /api/v1/auth/me/` | شاشة الحظر داخل `app_router.dart` | COMPLETE |
| تعديل الملف الشخصي + هاتف ولي الأمر للطالب + حذف الحساب نهائياً | `accounts/views.py` (`profile_settings`, `delete_account`) | `GET/PATCH/DELETE /api/v1/auth/me/` | `ProfileScreen` (`profile_screen.dart`) | COMPLETE |
| تغيير كلمة المرور | `accounts/views.py` (`change_password`) | `POST /api/v1/auth/change-password/` | `ChangePasswordScreen` (`change_password_screen.dart`) | COMPLETE |
| الإعدادات والدعم الفني (واتساب + بريد الدعم + دليل المنصة + باقات المعلمين) | `templates/base.html` | `GET /api/v1/public/guide/` | `SettingsScreen` (`settings_screen.dart`) | COMPLETE |

---

## 2. الواجهة العامة ودليل المنصة (Public Home & Guide)

| الشاشة / العنصر في الويب | المصدر في Django | نقطة النهاية (`api_v1`) | الشاشة / العنصر في Flutter | الحالة |
|---|---|---|---|---|
| الصفحة الرئيسية للزوار + إحصاءات المنصة | `templates/home.html` | `GET /api/v1/public/home/` | `HomeScreen` (`home_screen.dart`) | COMPLETE |
| أزرار التسجيل السريع حسب الدور (طالب / معلم / مساعد) | `templates/home.html` | `RegisterScreen(initialRole: ...)` | أزرار الانضمام الثلاثة في `HeroBannerCard` | COMPLETE |
| فلترة المعلمين حسب الصف الدراسي والمادة الدراسية | `core/views.py` (`home`) | `GET /api/v1/public/home/?grade=...&subject=...` | بطاقة الفلترة في `HomeScreen` | COMPLETE |
| زر "عرض المجموعات" على بطاقة كل معلم | `templates/home.html` | `GET /api/v1/student/groups/search/?q=...` | فتح `SearchGroupsScreen(initialQuery: ...)` | COMPLETE |
| دليل استخدام المنصة التفاعلي (طالب / معلم / مساعد) | `templates/core/guide.html` | `GET /api/v1/public/guide/` | `PlatformGuideScreen` (`platform_guide_screen.dart`) | COMPLETE |
| باقات اشتراك المعلمين | `core/views.py` (`plans_view`) | `GET /api/v1/public/plans/` | `TeacherSubscriptionScreen` (`teacher_subscription_screen.dart`) | COMPLETE |

---

## 3. الطالب (Student Dashboard, Groups, Packages, Exams, Grades)

| الشاشة / العنصر في الويب | المصدر في Django | نقطة النهاية (`api_v1`) | الشاشة / العنصر في Flutter | الحالة |
|---|---|---|---|---|
| لوحة الطالب: المجموعات النشطة + المجموعات المعلقة + المجموعات المقفولة (اشتراك المعلم منتهي) | `students/views.py` (`student_dashboard`) | `GET /api/v1/student/dashboard/` | `StudentDashboardScreen` (`student_dashboard_screen.dart`) | COMPLETE |
| البحث عن مجموعات بالاسم/المعلم + فلترة بالمرحلة والمادة + طلب الانضمام | `students/views.py` (`search_groups`, `join_group`) | `GET /api/v1/student/groups/search/` + `POST /join/` | `SearchGroupsScreen` (`search_groups_screen.dart`) | COMPLETE |
| محتوى المجموعة: المحاضرات (بكود المشاهدة) + الامتحانات + المذكرات PDF | `students/views.py` (`group_content`) | `GET /api/v1/student/groups/<id>/content/` | `StudentGroupDetailScreen` (`student_group_detail_screen.dart`) | COMPLETE |
| مشغل الفيديو الأصلي مع عداد المشاهدات + التحقق من الكود | `students/views.py` (`watch_lecture`) | `POST /api/v1/student/lectures/<id>/watch/` | `VideoPlayerScreen` (`video_player_screen.dart`) | COMPLETE |
| التواصل مع المعلم ومساعديه النشطين (واتساب + اتصال هاتفي) | `students/views.py` (`group_contact`) | `GET /api/v1/student/groups/<id>/contact/` | `TeacherContactSheet` (`teacher_contact_sheet.dart`) | COMPLETE |
| سجل الدرجات والحضور الشهري (فلتر الشهر + 4 درجات تفصيلية + الملاحظة + الامتحانات + نقاط الفيديوهات) | `students/views.py` (`student_marks`) | `GET /api/v1/student/groups/<id>/marks/?month=...` + `packages/<id>/marks/` | `StudentMarksScreen` (`student_marks_screen.dart`) | COMPLETE |
| لوحة الشرف (للمجموعة وللكورس الشامل) | `students/views.py` (`group_ranking`, `package_ranking`) | `GET /api/v1/student/groups/<id>/ranking/` + `GET /api/v1/student/packages/<id>/` | `LeaderboardScreen` (`leaderboard_screen.dart`) | COMPLETE |
| متجر الكورسات الشاملة + تفاصيل الكورس + الشراء اليدوي بإيصال | `students/views.py` (`packages_store`, `package_detail`, `manual_checkout`) | `GET /api/v1/student/packages/` + `POST /api/v1/payments/manual-checkout/` | `PackagesStoreScreen` + `PackageDetailScreen` + `ManualCheckoutScreen` | COMPLETE |
| محتوى الكورس الشامل + المشاهدات المتبقية + الامتحانات + المذكرات + لوحة الشرف + السجل | `students/views.py` (`package_content`) | `GET /api/v1/student/packages/<id>/content/` | `StudentPackageContentScreen` (`student_package_content_screen.dart`) | COMPLETE |
| أداء الامتحان الإلكتروني مع المؤقت وحفظ الإجابات وعرض النتيجة | `exams/views.py` (`take_exam`, `take_package_exam`) | `GET/POST /api/v1/student/exams/<id>/take/` + `packages/<pId>/exams/<eId>/take/` | `ExamTakeScreen` (`exam_take_screen.dart`) | COMPLETE |
| الإشعارات وتحديد كمقروء | `core/views.py` (`notifications_list`) | `GET /api/v1/notifications/` + `POST /<id>/read/` | `NotificationsScreen` (`notifications_screen.dart`) | COMPLETE |

---

## 4. المعلم والمساعد (Teacher & Assistant)

| الشاشة / العنصر في الويب | المصدر في Django | نقطة النهاية (`api_v1`) | الشاشة / العنصر في Flutter | الحالة |
|---|---|---|---|---|
| لوحة المعلم: الإحصائيات + الاشتراك + المحفظة + البحث في المجموعات + إنشاء/تعديل/حذف مجموعة | `teachers/views.py` (`teacher_dashboard`, `edit_group`, `delete_group`) | `GET/POST /api/v1/teacher/dashboard/` + `PATCH/DELETE /groups/<id>/` | `TeacherDashboardScreen` (`teacher_dashboard_screen.dart`) | COMPLETE |
| إدارة المساعدين: تعيين بالكود، قبول/رفض الطلبات، إلغاء التعيين، وتعديل الصلاحيات الأربع | `teachers/views.py` (`manage_assistants`) | `GET/POST /api/v1/teacher/assistants/` | `_showAssistantsSheet` في `TeacherDashboardScreen` | COMPLETE |
| إدارة المجموعة: 5 تبويبات (المحاضرات، الامتحانات، المذكرات PDF، الطلاب، طلبات الانضمام) | `teachers/views.py` (`group_detail`) | `GET /api/v1/teacher/groups/<id>/` | `TeacherGroupManageScreen` (`teacher_group_manage_screen.dart`) | COMPLETE |
| استيراد محاضرات وامتحانات من مجموعة أخرى + تعديل المجموعة | `teachers/views.py` (`import_group_content`) | `POST /api/v1/teacher/groups/<id>/ranking/` | أزرار AppBar في `TeacherGroupManageScreen` | COMPLETE |
| المحاضرات: إضافة (مع ربط اختياري بدرس المنهج للمساعد الذكي)، إظهار/إخفاء، حذف، وإدارة الأكواد | `teachers/views.py` (`add_lecture`, `toggle_lecture`, `delete_lecture`, `manage_codes`) | `POST /lectures/`, `POST/DELETE /teacher/lectures/<id>/`, `GET/POST /codes/` | تبويب المحاضرات + `ManageVideoCodesScreen` | COMPLETE |
| المذكرات (PDF): رفع مذكرة، فتح، وحذف | `teachers/views.py` (`upload_pdf`, `delete_pdf`) | `POST /groups/<id>/pdfs/`, `DELETE /teacher/pdfs/<id>/` | تبويب المذكرات في `TeacherGroupManageScreen` | COMPLETE |
| الطلاب: البحث، ضم بالكود المميز، قبول/رفض، إزالة، تسجيل أداء فردي، واستعراض/حذف السجل الكامل بالشهر | `teachers/views.py` (`group_students`, `student_full_log`) | `GET/POST /students/`, `GET/DELETE /students/<sId>/logs/` | تبويب الطلاب في `TeacherGroupManageScreen` | COMPLETE |
| الرصد الجماعي الكامل (الحصة + عظمى الـ 4 بنود + غياب + 4 درجات + ملاحظة) | `teachers/views.py` (`bulk_log`) | `POST /api/v1/teacher/groups/<id>/bulk-log/` | `BulkLogScreen` (`bulk_log_screen.dart`) | COMPLETE |
| إدارة الامتحان: تفعيل/إغلاق، تعديل، حذف، إضافة/تعديل/حذف الأسئلة، والبحث في نتائج الطلاب | `exams/views.py` (`manage_exam`, `edit_question`, `delete_question`) | `GET/POST/PATCH/DELETE /teacher/exams/<id>/`, `PATCH/DELETE /questions/<id>/` | `ExamManageScreen` (`exam_manage_screen.dart`) | COMPLETE |
| إدارة الكورسات الشاملة للمعلم والمساعد (إنشاء، تعديل، حذف، محتوى، استيراد، مشتركين وأرباح، لوحة شرف) | `teachers/views.py` (`packages_list`, `package_dashboard`) | `GET/POST /teacher/packages/`, `GET/POST/PATCH/DELETE /packages/<id>/` | `TeacherPackagesScreen` + `TeacherPackageManageScreen` | COMPLETE |
| المحفظة المالية وطلبات السحب (فودافون كاش / إنستا باي) | `teachers/views.py` (`teacher_wallet`) | `GET/POST /api/v1/teacher/wallet/` | `TeacherWalletScreen` (`teacher_wallet_screen.dart`) | COMPLETE |
| لوحة المساعد: المعلمون المشرف عليهم، المجموعات (مع إنشاء مجموعة)، الكورسات الشاملة (حسب الصلاحية)، الطلبات المعلقة، والبحث والتقديم | `assistants/views.py` (`assistant_dashboard`, `find_teacher`) | `GET/POST /api/v1/assistant/dashboard/`, `GET/POST /assistant/teachers/<id>/groups/` | `AssistantDashboardScreen` (`assistant_dashboard_screen.dart`) | COMPLETE |

---

## 5. الإدارة العليا ومالك المنصة (Platform Admin)

| الشاشة / العنصر في الويب | المصدر في Django | نقطة النهاية (`api_v1`) | الشاشة / العنصر في Flutter | الحالة |
|---|---|---|---|---|
| الإحصاءات + وضع الصيانة + آخر أحداث النظام | `dashboard_admin/views.py` (`admin_dashboard`, `toggle_maintenance`) | `GET /admin/dashboard/`, `POST /admin/maintenance/toggle/` | تبويب `الإحصاءات والصيانة` في `AdminDashboardScreen` | COMPLETE |
| إدارة المستخدمين (بحث، فلترة بالدور، تعديل كامل، تغيير كلمة المرور، توليد رابط دخول مؤقت، حظر/فك حظر، تجديد مجاني، حذف) | `dashboard_admin/views.py` (`manage_users`, `edit_user`) | `GET/POST /api/v1/admin/users/` | تبويب `المستخدمون` في `AdminDashboardScreen` | COMPLETE |
| المالية والإيصالات (معاينة الإيصال + قبول/رفض الدفع اليدوي + تأكيد سحب الأرباح + مبيعات الحزم + اشتراكات المعلمين) | `dashboard_admin/views.py` (`finance_dashboard`, `manual_payments`) | `GET/POST /api/v1/admin/finance/` | تبويب `الماليات والإيصالات` في `AdminDashboardScreen` | COMPLETE |
| إدارة الباقات (عرض، إضافة، تعديل، حذف مع كل الحدود والمميزات) | `dashboard_admin/views.py` (`manage_plans`) | `GET/POST /api/v1/admin/plans-staff/` | تبويب `الباقات` في `AdminDashboardScreen` | COMPLETE |
| إدارة المناهج والمواد (إضافة/حذف مواد، إضافة/تعديل/حذف وحدات ودروس) | `dashboard_admin/views.py` (`manage_curriculum`, `manage_subjects`) | `GET/POST /api/v1/admin/plans-staff/` | تبويب `المناهج والمواد` في `AdminDashboardScreen` | COMPLETE |
| فريق الإدارة وسجل الأحداث (إنشاء مسؤول، إزالة مسؤول، استعراض AuditLog) | `dashboard_admin/views.py` (`manage_staff`, `audit_logs`) | `GET/POST /api/v1/admin/plans-staff/` | تبويب `فريق الإدارة والسجل` في `AdminDashboardScreen` | COMPLETE |
| بريد الدعم الفني Zoho Mail (صندوق الوارد، قراءة رسالة، رد، رسالة جديدة، إعدادات OAuth) | `dashboard_admin/views.py` (`support_inbox`, `zoho_settings`) | `GET/POST /api/v1/admin/support/` | تبويب `بريد الدعم (Zoho)` في `AdminDashboardScreen` | COMPLETE |

