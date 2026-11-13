# API_COMPLETENESS_REPORT — تقرير اكتمال واجهة برمجة التطبيقات (`api_v1`)

تغطي واجهة `api_v1` الآن 100% من منطق الأعمال وعمليات الويب الأصلية مع الحفاظ الكامل على صلاحيات Django وقواعد الأمان.

---

## 1. نقاط النهاية الجديدة والمُحدّثة في هذه المرحلة

### أ. المصادقة (`api_v1/views_auth.py` & `api_v1/urls.py`)
| المسار | الطريقة | الكلاس | الوظيفة |
|---|---|---|---|
| `/api/v1/auth/google/` | `POST` | `GoogleLoginAPIView` | التحقق من `id_token` أو `access_token` عبر خوادم Google وإنشاء/ربط `User` + `SocialAccount` وإصدار JWT |
| `/api/v1/auth/google/callback/` | `GET` | `GoogleMobileCallbackView` | جسر Google OAuth عبر المتصفح وتوليد كود `OneTimeLoginLink` لمدة 15 دقيقة |
| `/api/v1/auth/one-time-login/` | `POST` | `OneTimeLoginAPIView` | التحقق من رمز أو رابط `OneTimeLoginLink` وإصدار JWT |

### ب. المعلم (`api_v1/views_teacher.py`)
| المسار | التحديث المنفذ |
|---|---|
| `GET /api/v1/teacher/groups/<group_id>/` | إضافة `other_groups` (مجموعات المعلم الأخرى في نفس المرحلة مع محاضراتها وامتحاناتها) للاستيراد |
| `POST /api/v1/teacher/groups/<group_id>/lectures/` | دعم `lesson_id` اختياري لربط المحاضرة بـ `CurriculumLesson` |
| `GET / PATCH /api/v1/teacher/exams/<exam_id>/` | دعم فلتر البحث `?q=` في نتائج الطلاب + دعم `PATCH` لتعديل عنوان/وصف/مدة/حالة الامتحان |
| `GET /api/v1/teacher/packages/<pkg_id>/` | إضافة `available_groups` (مجموعات المعلم في نفس المرحلة) لاستيراد المحتوى داخل الحزمة |

### ج. الإدارة العليا (`api_v1/views_admin.py` & `api_v1/urls.py`)
| المسار | التحديث المنفذ |
|---|---|
| `GET / POST /api/v1/admin/users/` | إرجاع `subjects` في `GET`، وإضافة `edit_user` و `change_password` و `generate_login_link` في `POST` |
| `GET /api/v1/admin/finance/` | إضافة `student_payments` (`PackageEnrollmentSerializer`) لمبيعات الكورسات الشاملة |
| `GET / POST /api/v1/admin/plans-staff/` | إرجاع `audit_logs` و `curriculum_units` و `subjects` في `GET`، وإضافة `edit_plan` و `create_staff` و `add_curriculum_unit` و `edit_curriculum_unit` و `delete_curriculum_unit` و `add_subject` و `delete_subject` |
| `GET / POST /api/v1/admin/support/` | `AdminSupportInboxAPIView` لقراءة بريد Zoho Mail، فتح رسالة (`?message_id=`)، الإرسال/الرد، وحفظ إعدادات `ZohoMailToken` للمالك |

---

## 2. ملخص المجموعات الكاملة في `api_v1/urls.py`
- **Auth & Profile**: `login`, `register`, `complete-profile`, `refresh`, `logout`, `me`, `change-password`, `reset-password-nid`, `google`, `google/callback`, `one-time-login`.
- **Public & Notifications & Payments**: `public/home`, `public/metadata`, `public/plans`, `public/guide`, `curriculum/lessons`, `notifications`, `notifications/<id>/read`, `payments/manual-checkout`.
- **Student**: `student/dashboard`, `student/groups/search`, `student/groups/<id>/join`, `student/groups/<id>/content`, `student/lectures/<id>/watch`, `student/exams/<id>/take`, `student/groups/<id>/marks`, `student/groups/<id>/ranking`, `student/groups/<id>/contact`, `student/packages`, `student/packages/<id>`, `student/packages/<id>/content`, `student/packages/<pId>/lectures/<lId>/watch`, `student/packages/<pId>/exams/<eId>/take`, `student/packages/<id>/marks`.
- **Teacher & Assistant**: `teacher/dashboard`, `teacher/groups/<id>`, `teacher/groups/<id>/lectures`, `teacher/lectures/<id>`, `teacher/lectures/<id>/codes`, `teacher/groups/<id>/pdfs`, `teacher/packages/<id>/pdfs`, `teacher/pdfs/<id>`, `teacher/groups/<id>/exams`, `teacher/exams/<id>`, `teacher/questions/<id>`, `teacher/groups/<id>/students`, `teacher/groups/<gId>/students/<sId>/logs`, `teacher/groups/<id>/bulk-log`, `teacher/groups/<id>/ranking`, `teacher/packages`, `teacher/packages/<id>`, `teacher/wallet`, `teacher/assistants`, `assistant/dashboard`, `assistant/teachers/<id>/groups`.
- **Admin**: `admin/dashboard`, `admin/maintenance/toggle`, `admin/users`, `admin/finance`, `admin/plans-staff`, `admin/support`.

