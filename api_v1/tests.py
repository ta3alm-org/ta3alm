"""
api_v1/tests.py — اختبارات شاملة لواجهة برمجة التطبيقات (Phase 3: API Testing & Validation)
تغطي:
- المصادقة (تسجيل، تأكيد OTP، استكمال بيانات، دخول بالبريد/الهاتف/الكود، تحديث التوكن، استعادة كلمة المرور)
- الصلاحيات وعزل بيانات الطلاب (منع IDOR وحظر المستخدمين)
- مسارات المعلم والطالب (المجموعات، المحاضرات، أكواد الفيديو، الامتحانات، الدرجات، المتصدرين)
- مسارات الكورسات الشاملة (الحزم)، المدفوعات اليدوية، ومحفظة المعلم، والإدارة
"""
from datetime import timedelta
import shutil
import tempfile

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from accounts.models import EmailVerification, StudentProfile
from api_v1.authentication import generate_jwt_pair
from api_v1.video_security import clear_watch_window
from core.models import ManualPayment, SiteSetting, Subject
from exams.models import Exam, Question
from students.models import Enrollment, PackageEnrollment
from teachers.models import CoursePackage, Group, Lecture, SubscriptionPlan, TeacherProfile, VideoCode, Wallet

User = get_user_model()


class Ta3almAPIV1TestSuite(TestCase):
    def setUp(self):
        cache.clear()
        self.media_dir = tempfile.mkdtemp(prefix='ta3alm_api_v1_tests_')
        self.client = APIClient()

        # إعداد المادة وباقة الاشتراك الافتراضية
        self.subject = Subject.objects.create(name='الفيزياء')
        self.plan = SubscriptionPlan.objects.create(
            name='الباقة الماسية',
            price=200,
            student_limit=500,
            group_limit=10,
            assistant_limit=3,
            allow_online_packages=True,
            is_default=True,
        )

        # إنشاء مالك المنصة (Admin Owner)
        self.admin_user = User.objects.create_user(
            username='owner_admin',
            email='owner@ta3alm.online',
            password='StrongPassword123!',
            first_name='أدمن',
            last_name='المنصة',
            phone='01000000001',
            role='admin',
            is_staff=True,
            is_superuser=True,
        )

        # إنشاء معلم نشط باشتراك سارٍ
        self.teacher_user = User.objects.create_user(
            username='mr_ahmed',
            email='ahmed@ta3alm.online',
            password='TeacherPassword123!',
            first_name='أحمد',
            last_name='محمود',
            phone='01011111111',
            role='teacher',
        )
        EmailVerification.objects.create(
            user=self.teacher_user,
            code='111111',
            is_verified=True,
            expires_at=timezone.now() + timedelta(days=1),
        )
        self.teacher_profile = TeacherProfile.objects.create(
            user=self.teacher_user,
            subject=self.subject,
            bio='خبير الفيزياء للثانوية العامة',
            subscription_end_date=timezone.now() + timedelta(days=30),
            current_plan=self.plan,
            is_approved=True,
        )
        Wallet.objects.create(teacher=self.teacher_profile, balance=500)

        # إنشاء طالب أول
        self.student_user = User.objects.create_user(
            username='student_ali',
            email='ali@ta3alm.online',
            password='StudentPassword123!',
            first_name='علي',
            last_name='حسن',
            phone='01022222222',
            national_id='30501010101234',
            role='student',
        )
        EmailVerification.objects.create(
            user=self.student_user,
            code='222222',
            is_verified=True,
            expires_at=timezone.now() + timedelta(days=1),
        )
        self.student_profile = StudentProfile.objects.create(
            user=self.student_user,
            parent_phone='01099999999',
        )

        # إنشاء طالب ثانٍ لاختبار عزل البيانات (IDOR)
        self.other_student_user = User.objects.create_user(
            username='student_omar',
            email='omar@ta3alm.online',
            password='StudentPassword123!',
            first_name='عمر',
            last_name='خالد',
            phone='01033333333',
            national_id='30502020202345',
            role='student',
        )
        EmailVerification.objects.create(
            user=self.other_student_user,
            code='333333',
            is_verified=True,
            expires_at=timezone.now() + timedelta(days=1),
        )
        self.other_student_profile = StudentProfile.objects.create(
            user=self.other_student_user,
            parent_phone='01088888888',
        )

    def tearDown(self):
        cache.clear()
        shutil.rmtree(self.media_dir, ignore_errors=True)

    def _auth_headers(self, user):
        tokens = generate_jwt_pair(user)
        return {'HTTP_AUTHORIZATION': f"Bearer {tokens['access']}"}

    # ==========================================================
    # 1. اختبارات المصادقة وإدارة الحساب
    # ==========================================================
    def test_01_register_and_complete_profile_flow(self):
        # 1) تسجيل حساب جديد
        res = self.client.post('/api/v1/auth/register/', {
            'full_name': 'يوسف إبراهيم',
            'email': 'newstudent@ta3alm.online',
            'phone': '01055555555',
            'password': 'NewPassword123!',
            'role': 'student',
        }, format='json')
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        self.assertIn('access', res.data)
        self.assertIn('refresh', res.data)
        self.assertFalse(res.data['user']['is_profile_complete'])

        access_token = res.data['access']
        headers = {'HTTP_AUTHORIZATION': f'Bearer {access_token}'}

        # 2) التحقق من كود البريد الإلكتروني (OTP) قبل استكمال الملف الشخصي
        verification = EmailVerification.objects.get(user__email='newstudent@ta3alm.online')
        res_otp = self.client.post('/api/v1/auth/verify-otp/', {
            'code': verification.code,
        }, format='json', **headers)
        self.assertEqual(res_otp.status_code, status.HTTP_200_OK)

        # 3) استكمال الملف الشخصي كطالب
        res_complete = self.client.post('/api/v1/auth/complete-profile/', {
            'full_name': 'يوسف إبراهيم',
            'phone': '01055555555',
            'parent_phone': '01066666666',
            'national_id': '30601010101234',
        }, format='json', **headers)
        self.assertEqual(res_complete.status_code, status.HTTP_200_OK)
        self.assertTrue(res_complete.data['user']['is_profile_complete'])
        self.assertEqual(res_complete.data['user']['role'], 'student')

    def test_02_login_with_email_phone_and_custom_id_and_refresh(self):
        # الدخول بالبريد الإلكتروني
        res_email = self.client.post('/api/v1/auth/login/', {
            'identifier': 'ali@ta3alm.online',
            'password': 'StudentPassword123!',
        }, format='json')
        self.assertEqual(res_email.status_code, status.HTTP_200_OK)
        self.assertIn('access', res_email.data)

        # الدخول برقم الهاتف
        res_phone = self.client.post('/api/v1/auth/login/', {
            'identifier': '01022222222',
            'password': 'StudentPassword123!',
        }, format='json')
        self.assertEqual(res_phone.status_code, status.HTTP_200_OK)

        # الدخول بالكود المميز للطالب (custom_id)
        res_code = self.client.post('/api/v1/auth/login/', {
            'identifier': self.student_user.custom_id,
            'password': 'StudentPassword123!',
        }, format='json')
        self.assertEqual(res_code.status_code, status.HTTP_200_OK)

        # تحديث التوكن (Refresh Token)
        refresh_token = res_code.data['refresh']
        res_refresh = self.client.post('/api/v1/auth/refresh/', {
            'refresh': refresh_token,
        }, format='json')
        self.assertEqual(res_refresh.status_code, status.HTTP_200_OK)
        self.assertIn('access', res_refresh.data)

    def test_03_reset_password_by_national_id(self):
        res = self.client.post('/api/v1/auth/reset-password-nid/', {
            'phone': '01022222222',
            'national_id': '30501010101234',
            'new_password': 'ResetPassword999!',
        }, format='json')
        self.assertEqual(res.status_code, status.HTTP_200_OK)

        # التأكد من الدخول بكلمة المرور الجديدة
        res_login = self.client.post('/api/v1/auth/login/', {
            'identifier': '01022222222',
            'password': 'ResetPassword999!',
        }, format='json')
        self.assertEqual(res_login.status_code, status.HTTP_200_OK)

    # ==========================================================
    # 2. اختبارات الصلاحيات وعزل البيانات (Security & IDOR)
    # ==========================================================
    def test_04_role_permissions_and_ban_enforcement(self):
        student_headers = self._auth_headers(self.student_user)

        # الطالب لا يمكنه الوصول للوحة المعلم أو الإدارة
        res_teacher = self.client.get('/api/v1/teacher/dashboard/', **student_headers)
        self.assertEqual(res_teacher.status_code, status.HTTP_403_FORBIDDEN)

        res_admin = self.client.get('/api/v1/admin/dashboard/', **student_headers)
        self.assertEqual(res_admin.status_code, status.HTTP_403_FORBIDDEN)

        # عند حظر المستخدم يُرفض طلبه فوراً
        self.student_user.is_banned = True
        self.student_user.save(update_fields=['is_banned'])
        res_banned = self.client.get('/api/v1/student/dashboard/', **student_headers)
        self.assertEqual(res_banned.status_code, status.HTTP_403_FORBIDDEN)
        self.student_user.is_banned = False
        self.student_user.save(update_fields=['is_banned'])

    # ==========================================================
    # 3. دورة عمل المعلم والطالب الكاملة (المجموعات، المحاضرات، الأكواد، الامتحانات)
    # ==========================================================
    def test_05_full_educational_workflow_teacher_and_student(self):
        teacher_headers = self._auth_headers(self.teacher_user)
        student_headers = self._auth_headers(self.student_user)
        other_student_headers = self._auth_headers(self.other_student_user)

        # 1) المعلم ينشئ مجموعة جديدة
        res_grp = self.client.post('/api/v1/teacher/dashboard/', {
            'name': 'مجموعة الفيزياء - تالتة ثانوي',
            'grade': '3_sec',
        }, format='json', **teacher_headers)
        self.assertEqual(res_grp.status_code, status.HTTP_201_CREATED)
        group_id = res_grp.data['group']['id']

        # 2) الطالب يبحث عن المجموعة ويرسل طلب انضمام
        res_search = self.client.get('/api/v1/student/groups/search/?q=الفيزياء', **student_headers)
        self.assertEqual(res_search.status_code, status.HTTP_200_OK)
        self.assertTrue(len(res_search.data['groups']) >= 1)

        res_join = self.client.post(f'/api/v1/student/groups/{group_id}/join/', {}, format='json', **student_headers)
        self.assertEqual(res_join.status_code, status.HTTP_201_CREATED)
        enrollment_id = res_join.data['enrollment']['id']

        # قبل موافقة المعلم: الطالب لا يستطيع فتح محتوى المجموعة
        res_pre_access = self.client.get(f'/api/v1/student/groups/{group_id}/content/', **student_headers)
        self.assertEqual(res_pre_access.status_code, status.HTTP_403_FORBIDDEN)

        # 3) المعلم يقبل طلب انضمام الطالب
        res_accept = self.client.post(f'/api/v1/teacher/groups/{group_id}/students/', {
            'action_type': 'accept',
            'enroll_id': enrollment_id,
        }, format='json', **teacher_headers)
        self.assertEqual(res_accept.status_code, status.HTTP_200_OK)

        # 4) طالب آخر غير مسجل (IDOR test) يحاول فتح المجموعة -> 403
        res_idor = self.client.get(f'/api/v1/student/groups/{group_id}/content/', **other_student_headers)
        self.assertEqual(res_idor.status_code, status.HTTP_403_FORBIDDEN)

        # 5) المعلم يضيف محاضرة للمجموعة
        res_lec = self.client.post(f'/api/v1/teacher/groups/{group_id}/lectures/', {
            'title': 'المحاضرة الأولى: التيار الكهربي وقانون أوم',
            'description': 'شرح تفصيلي لقانون أوم مع حل مسائل',
            'video_link': 'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
        }, format='json', **teacher_headers)
        self.assertEqual(res_lec.status_code, status.HTTP_201_CREATED)
        lecture_id = res_lec.data['lecture']['id']

        # 6) المعلم يولّد أكواد مشاهدة للمحاضرة (بحد أقصى مشاهدتين)
        res_codes = self.client.post(f'/api/v1/teacher/lectures/{lecture_id}/codes/', {
            'amount': 2,
            'views_limit': 2,
        }, format='json', **teacher_headers)
        self.assertEqual(res_codes.status_code, status.HTTP_201_CREATED)
        video_code = res_codes.data['generated_codes'][0]['code']

        # 7) الطالب يحاول مشاهدة المحاضرة قبل إدخال الكود -> يُطلب منه الكود
        res_watch_locked = self.client.get(f'/api/v1/student/lectures/{lecture_id}/watch/', **student_headers)
        self.assertEqual(res_watch_locked.status_code, status.HTTP_200_OK)
        self.assertFalse(res_watch_locked.data['is_unlocked'])

        # 8) الطالب يفعل الكود ثم يشاهد المحاضرة (المشاهدة 1 من 2)
        res_unlock = self.client.post(f'/api/v1/student/lectures/{lecture_id}/watch/', {
            'code': video_code,
        }, format='json', **student_headers)
        self.assertEqual(res_unlock.status_code, status.HTTP_200_OK)
        self.assertTrue(res_unlock.data['is_unlocked'])
        self.assertEqual(res_unlock.data['code_info']['current_views'], 0)

        res_watch_1 = self.client.get(f'/api/v1/student/lectures/{lecture_id}/watch/', **student_headers)
        self.assertTrue(res_watch_1.data['is_unlocked'])
        self.assertEqual(res_watch_1.data['code_info']['current_views'], 1)

        # المشاهدة 2 من 2 في نافذة جديدة
        clear_watch_window(self.student_user, lecture_id)
        res_watch_2 = self.client.get(f'/api/v1/student/lectures/{lecture_id}/watch/', **student_headers)
        self.assertTrue(res_watch_2.data['is_unlocked'])
        self.assertEqual(res_watch_2.data['code_info']['current_views'], 2)

        # المشاهدة 3 (تجاوز الحد الأقصى في نافذة جديدة) -> تُغلق المحاضرة مجدداً
        clear_watch_window(self.student_user, lecture_id)
        res_watch_3 = self.client.get(f'/api/v1/student/lectures/{lecture_id}/watch/', **student_headers)
        self.assertFalse(res_watch_3.data['is_unlocked'])

        # 9) المعلم ينشئ امتحاناً نشطاً ويضيف سؤالاً
        res_exam = self.client.post(f'/api/v1/teacher/groups/{group_id}/exams/', {
            'title': 'امتحان الفصل الأول',
            'duration_minutes': 30,
            'is_active': True,
        }, format='json', **teacher_headers)
        self.assertEqual(res_exam.status_code, status.HTTP_201_CREATED)
        exam_id = res_exam.data['exam']['id']

        res_q1 = self.client.post(f'/api/v1/teacher/exams/{exam_id}/', {
            'text': 'وحدة قياس شدة التيار الكهربي هي؟',
            'option_a': 'الأمبير',
            'option_b': 'الفولت',
            'option_c': 'الأوم',
            'option_d': 'الواط',
            'correct_answer': 'A',
            'marks': 5,
        }, format='json', **teacher_headers)
        self.assertEqual(res_q1.status_code, status.HTTP_201_CREATED)
        q1_id = res_q1.data['question']['id']

        # 10) الطالب يفتح الامتحان: التحقق الأمني من عدم إرسال الإجابة الصحيحة (correct_answer)
        res_take_get = self.client.get(f'/api/v1/student/exams/{exam_id}/take/', **student_headers)
        self.assertEqual(res_take_get.status_code, status.HTTP_200_OK)
        self.assertNotIn('correct_answer', res_take_get.data['questions'][0])

        # 11) الطالب يسلّم الامتحان ويتم التصحيح التلقائي ورصد الدرجة
        res_take_post = self.client.post(f'/api/v1/student/exams/{exam_id}/take/', {
            'answers': {str(q1_id): 'A'},
        }, format='json', **student_headers)
        self.assertEqual(res_take_post.status_code, status.HTTP_201_CREATED)
        self.assertEqual(res_take_post.data['score'], 5)
        self.assertEqual(res_take_post.data['total_marks'], 5)

        # منع إعادة دخول الامتحان مرة ثانية
        res_retake = self.client.post(f'/api/v1/student/exams/{exam_id}/take/', {
            'answers': {str(q1_id): 'A'},
        }, format='json', **student_headers)
        self.assertEqual(res_retake.status_code, status.HTTP_400_BAD_REQUEST)

        # 12) الطالب يستعرض درجاته ولوحة الشرف
        res_marks = self.client.get(f'/api/v1/student/groups/{group_id}/marks/', **student_headers)
        self.assertEqual(res_marks.status_code, status.HTTP_200_OK)
        self.assertTrue(len(res_marks.data['exam_results']) >= 1)

        res_rank = self.client.get(f'/api/v1/student/groups/{group_id}/ranking/', **student_headers)
        self.assertEqual(res_rank.status_code, status.HTTP_200_OK)
        self.assertEqual(res_rank.data['leaderboard'][0]['student_name'], 'علي حسن')
        self.assertEqual(res_rank.data['leaderboard'][0]['total_score'], 5)

    # ==========================================================
    # 4. اختبارات الكورسات الشاملة (Packages) والمدفوعات اليدوية والإدارة
    # ==========================================================
    def test_06_packages_manual_payment_and_admin_approval(self):
        teacher_headers = self._auth_headers(self.teacher_user)
        student_headers = self._auth_headers(self.student_user)
        admin_headers = self._auth_headers(self.admin_user)

        with override_settings(
            MEDIA_ROOT=self.media_dir,
            STORAGES={
                'default': {'BACKEND': 'django.core.files.storage.FileSystemStorage'},
                'staticfiles': {'BACKEND': 'django.contrib.staticfiles.storage.StaticFilesStorage'},
            },
        ):
            # 1) المعلم ينشئ كورس شامل (Package)
            res_pkg = self.client.post('/api/v1/teacher/packages/', {
                'title': 'معسكر مراجعة الفيزياء النهائية',
                'description': 'مراجعة شاملة للمنهج بالكامل',
                'grade': '3_sec',
                'price': 300,
                'view_limit': 3,
            }, format='json', **teacher_headers)
            self.assertEqual(res_pkg.status_code, status.HTTP_201_CREATED)
            pkg_id = res_pkg.data['package']['id']

            # إضافة محاضرة داخل الكورس
            res_pkg_lec = self.client.post(f'/api/v1/teacher/packages/{pkg_id}/', {
                'action': 'add_lecture',
                'title': 'محاضرة المراجعة الأولى',
                'video_link': 'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
            }, format='json', **teacher_headers)
            self.assertEqual(res_pkg_lec.status_code, status.HTTP_201_CREATED)
            pkg_lec_id = res_pkg_lec.data['lecture']['id']

            # 2) الطالب يرفع إيصال دفع يدوي للاشتراك في الكورس
            png_1x1 = (
                b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
                b'\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\rIDATx\x9cc```\xf8\x0f\x00'
                b'\x01\x01\x01\x00\x18\xdd\x8d\xb4\x00\x00\x00\x00IEND\xaeB`\x82'
            )
            fake_receipt = SimpleUploadedFile('receipt.png', png_1x1, content_type='image/png')
            res_pay = self.client.post('/api/v1/payments/manual-checkout/', {
                'payment_type': 'student_package',
                'target_id': pkg_id,
                'phone_number': '01022222222',
                'receipt_image': fake_receipt,
            }, format='multipart', **student_headers)
            self.assertEqual(res_pay.status_code, status.HTTP_201_CREATED)
            payment_id = res_pay.data['payment']['id']

            # 3) الأدمن يراجع الإيصال ويقبله -> يتم تفعيل الكورس للطالب وإيداع الرصيد في محفظة المعلم
            res_approve = self.client.post('/api/v1/admin/finance/', {
                'item_type': 'manual_payment',
                'id': payment_id,
                'action': 'approve',
            }, format='json', **admin_headers)
            self.assertEqual(res_approve.status_code, status.HTTP_200_OK)

            # التأكد من تسجيل الطالب في الكورس
            self.assertTrue(
                PackageEnrollment.objects.filter(
                    student=self.student_profile,
                    package_id=pkg_id,
                    is_paid=True,
                ).exists()
            )

            # 4) الطالب يشاهد محاضرة الكورس ويحصل على +10 نقاط تشجيعية
            res_watch_pkg = self.client.post(
                f'/api/v1/student/packages/{pkg_id}/lectures/{pkg_lec_id}/watch/',
                {},
                format='json',
                **student_headers,
            )
            self.assertEqual(res_watch_pkg.status_code, status.HTTP_200_OK)
            self.assertTrue(res_watch_pkg.data['points_just_awarded'])

        # 5) الأدمن يختبر لوحة الإحصائيات وتبديل وضع الصيانة
        res_admin_dash = self.client.get('/api/v1/admin/dashboard/', **admin_headers)
        self.assertEqual(res_admin_dash.status_code, status.HTTP_200_OK)
        self.assertIn('total_teachers', res_admin_dash.data)
        self.assertIn('is_maintenance_mode', res_admin_dash.data)

        res_maint = self.client.post('/api/v1/admin/maintenance/toggle/', {}, format='json', **admin_headers)
        self.assertEqual(res_maint.status_code, status.HTTP_200_OK)
        self.assertTrue(res_maint.data['is_maintenance_mode'])
