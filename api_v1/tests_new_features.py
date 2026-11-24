"""
api_v1/tests_new_features.py
اختبارات الميزات الجديدة: إجبارية النوع + بوابة القدامى، الشات الجماعي الموحد، صلاحية الأدمن الشاملة ومركز المحتوى، وتنقية الواجهة من التعليقات.
"""
from datetime import timedelta
import tempfile

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.http import HttpResponse
from django.test import Client, RequestFactory, TestCase, override_settings
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from accounts.models import EmailVerification, StudentProfile
from api_v1.authentication import generate_jwt_pair
from api_v1.models import DeviceBlock
from core.models import SiteSetting, Subject, SupportMessage
from core.profanity_filter import detect_profanity
from students.models import Enrollment
from ta3alm_project.middleware.web_device import FrontendHardeningMiddleware
from teachers.models import CoursePackage, Group, GroupChatMessage, SubscriptionPlan, TeacherProfile

User = get_user_model()


class NewFeaturesTestSuite(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.subject = Subject.objects.create(name='الكيمياء')
        self.plan = SubscriptionPlan.objects.create(
            name='الباقة الأساسية',
            price=100,
            student_limit=100,
            group_limit=1,
            assistant_limit=1,
            allow_online_packages=True,
            is_default=True,
        )

        self.admin_user = User.objects.create_user(
            username='admin_hub',
            email='admin_hub@ta3alm.online',
            password='AdminPassword123!',
            first_name='أدمن',
            last_name='الشامل',
            phone='01000000099',
            role='admin',
            is_staff=True,
            is_superuser=True,
        )

        self.teacher_user = User.objects.create_user(
            username='teacher_hub',
            email='teacher_hub@ta3alm.online',
            password='TeacherPassword123!',
            first_name='أحمد',
            last_name='عادل',
            phone='01011111199',
            gender='male',
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
            subscription_end_date=timezone.now() + timedelta(days=30),
            current_plan=self.plan,
            is_approved=True,
        )

        self.student_user = User.objects.create_user(
            username='student_hub',
            email='student_hub@ta3alm.online',
            password='StudentPassword123!',
            first_name='كريم',
            last_name='سالم',
            phone='01022222299',
            custom_id='S990001',
            national_id='30501010109999',
            gender=None,
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
            parent_phone='01099999998',
        )

        self.outsider_user = User.objects.create_user(
            username='outsider_hub',
            email='outsider_hub@ta3alm.online',
            password='StudentPassword123!',
            first_name='سارة',
            last_name='محمود',
            phone='01033333399',
            custom_id='S990002',
            national_id='30501010108888',
            gender='female',
            role='student',
        )
        EmailVerification.objects.create(
            user=self.outsider_user,
            code='333333',
            is_verified=True,
            expires_at=timezone.now() + timedelta(days=1),
        )
        self.outsider_profile = StudentProfile.objects.create(
            user=self.outsider_user,
            parent_phone='01088888887',
        )

        self.group = Group.objects.create(
            teacher=self.teacher_profile,
            name='مجموعة الكيمياء المتقدمة',
            grade='3_sec',
        )
        Enrollment.objects.create(
            student=self.student_profile,
            group=self.group,
            is_active=True,
        )
        self.package = CoursePackage.objects.create(
            teacher=self.teacher_profile,
            title='حزمة المراجعة',
            grade='3_sec',
            price=150,
            is_active=True,
        )

    def _auth_header(self, user):
        tokens = generate_jwt_pair(user)
        return {'HTTP_AUTHORIZATION': f"Bearer {tokens['access']}"}

    def test_gender_required_on_register_and_legacy_gate(self):
        # تسجيل بدون النوع يُرفض
        res_bad = self.client.post('/api/v1/auth/register/', {
            'full_name': 'طالب جديد',
            'email': 'no_gender@ta3alm.online',
            'phone': '01077777777',
            'password': 'Password123!',
            'role': 'student',
        }, format='json')
        self.assertEqual(res_bad.status_code, status.HTTP_400_BAD_REQUEST)

        # تسجيل بنوع صحيح يُقبل
        res_ok = self.client.post('/api/v1/auth/register/', {
            'full_name': 'طالبة جديدة',
            'email': 'female_new@ta3alm.online',
            'phone': '01077777778',
            'gender': 'female',
            'password': 'Password123!',
            'role': 'student',
        }, format='json')
        self.assertEqual(res_ok.status_code, status.HTTP_201_CREATED)
        self.assertEqual(res_ok.data['user']['gender'], 'female')
        self.assertFalse(res_ok.data['user']['requires_gender'])

        # مستخدم قديم بدون النوع: /auth/me/ يعيد requires_gender=True ويقبل PATCH
        legacy_hdr = self._auth_header(self.student_user)
        me_res = self.client.get('/api/v1/auth/me/', **legacy_hdr)
        self.assertEqual(me_res.status_code, status.HTTP_200_OK)
        self.assertTrue(me_res.data['requires_gender'])

        patch_res = self.client.patch('/api/v1/auth/me/', {'gender': 'male'}, format='json', **legacy_hdr)
        self.assertEqual(patch_res.status_code, status.HTTP_200_OK)
        self.student_user.refresh_from_db()
        self.assertEqual(self.student_user.gender, 'male')
        self.assertFalse(self.student_user.requires_gender_selection())

    @override_settings(ENFORCE_GENDER_MIDDLEWARE_IN_TESTS=True)
    def test_gender_completion_middleware_redirects_legacy_non_admin(self):
        web_client = Client()
        web_client.force_login(self.student_user)
        resp = web_client.get('/ar/')
        self.assertEqual(resp.status_code, 302)
        self.assertIn('complete-gender', resp['Location'])

        post_resp = web_client.post('/ar/complete-gender/', {'gender': 'male'})
        self.assertEqual(post_resp.status_code, 302)
        self.student_user.refresh_from_db()
        self.assertEqual(self.student_user.gender, 'male')

        # الأدمن لا يتم تحويله لبوابة النوع
        admin_client = Client()
        admin_client.force_login(self.admin_user)
        admin_resp = admin_client.get('/ar/admin-panel/')
        self.assertEqual(admin_resp.status_code, 200)

    def test_group_chat_permissions_lock_pin_and_clear(self):
        student_hdr = self._auth_header(self.student_user)
        teacher_hdr = self._auth_header(self.teacher_user)
        outsider_hdr = self._auth_header(self.outsider_user)
        admin_hdr = self._auth_header(self.admin_user)

        # غير المشترك مرفوض
        r_out = self.client.get(f'/api/v1/groups/{self.group.id}/chat/', **outsider_hdr)
        self.assertEqual(r_out.status_code, status.HTTP_403_FORBIDDEN)

        # الطالب المشترك يرسل رسالة
        r_send = self.client.post(
            f'/api/v1/groups/{self.group.id}/chat/',
            {'body': 'السلام عليكم يا أستاذ'},
            format='json',
            **student_hdr,
        )
        self.assertEqual(r_send.status_code, status.HTTP_201_CREATED)
        msg_id = r_send.data['message']['id']

        # الأدمن يثبت الرسالة ويقفل الشات
        r_pin = self.client.patch(
            f'/api/v1/groups/{self.group.id}/chat/{msg_id}/',
            {},
            format='json',
            **admin_hdr,
        )
        self.assertEqual(r_pin.status_code, status.HTTP_200_OK)
        self.assertTrue(r_pin.data['message']['is_pinned'])

        r_lock = self.client.post(
            f'/api/v1/groups/{self.group.id}/chat/',
            {'action': 'toggle_lock'},
            format='json',
            **teacher_hdr,
        )
        self.assertEqual(r_lock.status_code, status.HTTP_200_OK)
        self.assertTrue(r_lock.data['is_chat_locked'])

        # الطالب لا يستطيع الإرسال أثناء القفل
        r_blocked = self.client.post(
            f'/api/v1/groups/{self.group.id}/chat/',
            {'body': 'رسالة أثناء القفل'},
            format='json',
            **student_hdr,
        )
        self.assertEqual(r_blocked.status_code, status.HTTP_403_FORBIDDEN)

        # المعلم يمسح الشات
        r_clear = self.client.post(
            f'/api/v1/groups/{self.group.id}/chat/',
            {'action': 'clear'},
            format='json',
            **teacher_hdr,
        )
        self.assertEqual(r_clear.status_code, status.HTTP_200_OK)
        self.assertEqual(GroupChatMessage.objects.filter(group=self.group).count(), 0)

    def test_admin_content_hub_and_full_teacher_content_authority(self):
        admin_hdr = self._auth_header(self.admin_user)
        student_hdr = self._auth_header(self.student_user)

        # الطالب ممنوع من مركز إدارة المحتوى
        r_denied = self.client.get('/api/v1/admin/content-hub/', **student_hdr)
        self.assertEqual(r_denied.status_code, status.HTTP_403_FORBIDDEN)

        # الأدمن يستعرض المركز وينشئ مجموعة وحزمة ويدير محتوى أي معلم
        r_hub = self.client.get('/api/v1/admin/content-hub/', **admin_hdr)
        self.assertEqual(r_hub.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(r_hub.data['groups']), 1)

        r_new_g = self.client.post('/api/v1/admin/content-hub/', {
            'action': 'create_group',
            'teacher_id': self.teacher_profile.id,
            'name': 'مجموعة إدارية ثانية',
            'grade': '3_sec',
        }, format='json', **admin_hdr)
        self.assertEqual(r_new_g.status_code, status.HTTP_201_CREATED)
        second_group_id = r_new_g.data['group_id']

        # حتى لو تعدت المجموعة حد الباقة (group_limit=1)، الأدمن يديرها بالكامل
        r_grp_detail = self.client.get(f'/api/v1/teacher/groups/{second_group_id}/', **admin_hdr)
        self.assertEqual(r_grp_detail.status_code, status.HTTP_200_OK)

        r_pkg_detail = self.client.get(f'/api/v1/teacher/packages/{self.package.id}/', **admin_hdr)
        self.assertEqual(r_pkg_detail.status_code, status.HTTP_200_OK)

        # واجهة الويب للإدارة: مركز المحتوى + مساحات العمل
        web_admin = Client()
        web_admin.force_login(self.admin_user)
        self.assertEqual(web_admin.get('/ar/admin-panel/content-hub/').status_code, 200)
        self.assertEqual(web_admin.get(f'/ar/admin-panel/content-hub/groups/{self.group.id}/').status_code, 200)
        self.assertEqual(web_admin.get(f'/ar/admin-panel/content-hub/packages/{self.package.id}/').status_code, 200)

    def test_frontend_hardening_middleware_strips_html_comments(self):
        rf = RequestFactory()
        req = rf.get('/')

        def view(_request):
            return HttpResponse('<html><body><!-- secret comment --><h1>Hello</h1></body></html>', content_type='text/html; charset=utf-8')

        mw = FrontendHardeningMiddleware(view)
        resp = mw(req)
        body = resp.content.decode('utf-8')
        self.assertNotIn('<!--', body)
        self.assertNotIn('secret comment', body)
        self.assertEqual(resp['X-Content-Type-Options'], 'nosniff')

    def test_profanity_filter_catches_obfuscation_and_allows_curriculum_words(self):
        bad_samples = [
            'شرموطة',
            'شَـرْمُـوْطَـة',
            'كـ سـ مـ ك',
            'مـ*ـتـ*ـنـ*ـاك',
            'ششششرمووووطه',
            'fuuuuuck',
            'شرموته',
            'مطناكه',
            'كصمك',
            'كثمك',
            'عرث',
            'كحبه',
            'a7a',
            '5awal',
            '3ars',
            'kosomak',
            'ك0مك',
            'شرم9ط',
            'f.u.c.k',
            'p0rn',
            'b!tch',
        ]
        for sample in bad_samples:
            res = detect_profanity(sample)
            self.assertTrue(res.detected, f'Expected profanity match for: {sample}')

        safe_samples = [
            'عنصر النيكل عنصر انتقالي هام في الكيمياء',
            'قضيب مغناطيسي منتظم',
            'شرح درس لا النافية للجنس في النحو',
            'تحليل المقدار الجبري',
            'موعد السكشن الأول غداً',
            'رسالة مني وعنك في المراجعة',
            'مبارك حفل عرس سعيد',
        ]
        for safe in safe_samples:
            res = detect_profanity(safe)
            self.assertFalse(res.detected, f'False positive on safe curriculum text: {safe} ({res})')

    def test_student_profanity_in_group_and_support_chat_triggers_instant_ban(self):
        student_hdr = self._auth_header(self.student_user)
        install_id = 'test-install-profanity-group-001'

        r_bad = self.client.post(
            f'/api/v1/groups/{self.group.id}/chat/',
            {'body': 'شَـرْمُـوْطَـة'},
            format='json',
            HTTP_X_DEVICE_ID=install_id,
            **student_hdr,
        )
        self.assertEqual(r_bad.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(r_bad.data.get('code'), 'DEVICE_BLOCKED')
        self.assertEqual(GroupChatMessage.objects.filter(group=self.group).count(), 0)

        self.student_user.refresh_from_db()
        self.assertTrue(self.student_user.is_banned)
        self.assertTrue(
            DeviceBlock.objects.filter(installation_id=install_id, is_active=True).exists()
        )

        r_meta = self.client.get(
            '/api/v1/public/metadata/',
            HTTP_X_DEVICE_ID=install_id,
            **student_hdr,
        )
        self.assertEqual(r_meta.status_code, status.HTTP_200_OK)
        self.assertFalse(r_meta.data['boot_gate']['boot_allowed'])

        # طالب ثانٍ يرسل لفظاً مشفراً في الدعم الفني
        second_student = User.objects.create_user(
            username='student_profanity_2',
            email='stud_prof2@ta3alm.online',
            password='StudentPassword123!',
            first_name='يوسف',
            last_name='حسين',
            phone='01055554444',
            gender='male',
            role='student',
        )
        EmailVerification.objects.create(
            user=second_student,
            code='555555',
            is_verified=True,
            expires_at=timezone.now() + timedelta(days=1),
        )
        StudentProfile.objects.create(user=second_student, parent_phone='01099999997')
        second_hdr = self._auth_header(second_student)
        install_id_2 = 'test-install-profanity-support-002'

        r_sup = self.client.post(
            '/api/v1/support/chat/',
            {'body': 'كـ سـ مـ ك'},
            format='json',
            HTTP_X_DEVICE_ID=install_id_2,
            **second_hdr,
        )
        self.assertEqual(r_sup.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(r_sup.data.get('code'), 'DEVICE_BLOCKED')
        self.assertEqual(SupportMessage.objects.filter(sender=second_student).count(), 0)

        second_student.refresh_from_db()
        self.assertTrue(second_student.is_banned)
        self.assertTrue(
            DeviceBlock.objects.filter(installation_id=install_id_2, is_active=True).exists()
        )

    def test_account_only_ban_blocks_metadata_boot_gate_and_web_client(self):
        banned_user = User.objects.create_user(
            username='account_banned_only',
            email='acct_ban@ta3alm.online',
            password='StudentPassword123!',
            first_name='كريم',
            last_name='سعيد',
            phone='01077778888',
            gender='male',
            role='student',
            is_banned=True,
        )
        EmailVerification.objects.create(
            user=banned_user,
            code='777777',
            is_verified=True,
            expires_at=timezone.now() + timedelta(days=1),
        )
        hdr = self._auth_header(banned_user)

        r_meta = self.client.get(
            '/api/v1/public/metadata/',
            HTTP_X_DEVICE_ID='clean-device-install-999',
            **hdr,
        )
        self.assertEqual(r_meta.status_code, status.HTTP_200_OK)
        self.assertFalse(r_meta.data['boot_gate']['boot_allowed'])
        self.assertEqual(r_meta.data['boot_gate']['code'], 'ACCOUNT_BANNED')

        web_client = Client()
        web_client.force_login(banned_user)
        web_resp = web_client.get('/ar/')
        self.assertEqual(web_resp.status_code, 403)
        html = web_resp.content.decode('utf-8')
        self.assertIn('هذا الحساب محظور من استخدام المنصة', html)

    def test_apk_download_supports_http_range_partial_content(self):
        with tempfile.TemporaryDirectory() as tmp_media:
            with override_settings(
                MEDIA_ROOT=tmp_media,
                STORAGES={
                    'default': {'BACKEND': 'django.core.files.storage.FileSystemStorage'},
                    'staticfiles': {'BACKEND': 'django.contrib.staticfiles.storage.StaticFilesStorage'},
                },
            ):
                settings_obj = SiteSetting.load()
                apk_bytes = b'PK\x03\x040123456789ABCDEF'
                settings_obj.android_apk_file = SimpleUploadedFile(
                    'ta3alm-test.apk',
                    apk_bytes,
                    content_type='application/vnd.android.package-archive',
                )
                settings_obj.android_apk_url = ''
                settings_obj.save()

                resp = self.client.get('/api/v1/public/app-update/download/', HTTP_RANGE='bytes=0-3')
                self.assertEqual(resp.status_code, 206)
                self.assertEqual(resp['Accept-Ranges'], 'bytes')
                self.assertEqual(resp['Content-Range'], f'bytes 0-3/{len(apk_bytes)}')
                body = b''.join(resp.streaming_content) if getattr(resp, 'streaming', False) else resp.content
                self.assertEqual(body, b'PK\x03\x04')

                head_resp = self.client.head('/api/v1/public/app-update/download/')
                self.assertEqual(head_resp.status_code, 200)
                self.assertEqual(head_resp['Accept-Ranges'], 'bytes')
                self.assertEqual(head_resp['Content-Length'], str(len(apk_bytes)))

