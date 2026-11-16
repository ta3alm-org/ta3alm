"""
api_v1/tests_video_security.py
اختبارات شاملة لنظام حماية الفيديو، التوكنات قصيرة العمر، إبطال الجلسات المتزامنة،
تتبع التقدم والعلامات المرجعية، وحماية Google Play Integrity.
"""
from datetime import timedelta
from decimal import Decimal
import json
import shutil
import tempfile
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core import mail
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APITestCase

from accounts.models import EmailVerification, StudentProfile
from core.models import ManualPayment, SiteSetting, Subject, reconcile_teacher_wallet
from exams.models import Exam, Question
from students.models import Enrollment, PackageEnrollment, VideoViewTracking
from teachers.models import CoursePackage, Group, Lecture, SubscriptionPlan, TeacherProfile, VideoCode, Wallet

from api_v1.integrity_service import compute_request_hash
from api_v1.models import (
    DeviceIntegrityRecord,
    PlaybackSession,
    PlayIntegrityNonce,
    VideoAsset,
    VideoBookmark,
    VideoProgress,
    VideoSecurityAuditLog,
)
from api_v1.video_security import decode_playback_token

User = get_user_model()


class VideoSecurityAndIntegrityTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.subject = Subject.objects.create(name='Physics')
        self.plan = SubscriptionPlan.objects.create(
            name='Pro Plan',
            price=200,
            student_limit=500,
            group_limit=10,
            assistant_limit=3,
            allow_online_packages=True,
        )
        self.teacher_user = User.objects.create_user(
            username='teacher1',
            email='teacher1@example.com',
            password='Password123!',
            role='teacher',
            first_name='Ahmed',
        )
        self.teacher = TeacherProfile.objects.create(
            user=self.teacher_user,
            subject=self.subject,
            current_plan=self.plan,
            subscription_end_date=timezone.now() + timedelta(days=30),
        )
        self.group = Group.objects.create(teacher=self.teacher, name='Sec 3 Physics', grade='3_sec')
        self.protected_lecture = Lecture.objects.create(
            group=self.group,
            title='Wave Motion Native HLS',
            video_link='https://origin.private.ta3alm.online/raw/secret-1.mp4',
            description='Protected lesson',
            is_active=True,
        )
        self.next_lecture = Lecture.objects.create(
            group=self.group,
            title='Optics Part 2',
            video_link='https://www.youtube.com/watch?v=dQw4w9WgXcQ',
            description='Legacy YouTube lesson',
            is_active=True,
        )
        self.asset = VideoAsset.objects.create(
            lecture=self.protected_lecture,
            source_type='hls_protected',
            provider='bunny_stream',
            provider_asset_id='vid-abc-123',
            manifest_url='https://cdn.example.net/vid-abc-123/playlist.m3u8',
            quality_variants=[
                {'label': '360p', 'height': 360, 'bandwidth': 800000, 'url': 'https://cdn.example.net/vid-abc-123/360p/video.m3u8'},
                {'label': '720p', 'height': 720, 'bandwidth': 2400000, 'url': 'https://cdn.example.net/vid-abc-123/720p/video.m3u8'},
            ],
            subtitle_tracks=[
                {'language': 'ar', 'label': 'العربية', 'url': 'https://cdn.example.net/sub/ar.vtt', 'format': 'vtt'},
            ],
            duration_seconds=1200,
            intro_start_seconds=5,
            intro_end_seconds=35,
            migration_status='verified',
        )

        self.student_user = User.objects.create_user(
            username='student1',
            email='student1@example.com',
            password='Password123!',
            role='student',
            first_name='Omar',
            phone='01012345678',
        )
        self.student = StudentProfile.objects.create(user=self.student_user, parent_phone='01099999999')
        Enrollment.objects.create(student=self.student, group=self.group, is_active=True)

        self.other_student_user = User.objects.create_user(
            username='student2',
            email='student2@example.com',
            password='Password123!',
            role='student',
            first_name='Ali',
        )
        self.other_student = StudentProfile.objects.create(user=self.other_student_user, parent_phone='01088888888')

        self.video_code = VideoCode.objects.create(
            lecture=self.protected_lecture,
            code='SEC123',
            max_views=3,
        )
        for u in (self.teacher_user, self.student_user, self.other_student_user):
            EmailVerification.objects.create(
                user=u,
                code='123456',
                is_verified=True,
                expires_at=timezone.now() + timedelta(days=1),
            )

    def test_unenrolled_student_cannot_authorize_video(self):
        self.client.force_authenticate(user=self.other_student_user)
        url = reverse('api_v1_video_authorize', args=[self.protected_lecture.id])
        resp = self.client.post(url, {'device_id': 'dev-other'})
        self.assertEqual(resp.status_code, 403)
        self.assertTrue(VideoSecurityAuditLog.objects.filter(event_type='authorize_denied', user=self.other_student_user).exists())

    def test_video_code_activation_and_raw_url_suppression(self):
        self.client.force_authenticate(user=self.student_user)
        url = reverse('api_v1_video_authorize', args=[self.protected_lecture.id])

        # بدون كود أولاً يطلب الكود
        denied = self.client.get(url)
        self.assertEqual(denied.status_code, 403)
        self.assertTrue(denied.data.get('require_code'))

        # تفعيل الكود وإصدار توكن قصير العمر + عدم تسريب raw video_link
        resp = self.client.post(url, {'code': 'SEC123', 'device_id': 'android-dev-1'})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.data['is_unlocked'])
        self.assertEqual(resp.data['lecture']['video_link'], '')
        self.assertTrue(resp.data['source']['is_native_protected'])
        self.assertEqual(len(resp.data['source']['quality_variants']), 2)
        self.assertIn('watermark', resp.data)
        self.assertNotIn('01012345678', resp.data['watermark']['display_text'])
        self.assertTrue(resp.data['watermark']['masked_phone'].endswith('5678'))

        claims = decode_playback_token(resp.data['playback_token'])
        self.assertEqual(claims['dev'], 'android-dev-1')
        self.assertEqual(claims['lec'], self.protected_lecture.id)

    def test_legacy_youtube_lecture_separated_explicitly(self):
        from .video_security import unseal_video_reference
        VideoCode.objects.create(lecture=self.next_lecture, code='YT1111', max_views=2)
        self.client.force_authenticate(user=self.student_user)
        url = reverse('api_v1_video_authorize', args=[self.next_lecture.id])
        resp = self.client.post(url, {'code': 'YT1111', 'device_id': 'android-dev-1'})
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.data['source']['is_native_protected'])
        self.assertEqual(resp.data['source']['source_type'], 'ta3alm_shield')
        self.assertIsNone(resp.data['source']['youtube_video_id'])
        self.assertEqual(resp.data['source']['legacy_external_url'], '')
        self.assertNotIn('youtube.com', str(resp.data))
        sealed_ref = resp.data['source']['sealed_video_ref']
        self.assertTrue(bool(sealed_ref))
        self.assertEqual(
            unseal_video_reference(sealed_ref, resp.data['session_id'], resp.data['playback_token']),
            'dQw4w9WgXcQ',
        )

    def test_concurrent_session_revocation_on_second_device(self):
        self.client.force_authenticate(user=self.student_user)
        auth_url = reverse('api_v1_video_authorize', args=[self.protected_lecture.id])
        hb_url = reverse('api_v1_video_heartbeat', args=[self.protected_lecture.id])

        first = self.client.post(auth_url, {'code': 'SEC123', 'device_id': 'device-A'})
        self.assertEqual(first.status_code, 200)

        second = self.client.post(auth_url, {'device_id': 'device-B'})
        self.assertEqual(second.status_code, 200)
        self.assertEqual(second.data['revoked_other_sessions'], 1)

        # الجهاز الأول يرفض عند إرسال Heartbeat
        hb_old = self.client.post(hb_url, {
            'session_id': first.data['session_id'],
            'playback_token': first.data['playback_token'],
            'device_id': 'device-A',
        })
        self.assertEqual(hb_old.status_code, 409)
        self.assertEqual(hb_old.data.get('code'), 'SESSION_REVOKED')

        # الجهاز الثاني يعمل بشكل طبيعي مع تجديد التوكن
        hb_new = self.client.post(hb_url, {
            'session_id': second.data['session_id'],
            'playback_token': second.data['playback_token'],
            'device_id': 'device-B',
            'refresh_token': True,
        })
        self.assertEqual(hb_new.status_code, 200)
        self.assertIn('playback_token', hb_new.data)

    def test_progress_resume_continue_watching_and_bookmarks(self):
        self.client.force_authenticate(user=self.student_user)
        progress_url = reverse('api_v1_video_progress', args=[self.protected_lecture.id])
        resp = self.client.post(progress_url, {
            'position_seconds': 1100,
            'duration_seconds': 1200,
            'watched_delta_seconds': 60,
            'preferred_speed': 1.5,
        })
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.data['is_completed'])
        self.assertEqual(resp.data['preferred_speed'], 1.5)

        cw_url = reverse('api_v1_video_continue_watching')
        cw_resp = self.client.get(cw_url)
        self.assertEqual(cw_resp.status_code, 200)
        self.assertEqual(len(cw_resp.data['items']), 1)
        self.assertEqual(cw_resp.data['items'][0]['position_seconds'], 1100)

        bm_url = reverse('api_v1_video_bookmarks', args=[self.protected_lecture.id])
        created = self.client.post(bm_url, {'timestamp_seconds': 420, 'title': 'Wave formula', 'note': 'Important'})
        self.assertEqual(created.status_code, 201)
        bm_id = created.data['bookmark']['id']
        self.assertEqual(VideoBookmark.objects.count(), 1)

        del_url = reverse('api_v1_video_bookmark_delete', args=[bm_id])
        deleted = self.client.delete(del_url)
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(VideoBookmark.objects.count(), 0)

    def test_play_integrity_challenge_replay_and_policy_enforcement(self):
        self.client.force_authenticate(user=self.student_user)
        challenge_url = reverse('api_v1_integrity_challenge')
        verify_url = reverse('api_v1_integrity_verify')

        ch_resp = self.client.post(challenge_url, {'action': 'video_authorize', 'binding_data': str(self.protected_lecture.id)})
        self.assertEqual(ch_resp.status_code, 200)
        nonce_id = ch_resp.data['nonce_id']

        # التحقق الأول في وضع التطوير
        with override_settings(DEBUG=True):
            ver_resp = self.client.post(
                verify_url,
                {
                    'nonce_id': nonce_id,
                    'device_id': 'android-dev-clean',
                    'is_debug_build': True,
                    'tamper_signals': {'frida_detected': False},
                },
                format='json',
            )
            self.assertEqual(ver_resp.status_code, 200)
            self.assertEqual(ver_resp.data['policy_decision'], 'allow')

            # إعادة استخدام نفس الـ Nonce تُرفض كـ Replay Attack
            replay_resp = self.client.post(
                verify_url,
                {
                    'nonce_id': nonce_id,
                    'device_id': 'android-dev-clean',
                    'is_debug_build': True,
                },
                format='json',
            )
            self.assertEqual(replay_resp.status_code, 400)
            self.assertEqual(replay_resp.data.get('code'), 'NONCE_ALREADY_USED')

            # محاكاة رصد Frida يجب أن يؤدي إلى block حتى في التطوير
            ch2 = self.client.post(challenge_url, {'action': 'video_authorize'})
            blocked_resp = self.client.post(
                verify_url,
                {
                    'nonce_id': ch2.data['nonce_id'],
                    'device_id': 'android-dev-frida',
                    'is_debug_build': True,
                    'tamper_signals': {'frida_detected': True},
                },
                format='json',
            )
            self.assertEqual(blocked_resp.status_code, 200)
            self.assertEqual(blocked_resp.data['policy_decision'], 'block')

        # التأكد من رفض التشغيل إذا سجّل الجهاز نتيجة block
        denied = self.client.post(
            reverse('api_v1_video_authorize', args=[self.protected_lecture.id]),
            {'code': 'SEC123', 'device_id': 'android-dev-frida'},
        )
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(denied.data.get('code'), 'INTEGRITY_REQUIRED')

    def test_unenrolled_student_cannot_access_progress_or_bookmarks_and_position_is_clamped(self):
        # الطالب غير المسجّل يُمنع من قراءة أو تعديل التقدّم والعلامات (403)
        self.client.force_authenticate(user=self.other_student_user)
        progress_url = reverse('api_v1_video_progress', args=[self.protected_lecture.id])
        bm_url = reverse('api_v1_video_bookmarks', args=[self.protected_lecture.id])

        self.assertEqual(self.client.get(progress_url).status_code, 403)
        self.assertEqual(
            self.client.post(progress_url, {'position_seconds': 50, 'duration_seconds': 100}).status_code,
            403,
        )
        self.assertEqual(self.client.get(bm_url).status_code, 403)
        self.assertEqual(
            self.client.post(bm_url, {'timestamp_seconds': 25, 'title': 'Hack'}).status_code,
            403,
        )

        # الطالب المسجّل يتم تقليم position_seconds لديه بحيث لا يتجاوز duration_seconds
        self.client.force_authenticate(user=self.student_user)
        clamped_resp = self.client.post(
            progress_url,
            {
                'position_seconds': 5000,
                'duration_seconds': 600,
                'watched_delta_seconds': 30,
            },
        )
        self.assertEqual(clamped_resp.status_code, 200)
        self.assertEqual(clamped_resp.data['position_seconds'], 600)
        self.assertEqual(clamped_resp.data['duration_seconds'], 600)
        self.assertTrue(clamped_resp.data['is_completed'])

    def test_android_assetlinks_well_known_endpoint(self):
        sample_fp = 'ab' * 32
        with override_settings():
            import os
            prev = os.environ.get('ANDROID_ASSETLINKS_SHA256')
            os.environ['ANDROID_ASSETLINKS_SHA256'] = sample_fp
            try:
                resp = self.client.get('/.well-known/assetlinks.json')
            finally:
                if prev is None:
                    os.environ.pop('ANDROID_ASSETLINKS_SHA256', None)
                else:
                    os.environ['ANDROID_ASSETLINKS_SHA256'] = prev

        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(len(body), 2)
        self.assertEqual(body[0]['relation'], ['delegate_permission/common.handle_all_urls'])
        self.assertEqual(body[0]['target']['package_name'], 'online.ta3alm.ta3alm_flutter')
        self.assertEqual(body[0]['target']['sha256_cert_fingerprints'], [':'.join(['AB'] * 32)])
        self.assertEqual(body[1]['target']['package_name'], 'online.ta3alm.ta3alm_flutter.debug')

    def test_privacy_and_terms_pages_accessible(self):
        for url in ('/privacy/', '/privacy-policy/', '/terms/', '/ar/privacy/', '/en/terms/'):
            resp = self.client.get(url)
            self.assertEqual(resp.status_code, 200, f'Expected 200 OK for {url}')

    def test_manual_signup_email_verification_via_otp_code(self):
        mail.outbox.clear()
        with patch('services.zoho_mail_service.ZohoMailService.is_connected', return_value=False):
            signup_resp = self.client.post(
                '/ar/manual-signup/',
                {
                    'full_name': 'طالب تجريبي',
                    'email': 'verify_otp@ta3alm.test',
                    'phone': '01012345001',
                    'password': 'StrongPassword123!',
                    'confirm_password': 'StrongPassword123!',
                    'role': 'student',
                },
            )
        self.assertRedirects(signup_resp, '/ar/verify-email/', fetch_redirect_response=False)

        user = User.objects.get(email='verify_otp@ta3alm.test')
        verification = EmailVerification.objects.get(user=user)
        self.assertFalse(verification.is_verified)
        self.assertEqual(len(verification.code), 6)
        self.assertTrue(len(mail.outbox) >= 1)
        self.assertIn(verification.code, mail.outbox[-1].body)

        # قبل التفعيل يجب أن يتم حجبه عن complete_profile وتوجيهه لصفحة التفعيل
        blocked_resp = self.client.get('/ar/complete-profile/')
        self.assertRedirects(blocked_resp, '/ar/verify-email/', fetch_redirect_response=False)

        # إدخال كود خطأ لا يفعّل الحساب
        wrong_resp = self.client.post('/ar/verify-email/', {'code': '000000'})
        self.assertEqual(wrong_resp.status_code, 200)
        verification.refresh_from_db()
        self.assertFalse(verification.is_verified)

        # إدخال الكود الصحيح يفعّل الحساب ويوجه لاستكمال الملف الشخصي
        ok_resp = self.client.post('/ar/verify-email/', {'code': verification.code})
        self.assertRedirects(ok_resp, '/ar/complete-profile/', fetch_redirect_response=False)
        verification.refresh_from_db()
        self.assertTrue(verification.is_verified)

    def test_manual_signup_email_verification_via_direct_link(self):
        mail.outbox.clear()
        with patch('services.zoho_mail_service.ZohoMailService.is_connected', return_value=False):
            self.client.post(
                '/ar/manual-signup/',
                {
                    'full_name': 'طالب رابط',
                    'email': 'verify_link@ta3alm.test',
                    'phone': '01012345002',
                    'password': 'StrongPassword123!',
                    'confirm_password': 'StrongPassword123!',
                    'role': 'student',
                },
            )
        user = User.objects.get(email='verify_link@ta3alm.test')
        verification = EmailVerification.objects.get(user=user)

        # تسجيل الخروج ثم فتح الرابط المباشر كما يحدث عند فتحه من الإيميل
        self.client.logout()
        link_resp = self.client.get(f'/verify-email/{verification.token}/')
        self.assertRedirects(link_resp, '/ar/complete-profile/', fetch_redirect_response=False)

        verification.refresh_from_db()
        self.assertTrue(verification.is_verified)
        self.assertEqual(self.client.session.get('_auth_user_id'), str(user.pk))


class PlatformFinancialAndContentFixesTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.media_dir = tempfile.mkdtemp()
        self.subject = Subject.objects.create(name='Mathematics')
        self.plan = SubscriptionPlan.objects.create(
            name='Basic Plan',
            price=100,
            student_limit=500,
            group_limit=10,
            assistant_limit=2,
            allow_online_packages=True,
            allow_question_images=False,
        )
        self.admin_user = User.objects.create_superuser(
            username='owner_admin',
            email='owner@ta3alm.test',
            password='Password123!',
            role='admin',
            first_name='Owner',
        )
        self.teacher_user = User.objects.create_user(
            username='teacher_fin',
            email='teacher_fin@ta3alm.test',
            password='Password123!',
            role='teacher',
            first_name='Hassan',
        )
        self.teacher = TeacherProfile.objects.create(
            user=self.teacher_user,
            subject=self.subject,
            current_plan=self.plan,
            subscription_end_date=timezone.now() + timedelta(days=30),
        )
        self.student_user = User.objects.create_user(
            username='student_fin',
            email='student_fin@ta3alm.test',
            password='Password123!',
            role='student',
            first_name='Youssef',
            phone='01022223333',
        )
        self.student = StudentProfile.objects.create(user=self.student_user, parent_phone='01099998888')
        self.group = Group.objects.create(teacher=self.teacher, name='Sec 3 Math', grade='3_sec')
        Enrollment.objects.create(student=self.student, group=self.group, is_active=True)

        self.lecture = Lecture.objects.create(
            group=self.group,
            title='Calculus Lesson 1',
            video_link='https://www.youtube.com/watch?v=dQw4w9WgXcQ',
            description='Intro',
            is_active=True,
        )
        self.package = CoursePackage.objects.create(
            teacher=self.teacher,
            title='Full Calculus Bundle',
            grade='3_sec',
            description='All lessons',
            price=200,
            view_limit=1,
            is_active=True,
        )
        self.package.lectures.add(self.lecture)
        for u in (self.teacher_user, self.student_user):
            EmailVerification.objects.create(
                user=u,
                code='123456',
                is_verified=True,
                expires_at=timezone.now() + timedelta(days=1),
            )

    def tearDown(self):
        cache.clear()
        shutil.rmtree(self.media_dir, ignore_errors=True)

    def test_single_watch_only_deducts_one_view_across_retries_and_reauthorizations(self):
        VideoCode.objects.create(lecture=self.lecture, code='ONCE11', max_views=1)
        self.client.force_authenticate(user=self.student_user)

        auth_url = reverse('api_v1_video_authorize', args=[self.lecture.id])
        watch_url = reverse('api_v1_student_watch_lecture', args=[self.lecture.id])

        first_auth = self.client.post(auth_url, {'code': 'ONCE11', 'device_id': 'dev-phone'})
        self.assertEqual(first_auth.status_code, 200)
        self.assertEqual(first_auth.data['code_info']['current_views'], 1)

        # محاولات إعادة التهيئة أو الدخول أثناء نفس نافذة المشاهدة لا تخصم مشاهدات إضافية ولا تغلق الفيديو
        second_auth = self.client.post(auth_url, {'device_id': 'dev-phone'})
        self.assertEqual(second_auth.status_code, 200)
        self.assertEqual(second_auth.data['code_info']['current_views'], 1)

        watch_get = self.client.get(watch_url)
        self.assertEqual(watch_get.status_code, 200)
        self.assertTrue(watch_get.data['is_unlocked'])
        self.assertEqual(watch_get.data['code_info']['current_views'], 1)

        # مسار الحزمة الأونلاين أيضاً يخصم مشاهدة واحدة فقط رغم تكرار الطلب
        pkg_watch_url = reverse('api_v1_student_watch_pkg_lecture', args=[self.package.id, self.lecture.id])
        PackageEnrollment.objects.create(student=self.student, package=self.package, is_paid=True)
        cache.clear()
        PlaybackSession.objects.all().delete()

        pkg_first = self.client.post(pkg_watch_url)
        self.assertEqual(pkg_first.status_code, 200)
        self.assertEqual(pkg_first.data['remaining_views'], 0)

        pkg_auth_retry = self.client.post(auth_url, {'package_id': self.package.id, 'device_id': 'dev-phone'})
        self.assertEqual(pkg_auth_retry.status_code, 200)
        tracker = VideoViewTracking.objects.get(student=self.student, package=self.package, lecture=self.lecture)
        self.assertEqual(tracker.views_count, 1)

    def test_commission_setting_manual_payment_credit_and_wallet_reconcile(self):
        # المالك يضبط نسبة العمولة إلى 15%
        self.client.force_authenticate(user=self.admin_user)
        admin_dash_url = reverse('api_v1_admin_dashboard')
        resp = self.client.post(admin_dash_url, {'platform_commission_percentage': 15})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(SiteSetting.load().platform_commission_percentage, 15)

        # إنشاء طلب دفع يدوي ثم قبوله يضيف 85% من قيمة الحزمة لمحفظة المعلم مرة واحدة فقط
        mp = ManualPayment.objects.create(
            user=self.student_user,
            amount=200,
            payment_type='student_package',
            target_id=self.package.id,
            phone_number='01022223333',
            receipt_image='receipts/dummy.png',
        )
        finance_url = reverse('api_v1_admin_finance')
        approve_resp = self.client.post(
            finance_url,
            {'item_type': 'manual_payment', 'id': mp.id, 'action': 'approve'},
        )
        self.assertEqual(approve_resp.status_code, 200)

        wallet = Wallet.objects.get(teacher=self.teacher)
        self.assertEqual(wallet.balance, Decimal('170.00'))
        self.assertEqual(wallet.total_earnings, Decimal('170.00'))

        # إعادة المزامنة لصفوف مدفوعة سابقاً بدون رصيد في المحفظة
        wallet.balance = Decimal('0.00')
        wallet.total_earnings = Decimal('0.00')
        wallet.save()

        self.client.force_authenticate(user=self.teacher_user)
        wallet_resp = self.client.get(reverse('api_v1_teacher_wallet'))
        self.assertEqual(wallet_resp.status_code, 200)
        self.assertEqual(Decimal(str(wallet_resp.data['wallet']['balance'])), Decimal('170.00'))
        self.assertEqual(wallet_resp.data['platform_commission_percentage'], 15)

    def test_pdf_file_upload_and_question_image_upload(self):
        with override_settings(
            MEDIA_ROOT=self.media_dir,
            STORAGES={
                'default': {'BACKEND': 'django.core.files.storage.FileSystemStorage'},
                'staticfiles': {'BACKEND': 'django.contrib.staticfiles.storage.StaticFilesStorage'},
            },
        ):
            self.client.force_authenticate(user=self.teacher_user)

            # 1. رفع ملف PDF مباشرة
            pdf_bytes = b'%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n'
            uploaded_pdf = SimpleUploadedFile('notes.pdf', pdf_bytes, content_type='application/pdf')
            pdf_url = reverse('api_v1_teacher_group_pdfs', args=[self.group.id])
            pdf_resp = self.client.post(pdf_url, {'title': 'ملخص التفاضل', 'file': uploaded_pdf}, format='multipart')
            self.assertEqual(pdf_resp.status_code, 201)
            self.assertIn('/media/pdfs/', pdf_resp.data['pdf']['file_url'])

            # 2. رفع صورة سؤال حتى لو كانت خطة الباقة الأساسية allow_question_images=False
            exam = Exam.objects.create(group=self.group, title='اختبار 1', duration_minutes=15)
            png_1x1 = (
                b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
                b'\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\rIDATx\x9cc```\xf8\x0f\x00'
                b'\x01\x01\x01\x00\x18\xdd\x8d\xb4\x00\x00\x00\x00IEND\xaeB`\x82'
            )
            uploaded_img = SimpleUploadedFile('diagram.png', png_1x1, content_type='image/png')
            exam_url = reverse('api_v1_teacher_exam_detail', args=[exam.id])
            q_resp = self.client.post(
                exam_url,
                {
                    'text': 'أوجد قيمة س من الرسم',
                    'option_a': '1',
                    'option_b': '2',
                    'option_c': '3',
                    'option_d': '4',
                    'correct_answer': 'B',
                    'marks': 2,
                    'image': uploaded_img,
                },
                format='multipart',
            )
            self.assertEqual(q_resp.status_code, 201)
            self.assertTrue(bool(q_resp.data['question']['image']))
            self.assertTrue(self.client.get(exam_url).data['allow_images'])

    def test_view_exhaustion_on_exit_non_sliding_window_and_record_view_false_blocked(self):
        from datetime import timedelta
        from django.utils import timezone
        from api_v1.models import PlaybackSession
        from api_v1.video_security import watch_window_cache_key
        from students.models import PackageEnrollment, VideoViewTracking
        from teachers.models import VideoCode

        vc = VideoCode.objects.create(lecture=self.lecture, code='LIMIT2VIEW', max_views=2)
        self.client.force_authenticate(user=self.student_user)

        auth_url = reverse('api_v1_video_authorize', args=[self.lecture.id])
        group_content_url = reverse('api_v1_student_group_content', args=[self.group.id])

        # 1) الدخول الأول حتى مع محاولة تمرير record_view=false يخصم المشاهدة الأولى
        first = self.client.post(
            auth_url,
            {'code': 'LIMIT2VIEW', 'device_id': 'dev-exhaust-1', 'record_view': False},
        )
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.data['code_info']['current_views'], 1)
        sess1_id = first.data['session_id']

        # التحقق أن view_window_expires_at ثابت ومضبوط على جلسة التشغيل ولا يتمدد بالطلبات المتكررة
        sess1 = PlaybackSession.objects.get(session_id=sess1_id)
        initial_exp = sess1.view_window_expires_at
        self.assertIsNotNone(initial_exp)

        # إعادة التشغيل داخل نفس الجلسة قبل الخروج لا تخصم ثانيةً ولا تمدد نافذة المشاهدة
        same_win = self.client.post(auth_url, {'device_id': 'dev-exhaust-1', 'record_view': False})
        self.assertEqual(same_win.status_code, 200)
        self.assertEqual(same_win.data['code_info']['current_views'], 1)
        sess1.refresh_from_db()
        self.assertLessEqual(abs((sess1.view_window_expires_at - initial_exp).total_seconds()), 1)

        # 2) الخروج الصريح من المشغل يُنهي الجلسة ويمسح النافذة، فيُخصم دخول ثانٍ وتصل للحد (2/2)
        revoke_resp = self.client.post(reverse('api_v1_video_session_revoke', args=[sess1_id]))
        self.assertEqual(revoke_resp.status_code, 200)
        sess1.refresh_from_db()
        self.assertEqual(sess1.status, 'ended')
        self.assertIsNone(cache.get(watch_window_cache_key(self.student_user.id, self.lecture.id)))

        second = self.client.post(auth_url, {'device_id': 'dev-exhaust-1'})
        self.assertEqual(second.status_code, 200)
        self.assertEqual(second.data['code_info']['current_views'], 2)

        # الخروج ثم الرجوع لقائمة المجموعة مع clear_watch=1 -> المحاولة الثالثة تُرفض لانتهاء المشاهدات
        self.client.get(group_content_url, {'clear_watch': '1'})
        third = self.client.post(auth_url, {'device_id': 'dev-exhaust-1'})
        self.assertEqual(third.status_code, 403)
        self.assertTrue(third.data.get('require_code'))

        # 3) اختبار انتهاء نافذة 20 دقيقة بدون تمديد على الحزمة المدفوعة
        self.package.view_limit = 1
        self.package.save(update_fields=['view_limit'])
        PackageEnrollment.objects.create(student=self.student, package=self.package, is_paid=True)
        pkg_first = self.client.post(
            auth_url,
            {'package_id': self.package.id, 'device_id': 'dev-exhaust-1'},
        )
        self.assertEqual(pkg_first.status_code, 200)
        tracker = VideoViewTracking.objects.get(
            student=self.student, package=self.package, lecture=self.lecture
        )
        self.assertEqual(tracker.views_count, 1)

        # محاكاة مرور 21 دقيقة (انتهاء نافذة الكاش + view_window_expires_at في قاعدة البيانات) يحرم فتح مشاهدة ثانية مع حد = 1
        cache.delete(watch_window_cache_key(self.student_user.id, self.lecture.id))
        PlaybackSession.objects.filter(
            user=self.student_user, lecture=self.lecture, course_package=self.package
        ).update(view_window_expires_at=timezone.now() - timedelta(minutes=1))
        pkg_second = self.client.post(
            auth_url,
            {'package_id': self.package.id, 'device_id': 'dev-exhaust-1'},
        )
        self.assertEqual(pkg_second.status_code, 403)

    def test_withdraw_request_three_state_approve_reject_refund_and_reconcile(self):
        from core.models import ManualPayment, Notification, SiteSetting
        from dashboard_admin.models import AuditLog
        from teachers.models import Wallet, WithdrawRequest
        from teachers.views import reconcile_teacher_wallet

        site_cfg = SiteSetting.load()
        site_cfg.platform_commission_percentage = 0
        site_cfg.save(update_fields=['platform_commission_percentage'])

        self.package.price = Decimal('500.00')
        self.package.save(update_fields=['price'])

        finance_url = reverse('api_v1_admin_finance')
        self.client.force_authenticate(user=self.admin_user)
        mp = ManualPayment.objects.create(
            user=self.student_user,
            amount=500,
            payment_type='student_package',
            target_id=self.package.id,
            phone_number='01022223333',
            receipt_image='receipts/withdraw_test.png',
        )
        self.assertEqual(
            self.client.post(
                finance_url,
                {'item_type': 'manual_payment', 'id': mp.id, 'action': 'approve'},
            ).status_code,
            200,
        )
        wallet = Wallet.objects.get(teacher=self.teacher)
        self.assertEqual(wallet.balance, Decimal('500.00'))

        # 1) إنشاء طلب سحب عبر API المعلم يبدأ كـ pending و is_paid=False
        self.client.force_authenticate(user=self.teacher_user)
        wr_create = self.client.post(
            reverse('api_v1_teacher_wallet'),
            {'amount': '150.00', 'method': 'vodafone', 'details': '01099887766 فودافون كاش'},
        )
        self.assertEqual(wr_create.status_code, 201)
        wr1 = WithdrawRequest.objects.get(id=wr_create.data['withdrawal']['id'])
        self.assertEqual(wr1.status, 'pending')
        self.assertFalse(wr1.is_paid)
        self.assertEqual(wr_create.data['withdrawal']['status'], 'pending')

        wallet.refresh_from_db()
        self.assertEqual(wallet.balance, Decimal('350.00'))

        # 2) لوحة الأدمن ترى status='pending' ورفض الطلب يُعيد الرصيد ويُرسل إشعاراً للمعلم
        self.client.force_authenticate(user=self.admin_user)
        fin_list = self.client.get(finance_url)
        self.assertEqual(fin_list.status_code, 200)
        pending_row = next(w for w in fin_list.data['withdraw_requests'] if w['id'] == wr1.id)
        self.assertEqual(pending_row['status'], 'pending')
        self.assertFalse(pending_row['is_paid'])

        rej_resp = self.client.post(
            finance_url,
            {
                'item_type': 'withdrawal',
                'id': wr1.id,
                'action': 'reject',
                'rejection_reason': 'بيانات المحفظة غير صحيحة',
            },
        )
        self.assertEqual(rej_resp.status_code, 200)
        wr1.refresh_from_db()
        wallet.refresh_from_db()
        self.assertEqual(wr1.status, 'rejected')
        self.assertFalse(wr1.is_paid)
        self.assertIsNotNone(wr1.reviewed_at)
        self.assertEqual(wr1.rejection_reason, 'بيانات المحفظة غير صحيحة')
        self.assertEqual(wallet.balance, Decimal('500.00'))
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.teacher_user,
                title__contains='رفض',
            ).exists()
        )
        self.assertTrue(
            AuditLog.objects.filter(action=AuditLog.ACTION_REJECT_WITHDRAW).exists()
        )

        # منع مراجعة نفس الطلب مرة أخرى
        dup_resp = self.client.post(
            finance_url,
            {'item_type': 'withdrawal', 'id': wr1.id, 'action': 'approve'},
        )
        self.assertEqual(dup_resp.status_code, 400)

        # 3) الموافقة على طلب ثانٍ تعتمده كـ paid، وتسوية المحفظة تستبعد الطلب المرفوض وتُبقي 400.00
        self.client.force_authenticate(user=self.teacher_user)
        wr2_create = self.client.post(
            reverse('api_v1_teacher_wallet'),
            {'amount': '100.00', 'method': 'instapay', 'details': '01122334455 إنستاباي'},
        )
        self.assertEqual(wr2_create.status_code, 201)
        wr2 = WithdrawRequest.objects.get(id=wr2_create.data['withdrawal']['id'])

        self.client.force_authenticate(user=self.admin_user)
        app_resp = self.client.post(
            finance_url,
            {'item_type': 'withdrawal', 'id': wr2.id, 'action': 'approve'},
        )
        self.assertEqual(app_resp.status_code, 200)
        wr2.refresh_from_db()
        self.assertEqual(wr2.status, 'paid')
        self.assertTrue(wr2.is_paid)
        self.assertIsNotNone(wr2.reviewed_at)

        wallet.refresh_from_db()
        self.assertEqual(wallet.balance, Decimal('400.00'))

        # تصفير المحفظة وإعادة التسوية يجب أن يسترجع 400.00 (500 مكتسبة - 100 مدفوعة فقط دون خصم 150 المرفوضة)
        wallet.balance = Decimal('0.00')
        wallet.total_earnings = Decimal('0.00')
        wallet.save()
        reconcile_teacher_wallet(self.teacher)
        wallet.refresh_from_db()
        self.assertEqual(wallet.total_earnings, Decimal('500.00'))
        self.assertEqual(wallet.balance, Decimal('400.00'))

