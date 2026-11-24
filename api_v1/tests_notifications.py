"""
api_v1/tests_notifications.py
اختبارات شاملة لنظام الإشعارات الموحد عبر جميع الأدوار ونقاط سحب الخلفية للأندرويد.
"""
from datetime import timedelta
from decimal import Decimal
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase

from accounts.models import EmailVerification, OneTimeLoginLink, StudentProfile
from api_v1.device_security_service import record_security_event
from api_v1.models import DeviceBlock, RegisteredDevice
from assistants.models import AssistantJob, AssistantProfile
from core.models import ManualPayment, Notification, SiteSetting, Subject
from core.notifications_service import (
    generate_notif_pull_token,
    maybe_notify_teacher_subscription_expiry,
    verify_notif_pull_token,
)
from dashboard_admin.models import AdminProfile, AdminRole
from exams.models import Exam, ExamResult, Question
from students.models import (
    Enrollment,
    PackageEnrollment,
    PackageExamResult,
    PerformanceLog,
    VideoViewTracking,
)
from teachers.models import (
    CoursePackage,
    Group,
    Lecture,
    PaymentTransaction,
    PDFFile,
    SubscriptionPlan,
    TeacherProfile,
    VideoCode,
    Wallet,
    WithdrawRequest,
)

User = get_user_model()


class PlatformNotificationCoverageTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.subject = Subject.objects.create(name='الرياضيات')
        self.plan = SubscriptionPlan.objects.create(
            name='الباقة الاحترافية',
            price=400,
            student_limit=100,
            group_limit=10,
            assistant_limit=3,
            allow_online_packages=True,
        )

        self.owner_user = User.objects.create_superuser(
            username='owner_n',
            email='owner_n@example.com',
            password='Password123!',
            role='admin',
        )
        self.finance_user = User.objects.create_user(
            username='finance_n',
            email='finance_n@example.com',
            password='Password123!',
            role='admin',
            first_name='أحمد',
            last_name='المالي',
        )
        AdminProfile.objects.create(
            user=self.finance_user,
            admin_role=AdminRole.FINANCE,
            is_active_admin=True,
            appointed_by=self.owner_user,
        )

        self.teacher_user = User.objects.create_user(
            username='teacher_n',
            email='teacher_n@example.com',
            password='Password123!',
            role='teacher',
            first_name='محمود',
            last_name='المعلم',
            phone='01011111111',
        )
        self.teacher = TeacherProfile.objects.create(
            user=self.teacher_user,
            subject=self.subject,
            current_plan=self.plan,
            subscription_end_date=timezone.now() + timedelta(days=2),
            is_approved=True,
        )
        self.wallet = Wallet.objects.create(
            teacher=self.teacher,
            balance=Decimal('1000.00'),
            total_earnings=Decimal('1000.00'),
        )

        self.assistant_user = User.objects.create_user(
            username='assistant_n',
            email='assistant_n@example.com',
            password='Password123!',
            role='assistant',
            first_name='سارة',
            last_name='المساعدة',
            phone='01022222222',
        )
        self.assistant = AssistantProfile.objects.create(
            user=self.assistant_user,
            phone='01022222222',
        )

        self.student_user = User.objects.create_user(
            username='student_n',
            email='student_n@example.com',
            password='Password123!',
            role='student',
            first_name='يوسف',
            last_name='الطالب',
            phone='01033333333',
        )
        self.student = StudentProfile.objects.create(
            user=self.student_user,
            parent_phone='01044444444',
        )

        self.group = Group.objects.create(
            teacher=self.teacher,
            name='مجموعة التفوق',
            grade='3sec',
        )

    def test_academic_and_assistant_lifecycle_notifications(self):
        # 1. طلب مساعد وانضمامه وصلاحياته
        job = AssistantJob.objects.create(
            assistant=self.assistant,
            teacher=self.teacher,
            is_active=False,
        )
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.teacher_user,
                title__contains='مساعد',
            ).exists()
        )
        job.is_active = True
        job.can_manage_students = True
        job.can_manage_exams = True
        job.save()
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.assistant_user,
                title__contains='قبولك',
            ).exists()
        )

        # 2. طلب انضمام طالب وقبوله (يشمل إشعار المعلم + المساعد المختص دون تكرار)
        Notification.objects.all().delete()
        enroll = Enrollment.objects.create(
            student=self.student,
            group=self.group,
            is_active=False,
        )
        self.assertEqual(
            Notification.objects.filter(
                recipient=self.teacher_user,
                title='طلب انضمام جديد',
            ).count(),
            1,
        )
        self.assertEqual(
            Notification.objects.filter(
                recipient=self.assistant_user,
                title='طلب انضمام جديد',
            ).count(),
            1,
        )

        enroll.is_active = True
        enroll.save(update_fields=['is_active'])
        self.assertEqual(
            Notification.objects.filter(
                recipient=self.student_user,
                title='تم قبول طلبك!',
            ).count(),
            1,
        )

        # 3. محاضرة جديدة وملف واختبار ونتيجة وسجل أداء
        lecture = Lecture.objects.create(
            group=self.group,
            title='التفاضل المتقدم',
            video_link='https://www.youtube.com/watch?v=dQw4w9WgXcQ',
            is_active=True,
        )
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.student_user,
                link=f'/student/lecture/{lecture.id}/watch/',
            ).exists()
        )

        PDFFile.objects.create(
            group=self.group,
            title='ملخص قوانين التفاضل',
            link='https://example.com/file.pdf',
        )
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.student_user,
                title__contains='ملف',
            ).exists()
        )

        exam = Exam.objects.create(
            group=self.group,
            title='اختبار الوحدة الأولى',
            duration_minutes=20,
            is_active=True,
        )
        Question.objects.create(
            exam=exam,
            text='ما ناتج 2+2؟',
            option_a='3',
            option_b='4',
            option_c='5',
            option_d='6',
            correct_answer='B',
            marks=5,
        )
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.student_user,
                link=f'/student/exam/{exam.id}/take/',
            ).exists()
        )

        ExamResult.objects.create(student=self.student, exam=exam, score=5)
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.student_user,
                title='نتيجة الاختبار',
                message__contains='5/5',
            ).exists()
        )
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.assistant_user,
                title='تسليم اختبار جديد',
            ).exists()
        )

        PerformanceLog.objects.create(
            student=self.student,
            group=self.group,
            session_number=3,
            is_present=True,
            homework_score=9,
            homework_max=10,
        )
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.student_user,
                title__contains='الحصة 3',
            ).exists()
        )

        # 4. كود الفيديو (تفعيل ثم استنفاد المشاهدات)
        vc = VideoCode.objects.create(
            lecture=lecture,
            code='TEST99',
            max_views=1,
            current_views=0,
            is_used=False,
        )
        vc.is_used = True
        vc.used_by = self.student
        vc.used_at = timezone.now()
        vc.save()
        vc.current_views = 1
        vc.save()
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.student_user,
                title='تم تفعيل كود المحاضرة',
            ).exists()
        )
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.student_user,
                title='انتهاء مشاهدات الكود',
            ).exists()
        )

        # 5. حذف الاشتراك (إزالة من المجموعة)
        enroll.delete()
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.student_user,
                title='تحديث عضوية المجموعة',
            ).exists()
        )

    def test_packages_and_finance_notifications(self):
        pkg = CoursePackage.objects.create(
            teacher=self.teacher,
            title='حزمة المراجعة النهائية',
            grade='3sec',
            description='مراجعة شاملة',
            price=250,
            is_active=True,
        )
        lec = Lecture.objects.create(
            title='حصة المراجعة 1',
            video_link='https://www.youtube.com/watch?v=dQw4w9WgXcQ',
            is_active=True,
        )
        exam = Exam.objects.create(title='امتحان المراجعة', is_active=True)

        pkg_enroll = PackageEnrollment.objects.create(
            student=self.student,
            package=pkg,
            is_paid=True,
        )
        self.assertIsNotNone(pkg_enroll.id)
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.student_user,
                title='تم تفعيل حزمتك التعليمية',
            ).exists()
        )
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.teacher_user,
                title__contains='مبيعة',
            ).exists()
        )

        # M2M add triggers notification to paid package students
        pkg.lectures.add(lec)
        pkg.exams.add(exam)
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.student_user,
                title__contains=pkg.title,
                message__contains='محاضرة',
            ).exists()
        )
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.student_user,
                title__contains=pkg.title,
                message__contains='اختبار',
            ).exists()
        )

        PackageExamResult.objects.create(
            student=self.student,
            package=pkg,
            exam=exam,
            score=10,
        )
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.student_user,
                title='نتيجة اختبار الحزمة',
            ).exists()
        )

        vt = VideoViewTracking.objects.create(
            student=self.student,
            package=pkg,
            lecture=lec,
            views_count=1,
            is_completed=True,
            points_awarded=10,
        )
        self.assertIsNotNone(vt.id)
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.student_user,
                title='إتمام مشاهدة محاضرة بالحزمة',
            ).exists()
        )

        # الدفع اليدوي + المالية
        payment = ManualPayment.objects.create(
            user=self.teacher_user,
            amount=400,
            payment_type='teacher_subscription',
            target_id=self.plan.id,
            phone_number='01099999999',
            receipt_image='receipts/test_receipt.jpg',
            status='pending',
        )
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.finance_user,
                title__contains=f'#{payment.id}',
            ).exists()
        )
        payment.status = 'approved'
        payment.save()
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.teacher_user,
                title='تم قبول وتفعيل طلب الدفع!',
            ).exists()
        )

        # طلب السحب وتأكيد الدفع + تجديد Paymob/Admin + قرب الانتهاء
        withdraw = WithdrawRequest.objects.create(
            wallet=self.wallet,
            amount=Decimal('300.00'),
            method='vodafone',
            details='01055555555',
            is_paid=False,
        )
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.finance_user,
                title__contains=f'#{withdraw.id}',
            ).exists()
        )
        withdraw.is_paid = True
        withdraw.save()
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.teacher_user,
                title='تم تحويل أرباحك!',
            ).exists()
        )

        PaymentTransaction.objects.create(
            teacher=self.teacher,
            amount=400,
            transaction_id='TX-1001',
        )
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.teacher_user,
                title='تم تجديد اشتراكك بنجاح',
            ).exists()
        )

        self.teacher.subscription_end_date = timezone.now() + timedelta(days=2)
        self.teacher.save(update_fields=['subscription_end_date'])
        self.assertTrue(maybe_notify_teacher_subscription_expiry(self.teacher))
        self.assertFalse(maybe_notify_teacher_subscription_expiry(self.teacher))  # لا تكرار خلال 24 ساعة

    def test_security_account_events_and_background_pull_endpoint(self):
        # 1. تفعيل OTP ترحيبي + تغيير كلمة المرور + رابط دخول مؤقت + الحظر
        verif = EmailVerification.objects.create(
            user=self.student_user,
            code='123456',
            is_verified=False,
            expires_at=timezone.now() + timedelta(minutes=15),
        )
        verif.mark_verified()
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.student_user,
                title__contains='مرحباً بك',
            ).exists()
        )

        OneTimeLoginLink.objects.create(user=self.student_user)
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.student_user,
                title__contains='رابط دخول مؤقت',
            ).exists()
        )

        # 2. أجهزة وأحداث أمنية
        dev = RegisteredDevice.objects.create(
            user=self.student_user,
            installation_id='inst-test-notif-001',
            device_name='Pixel 8',
            os_name='Android',
        )
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.student_user,
                title='تسجيل دخول من جهاز جديد',
            ).exists()
        )

        blk = DeviceBlock.objects.create(
            device=dev,
            user=self.student_user,
            installation_id=dev.installation_id,
            reason='محاولة فحص أمني',
            is_active=True,
        )
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.student_user,
                title='تم حظر أحد أجهزة حسابك أمنياً',
            ).exists()
        )
        blk.is_active = False
        blk.save()
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.student_user,
                title='تم فك الحظر عن جهازك',
            ).exists()
        )

        record_security_event(
            event_type='screen_recording_detected',
            severity='high',
            risk_score=70,
            user=self.student_user,
            device=dev,
            notify_user=True,
            notify_title='تنبيه حماية المحتوى',
            notify_message='تم رصد تسجيل شاشة.',
        )
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.owner_user,
                title__contains='screen_recording_detected',
            ).exists()
        )

        # 3. تغيير إعدادات الموقع (الصيانة + نشر تحديث أندرويد)
        site_cfg = SiteSetting.load()
        site_cfg.is_maintenance_mode = True
        site_cfg.android_latest_version_code = site_cfg.android_latest_version_code + 1
        site_cfg.android_latest_version_name = '1.2.0'
        site_cfg.save()
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.owner_user,
                title='تحديث حالة المنصة',
            ).exists()
        )
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.owner_user,
                title__contains='v1.2.0',
            ).exists()
        )
        site_cfg.is_maintenance_mode = False
        site_cfg.save(update_fields=['is_maintenance_mode'])

        # 4. نقطة الإشعارات العادية + نقطة سحب الخلفية للأندرويد
        self.client.force_authenticate(user=self.student_user)
        list_res = self.client.get('/api/v1/notifications/')
        self.assertEqual(list_res.status_code, status.HTTP_200_OK)
        sync_token = list_res.data.get('notif_sync_token')
        self.assertTrue(sync_token)
        first_latest_id = list_res.data['latest_id']

        # إنشاء إشعار جديد بعد latest_id والتحقق من since_id عبر endpoint الخلفية
        new_notif = Notification.objects.create(
            recipient=self.student_user,
            title='اختبار الخلفية',
            message='وصول فوري للخلفية',
            link='/student/group/1/',
        )
        self.client.force_authenticate(user=None)

        bg_res = self.client.get(
            f'/api/v1/notifications/background-pull/?since_id={first_latest_id}',
            HTTP_X_TA3ALM_NOTIF_TOKEN=sync_token,
        )
        self.assertEqual(bg_res.status_code, status.HTTP_200_OK)
        returned_ids = [n['id'] for n in bg_res.data['notifications']]
        self.assertEqual(returned_ids, [new_notif.id])

        # التحقق من رفض التوكن بعد تغيير كلمة المرور أو حظر المستخدم
        self.student_user.set_password('NewStrongPass999!')
        self.student_user.save()
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.student_user,
                title='تم تحديث كلمة المرور',
            ).exists()
        )
        self.assertIsNone(verify_notif_pull_token(sync_token))
        invalid_res = self.client.get(
            '/api/v1/notifications/background-pull/',
            HTTP_X_TA3ALM_NOTIF_TOKEN=sync_token,
        )
        self.assertEqual(invalid_res.status_code, status.HTTP_401_UNAUTHORIZED)

        new_token = generate_notif_pull_token(self.student_user)
        self.student_user.is_banned = True
        self.student_user.save()
        banned_res = self.client.get(
            '/api/v1/notifications/background-pull/',
            HTTP_X_TA3ALM_NOTIF_TOKEN=new_token,
        )
        self.assertEqual(banned_res.status_code, status.HTTP_401_UNAUTHORIZED)


class FCMNotificationPushTests(APITestCase):
    def setUp(self):
        self.user_a = User.objects.create_user(
            username='fcm_user_a',
            email='fcm_a@example.com',
            password='Password123!',
            role='student',
        )
        EmailVerification.objects.create(
            user=self.user_a,
            code='123456',
            is_verified=True,
            expires_at=timezone.now() + timedelta(days=1),
        )
        self.user_b = User.objects.create_user(
            username='fcm_user_b',
            email='fcm_b@example.com',
            password='Password123!',
            role='teacher',
        )
        EmailVerification.objects.create(
            user=self.user_b,
            code='654321',
            is_verified=True,
            expires_at=timezone.now() + timedelta(days=1),
        )

    def test_fcm_token_register_transfer_and_logout_deactivate(self):
        from core.models import FCMDeviceToken

        self.client.force_authenticate(user=self.user_a)
        res1 = self.client.post(
            '/api/v1/notifications/fcm-token/',
            {
                'token': 'fcm_device_token_alpha_1234567890',
                'installation_id': 'inst_phone_1',
                'platform': 'android',
            },
            format='json',
        )
        self.assertEqual(res1.status_code, status.HTTP_200_OK)
        self.assertFalse(res1.data['fcm_configured'])

        # تسجيل رمز أحدث لنفس التثبيت يُعطل الرمز الأقدم لنفس المستخدم
        res2 = self.client.post(
            '/api/v1/notifications/fcm-token/',
            {
                'token': 'fcm_device_token_beta_1234567890',
                'installation_id': 'inst_phone_1',
                'platform': 'android',
            },
            format='json',
        )
        self.assertEqual(res2.status_code, status.HTTP_200_OK)
        self.assertFalse(FCMDeviceToken.objects.get(token='fcm_device_token_alpha_1234567890').is_active)
        self.assertTrue(FCMDeviceToken.objects.get(token='fcm_device_token_beta_1234567890').is_active)

        # إضافة رمز لجهاز ثانٍ للمستخدم نفسه
        self.client.post(
            '/api/v1/notifications/fcm-token/',
            {
                'token': 'fcm_device_token_tablet_1234567890',
                'installation_id': 'inst_tablet_2',
                'platform': 'android',
            },
            format='json',
        )

        # تسجيل خروج الهاتف فقط يُعطل رمزه ويبقي رمز التابلت نشطاً
        del_res = self.client.delete(
            '/api/v1/notifications/fcm-token/',
            {'installation_id': 'inst_phone_1'},
            format='json',
        )
        self.assertEqual(del_res.status_code, status.HTTP_200_OK)
        self.assertEqual(del_res.data['deactivated'], 1)
        self.assertFalse(FCMDeviceToken.objects.get(token='fcm_device_token_beta_1234567890').is_active)
        self.assertTrue(FCMDeviceToken.objects.get(token='fcm_device_token_tablet_1234567890').is_active)

        # إذا سجل مستخدم آخر على نفس الجهاز بنفس رمز FCM تنتقل الملكية إليه
        self.client.force_authenticate(user=self.user_b)
        res_transfer = self.client.post(
            '/api/v1/notifications/fcm-token/',
            {
                'token': 'fcm_device_token_tablet_1234567890',
                'installation_id': 'inst_tablet_2',
                'platform': 'android',
            },
            format='json',
        )
        self.assertEqual(res_transfer.status_code, status.HTTP_200_OK)
        transferred = FCMDeviceToken.objects.get(token='fcm_device_token_tablet_1234567890')
        self.assertEqual(transferred.user_id, self.user_b.id)
        self.assertTrue(transferred.is_active)

    def test_fcm_push_payload_channel_routing_and_unregistered_cleanup(self):
        import json
        from unittest.mock import MagicMock, patch
        from django.test import override_settings
        from core.fcm_service import resolve_android_channel, send_fcm_push_for_notifications
        from core.models import FCMDeviceToken

        self.assertEqual(resolve_android_channel('حظر جهاز جديد', '/devices/'), 'ta3alm_security')
        self.assertEqual(resolve_android_channel('تم تنفيذ طلب السحب', '/teacher/wallet/'), 'ta3alm_finance')
        self.assertEqual(resolve_android_channel('محاضرة جديدة', '/student/group/5/'), 'ta3alm_academic')

        FCMDeviceToken.objects.create(
            user=self.user_a,
            token='fcm_valid_token_aaaaaaaaaaaaaaaaaa',
            installation_id='inst_ok',
            is_active=True,
        )
        FCMDeviceToken.objects.create(
            user=self.user_a,
            token='fcm_dead_token_bbbbbbbbbbbbbbbbbbb',
            installation_id='inst_dead',
            is_active=True,
        )

        notif = Notification.objects.create(
            recipient=self.user_a,
            title='اعتماد طلب سحب أرباح',
            message='تم تحويل 500 جنيه إلى محفظتك.',
            link='/teacher/wallet/',
        )

        # بدون إعدادات Firebase يظل الإرسال معطلاً دون أخطاء
        with override_settings(FIREBASE_SERVICE_ACCOUNT_JSON='', FIREBASE_SERVICE_ACCOUNT_FILE=''):
            no_cfg = send_fcm_push_for_notifications([notif])
            self.assertFalse(no_cfg['configured'])
            self.assertEqual(no_cfg['sent'], 0)

        fake_sa = json.dumps({
            'type': 'service_account',
            'project_id': 'ta3alm-edu-test',
            'client_email': 'firebase-admin@ta3alm-edu-test.iam.gserviceaccount.com',
            'private_key': 'FAKE_TEST_KEY',
        })

        def _fake_post(url, json=None, timeout=None):
            resp = MagicMock()
            token_sent = json['message']['token']
            if 'dead' in token_sent:
                resp.status_code = 404
                resp.json.return_value = {
                    'error': {
                        'status': 'NOT_FOUND',
                        'details': [{'errorCode': 'UNREGISTERED'}],
                    }
                }
            else:
                resp.status_code = 200
                resp.json.return_value = {'name': 'projects/ta3alm-edu-test/messages/1'}
            return resp

        fake_session = MagicMock()
        fake_session.post.side_effect = _fake_post

        with override_settings(FIREBASE_SERVICE_ACCOUNT_JSON=fake_sa), \
             patch('google.oauth2.service_account.Credentials.from_service_account_info', return_value=MagicMock()), \
             patch('google.auth.transport.requests.AuthorizedSession', return_value=fake_session):
            res = send_fcm_push_for_notifications([notif])

        self.assertTrue(res['configured'])
        self.assertEqual(res['sent'], 1)
        self.assertEqual(res['failed'], 1)
        self.assertEqual(res['deactivated'], 1)

        # التحقق من بناء حمولة القناة الصوتية الصحيحة ومن تعطيل التوكن المنتهي
        first_call_payload = fake_session.post.call_args_list[0].kwargs['json']
        self.assertEqual(first_call_payload['message']['android']['notification']['channel_id'], 'ta3alm_finance')
        self.assertEqual(first_call_payload['message']['android']['notification']['sound'], 'ta3alm_chime')
        self.assertEqual(first_call_payload['message']['data']['link'], '/teacher/wallet/')
        self.assertEqual(first_call_payload['message']['data']['notification_id'], str(notif.id))

        self.assertTrue(FCMDeviceToken.objects.get(token='fcm_valid_token_aaaaaaaaaaaaaaaaaa').is_active)
        self.assertFalse(FCMDeviceToken.objects.get(token='fcm_dead_token_bbbbbbbbbbbbbbbbbbb').is_active)

    def test_single_and_bulk_notifications_hook_fcm_scheduler(self):
        from unittest.mock import patch
        from core.notifications_service import notify_user, notify_users_bulk

        with patch('core.fcm_service.schedule_fcm_push_for_notifications') as sched_mock:
            n = notify_user(self.user_a, 'تنبيه فردي', 'محتوى التنبيه', link='/notifications/all/')
            self.assertIsNotNone(n)
            self.assertEqual(sched_mock.call_count, 1)

            count = notify_users_bulk(
                [self.user_a, self.user_b],
                'تنبيه جماعي',
                'رسالة جماعية',
                link='/student/',
            )
            self.assertEqual(count, 2)
            self.assertEqual(sched_mock.call_count, 2)

    def test_android_browser_popup_uses_admin_github_apk_url(self):
        cfg = SiteSetting.load()
        github_url = 'https://github.com/ta3alm-edu/ta3alm/releases/download/v1.3.0/app-release.apk'
        cfg.android_apk_url = github_url
        cfg.android_latest_version_name = '1.3.0'
        cfg.android_latest_version_code = 5
        cfg.save()

        # متاح للزوار والمسجلين مع ظهور المودال والرابط المباشر من الإدارة دون حفظ الإغلاق
        guest_res = self.client.get(
            '/ar/',
            follow=True,
            HTTP_HOST='www.ta3alm.online',
            HTTP_USER_AGENT='Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 Chrome/125.0 Mobile Safari/537.36',
        )
        self.assertEqual(guest_res.status_code, status.HTTP_200_OK)
        body = guest_res.content.decode('utf-8')
        self.assertIn('id="ta3almAndroidDownloadModal"', body)
        self.assertIn(f'href="{github_url}"', body)
        self.assertIn('v1.3.0', body)
        self.assertNotIn('ta3alm_app_banner_dismissed', body)


class AdminCustomNotificationTests(APITestCase):
    def setUp(self):
        self.subject_math = Subject.objects.create(name='الرياضيات')
        self.subject_phys = Subject.objects.create(name='الفيزياء')

        self.plan_basic = SubscriptionPlan.objects.create(
            name='الباقة الأساسية',
            price=150,
            student_limit=50,
            group_limit=3,
            assistant_limit=1,
        )
        self.plan_pro = SubscriptionPlan.objects.create(
            name='الباقة الذهبية',
            price=450,
            student_limit=500,
            group_limit=20,
            assistant_limit=5,
            allow_online_packages=True,
        )

        self.owner_user = User.objects.create_superuser(
            username='custom_owner',
            email='custom_owner@example.com',
            password='Password123!',
            role='admin',
            first_name='مالك',
            last_name='المنصة',
        )
        self.mod_user = User.objects.create_user(
            username='custom_mod',
            email='custom_mod@example.com',
            password='Password123!',
            role='admin',
            first_name='مشرف',
            last_name='الإدارة',
        )
        AdminProfile.objects.create(
            user=self.mod_user,
            admin_role=AdminRole.MODERATOR,
            is_active_admin=True,
            appointed_by=self.owner_user,
        )
        self.support_user = User.objects.create_user(
            username='custom_support',
            email='custom_support@example.com',
            password='Password123!',
            role='admin',
        )
        AdminProfile.objects.create(
            user=self.support_user,
            admin_role=AdminRole.SUPPORT,
            is_active_admin=True,
            appointed_by=self.owner_user,
        )

        self.teacher_active_user = User.objects.create_user(
            username='custom_t_active',
            email='t_active@example.com',
            password='Password123!',
            role='teacher',
            first_name='أحمد',
            last_name='ساري',
            phone='01010000001',
        )
        EmailVerification.objects.create(
            user=self.teacher_active_user,
            code='111111',
            is_verified=True,
            expires_at=timezone.now() + timedelta(days=1),
        )
        self.teacher_active = TeacherProfile.objects.create(
            user=self.teacher_active_user,
            subject=self.subject_math,
            current_plan=self.plan_pro,
            subscription_end_date=timezone.now() + timedelta(days=20),
            is_approved=True,
        )

        self.teacher_expired_user = User.objects.create_user(
            username='custom_t_exp',
            email='t_exp@example.com',
            password='Password123!',
            role='teacher',
            first_name='خالد',
            last_name='منتهي',
            phone='01010000002',
        )
        self.teacher_expired = TeacherProfile.objects.create(
            user=self.teacher_expired_user,
            subject=self.subject_phys,
            current_plan=self.plan_basic,
            subscription_end_date=timezone.now() - timedelta(days=3),
            is_approved=True,
        )

        self.student_3sec_user = User.objects.create_user(
            username='custom_st_3sec',
            email='st_3sec@example.com',
            password='Password123!',
            role='student',
            first_name='منة',
            last_name='الله',
            custom_id='ST3001',
            phone='01020000001',
        )
        EmailVerification.objects.create(
            user=self.student_3sec_user,
            code='222222',
            is_verified=True,
            expires_at=timezone.now() + timedelta(days=1),
        )
        self.student_3sec = StudentProfile.objects.create(
            user=self.student_3sec_user,
            parent_phone='01099999991',
        )

        self.student_1prep_user = User.objects.create_user(
            username='custom_st_1prep',
            email='st_1prep@example.com',
            password='Password123!',
            role='student',
            first_name='عمر',
            last_name='طالب',
            custom_id='ST1001',
        )
        self.student_1prep = StudentProfile.objects.create(
            user=self.student_1prep_user,
            parent_phone='01099999992',
        )

        self.banned_student_user = User.objects.create_user(
            username='custom_st_banned',
            email='st_banned@example.com',
            password='Password123!',
            role='student',
            first_name='محظور',
            last_name='حساب',
            is_banned=True,
        )
        StudentProfile.objects.create(
            user=self.banned_student_user,
            parent_phone='01099999993',
        )

        self.assistant_user = User.objects.create_user(
            username='custom_ast',
            email='ast_c@example.com',
            password='Password123!',
            role='assistant',
            first_name='ندى',
            last_name='المساعدة',
        )
        AssistantProfile.objects.create(user=self.assistant_user, phone='01030000001')

        self.group_3sec = Group.objects.create(
            teacher=self.teacher_active,
            name='مجموعة ٣ ثانوي أ',
            grade='3_sec',
        )
        Enrollment.objects.create(student=self.student_3sec, group=self.group_3sec, is_active=True)

        self.pkg_1prep = CoursePackage.objects.create(
            teacher=self.teacher_expired,
            title='باقة ١ إعدادي',
            grade='1_prep',
            description='وصف',
            price=200,
        )
        PackageEnrollment.objects.create(student=self.student_1prep, package=self.pkg_1prep, is_paid=True)

        from core.models import FCMDeviceToken

        FCMDeviceToken.objects.create(
            user=self.student_3sec_user,
            token='fcm_custom_notif_student_token_123456',
            platform='android',
            is_active=True,
        )
        FCMDeviceToken.objects.create(
            user=self.teacher_active_user,
            token='fcm_custom_notif_teacher_token_123456',
            platform='android',
            is_active=True,
        )

    def test_permissions_for_admin_custom_notifications(self):
        from django.urls import reverse

        # طالب ومشرف دعم ممنوعان
        self.client.force_authenticate(user=self.student_3sec_user)
        res_student = self.client.get('/api/v1/admin/notifications/')
        self.assertEqual(res_student.status_code, status.HTTP_403_FORBIDDEN)

        self.client.force_authenticate(user=self.support_user)
        res_support = self.client.get('/api/v1/admin/notifications/')
        self.assertEqual(res_support.status_code, status.HTTP_403_FORBIDDEN)

        # المشرف Moderator مسموح له
        self.client.force_authenticate(user=self.mod_user)
        res_mod = self.client.get('/api/v1/admin/notifications/')
        self.assertEqual(res_mod.status_code, status.HTTP_200_OK)
        self.assertIn('segments', res_mod.data)
        self.assertIn('grades', res_mod.data)

        # الويب محمي للطلاب
        self.client.force_authenticate(user=None)
        self.client.force_login(self.student_3sec_user)
        web_forbidden = self.client.get(reverse('admin_panel:send_notifications'), follow=False)
        self.assertEqual(web_forbidden.status_code, status.HTTP_302_FOUND)

    def test_send_to_specific_users_segment_and_all_via_api(self):
        from unittest.mock import patch
        from dashboard_admin.models import AuditLog

        self.client.force_authenticate(user=self.owner_user)

        # 1. بحث ومعاينة لمستخدمين معيّنين
        search_res = self.client.get('/api/v1/admin/notifications/', {'q': 'ST3001'})
        self.assertEqual(search_res.status_code, status.HTTP_200_OK)
        self.assertEqual(len(search_res.data['users']), 1)
        self.assertEqual(search_res.data['users'][0]['id'], self.student_3sec_user.id)
        self.assertTrue(search_res.data['users'][0]['has_fcm'])

        # 2. إرسال لمستخدمين معينين
        with patch('core.fcm_service.schedule_fcm_push_for_notifications') as sched_mock:
            res_users = self.client.post(
                '/api/v1/admin/notifications/',
                {
                    'target_mode': 'users',
                    'user_ids': [self.student_3sec_user.id, self.assistant_user.id],
                    'title': 'رسالة خاصة بكما',
                    'message': 'يرجى مراجعة حسابكما اليوم.',
                    'link': '/notifications/all/',
                },
                format='json',
            )
            self.assertEqual(res_users.status_code, status.HTTP_200_OK)
            self.assertEqual(res_users.data['recipient_count'], 2)
            self.assertEqual(res_users.data['fcm_user_count'], 1)
            self.assertEqual(sched_mock.call_count, 1)

        self.assertTrue(
            Notification.objects.filter(
                recipient=self.student_3sec_user,
                title='رسالة خاصة بكما',
            ).exists()
        )
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.assistant_user,
                title='رسالة خاصة بكما',
            ).exists()
        )
        self.assertFalse(
            Notification.objects.filter(
                recipient=self.teacher_active_user,
                title='رسالة خاصة بكما',
            ).exists()
        )

        # 3. إرسال لفئة (طلاب الصف الثالث الثانوي)
        Notification.objects.all().delete()
        res_grade = self.client.post(
            '/api/v1/admin/notifications/',
            {
                'target_mode': 'segment',
                'segment': 'grade',
                'grade': '3_sec',
                'title': 'مراجعة ٣ ثانوي',
                'message': 'مواعيد المراجعة النهائية متاحة الآن.',
                'link': '/student/dashboard/',
            },
            format='json',
        )
        self.assertEqual(res_grade.status_code, status.HTTP_200_OK)
        self.assertEqual(res_grade.data['recipient_count'], 1)
        self.assertTrue(Notification.objects.filter(recipient=self.student_3sec_user).exists())
        self.assertFalse(Notification.objects.filter(recipient=self.student_1prep_user).exists())

        # 4. التحقق من باقي الفئات عبر المعاينة الحية
        segment_checks = [
            ({'target_mode': 'segment', 'segment': 'teachers_active'}, 1),
            ({'target_mode': 'segment', 'segment': 'teachers_expired'}, 1),
            ({'target_mode': 'segment', 'segment': 'teacher_students', 'teacher_id': self.teacher_active.id}, 1),
            ({'target_mode': 'segment', 'segment': 'teacher_plan', 'plan_id': self.plan_pro.id}, 1),
            ({'target_mode': 'segment', 'segment': 'subject_teachers', 'subject_id': self.subject_math.id}, 1),
            ({'target_mode': 'segment', 'segment': 'fcm_enabled'}, 2),
            ({'target_mode': 'segment', 'segment': 'assistants'}, 1),
            ({'target_mode': 'segment', 'segment': 'admins'}, 3),
        ]
        for query, expected_count in segment_checks:
            prev_res = self.client.get('/api/v1/admin/notifications/', {'preview': '1', **query})
            self.assertEqual(prev_res.status_code, status.HTTP_200_OK)
            self.assertTrue(prev_res.data['ok'], msg=f"Failed segment {query}: {prev_res.data}")
            self.assertEqual(prev_res.data['recipient_count'], expected_count, msg=f"Segment mismatch {query}")

        # 5. إرسال لكل المستخدمين (يستثني المحظورين افتراضياً)
        Notification.objects.all().delete()
        res_all = self.client.post(
            '/api/v1/admin/notifications/',
            {
                'target_mode': 'all',
                'title': 'إعلان عام للمنصة',
                'message': 'تم إطلاق التحديث الجديد لجميع الأعضاء.',
                'link': '/plans/',
                'exclude_banned': True,
            },
            format='json',
        )
        self.assertEqual(res_all.status_code, status.HTTP_200_OK)
        # 8 حسابات نشطة غير محظورة (owner, mod, support, 2 teachers, 2 active students, assistant)
        self.assertEqual(res_all.data['recipient_count'], 8)
        self.assertFalse(Notification.objects.filter(recipient=self.banned_student_user).exists())
        self.assertTrue(Notification.objects.filter(recipient=self.teacher_expired_user).exists())

        # سجل الأحداث AuditLog مسجل
        audit = AuditLog.objects.filter(action=AuditLog.ACTION_SEND_NOTIFICATION).order_by('-id').first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.details['recipient_count'], 8)
        self.assertEqual(audit.details['title'], 'إعلان عام للمنصة')

    def test_validation_rejects_unsafe_link_and_missing_fields(self):
        self.client.force_authenticate(user=self.owner_user)

        bad_link = self.client.post(
            '/api/v1/admin/notifications/',
            {
                'target_mode': 'all',
                'title': 'عنوان',
                'message': 'رسالة',
                'link': 'javascript:alert(1)',
            },
            format='json',
        )
        self.assertEqual(bad_link.status_code, status.HTTP_400_BAD_REQUEST)

        empty_users = self.client.post(
            '/api/v1/admin/notifications/',
            {
                'target_mode': 'users',
                'user_ids': [],
                'title': 'عنوان',
                'message': 'رسالة',
            },
            format='json',
        )
        self.assertEqual(empty_users.status_code, status.HTTP_400_BAD_REQUEST)

        missing_grade = self.client.post(
            '/api/v1/admin/notifications/',
            {
                'target_mode': 'segment',
                'segment': 'grade',
                'title': 'عنوان',
                'message': 'رسالة',
            },
            format='json',
        )
        self.assertEqual(missing_grade.status_code, status.HTTP_400_BAD_REQUEST)

    def test_web_admin_notifications_page_and_preview(self):
        from django.urls import reverse

        self.client.force_login(self.mod_user)
        url = reverse('admin_panel:send_notifications')
        preview_url = reverse('admin_panel:notifications_recipient_preview')

        # فتح الصفحة مع تحديد مستخدم مسبقاً من صفحة إدارة المستخدمين
        get_res = self.client.get(
            f'{url}?mode=users&user_id={self.teacher_active_user.id}',
            follow=True,
        )
        self.assertEqual(get_res.status_code, status.HTTP_200_OK)
        html = get_res.content.decode('utf-8')
        self.assertIn('إرسال إشعارات مخصصة', html)
        self.assertIn('t_active@example.com', html)

        # المعاينة الحية JSON
        prev_res = self.client.get(
            preview_url,
            {'target_mode': 'segment', 'segment': 'teachers'},
            follow=True,
        )
        self.assertEqual(prev_res.status_code, status.HTTP_200_OK)
        prev_data = prev_res.json()
        self.assertTrue(prev_data['ok'])
        self.assertEqual(prev_data['recipient_count'], 2)

        # الإرسال عبر POST
        post_res = self.client.post(
            url,
            {
                'target_mode': 'segment',
                'segment': 'teachers_active',
                'exclude_banned': '1',
                'title': 'تنبيه للمعلمين المشتركين',
                'message': 'رسالة من لوحة الإدارة بالويب.',
                'link': '/teacher/dashboard/',
            },
            follow=True,
        )
        self.assertEqual(post_res.status_code, status.HTTP_200_OK)
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.teacher_active_user,
                title='تنبيه للمعلمين المشتركين',
            ).exists()
        )
        self.assertFalse(
            Notification.objects.filter(
                recipient=self.teacher_expired_user,
                title='تنبيه للمعلمين المشتركين',
            ).exists()
        )

    def test_fcm_payload_caps_long_announcement_body_safely(self):
        from core.fcm_service import _build_fcm_message

        long_msg = 'س' * 750
        notif = Notification.objects.create(
            recipient=self.student_3sec_user,
            title='إعلان طويل',
            message=long_msg,
        )
        payload = _build_fcm_message(notif, 'fake_token_123')
        self.assertEqual(len(payload['message']['notification']['body']), 500)
        self.assertTrue(payload['message']['notification']['body'].endswith('…'))
        notif.refresh_from_db()
        self.assertEqual(len(notif.message), 750)



