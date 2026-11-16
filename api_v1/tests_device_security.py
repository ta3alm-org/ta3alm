"""
api_v1/tests_device_security.py
مجموعة اختبارات أمنية شاملة (18 اختباراً) تغطي:
- بصمة الأجهزة المُرقّمة الإصدار fp_v1 واكتشاف الانحراف والتحديثات الطبيعية
- تسجيل الأجهزة، الحدود القصوى حسب الدور، منع الاستبدال الصامت، فحص الملكية (Anti-IDOR)
- ذكاء الـ IP، الانتقال الجغرافي السريع، شبكات المحمول/CGNAT، ومرونة VPN
- محرك تسجيل المخاطر السلوكية، كشف مشاركة الحساب، ومحاولات الدخول الفاشلة
- تكامل Play Integrity ورصد التلاعب وحماية التقاط الشاشة
- لوحة الأمان للمسؤولين وسجل التدقيق AuditLog وسياسة الاحتفاظ بالبيانات
"""
from datetime import timedelta
import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APITestCase

from accounts.models import EmailVerification, StudentProfile
from core.models import SiteSetting, Subject
from dashboard_admin.models import AuditLog
from students.models import Enrollment
from teachers.models import Group, Lecture, SubscriptionPlan, TeacherProfile, VideoCode

from api_v1.device_security_service import (
    detect_account_sharing,
    generate_versioned_fingerprint,
    normalize_device_info,
    prune_expired_telemetry,
    register_or_update_device,
    validate_installation_id,
)
from api_v1.models import (
    DeviceActivity,
    DeviceBlock,
    DeviceFingerprint,
    DeviceSecurityEvent,
    DeviceSession,
    DeviceTrustStatus,
    PlaybackSession,
    RegisteredDevice,
    SecurityPolicyConfig,
    VideoAsset,
    VideoSecurityAuditLog,
)

User = get_user_model()


def _sample_device_info(
    *,
    manufacturer='Samsung',
    model='Galaxy S23',
    android_version='14',
    api_level=34,
    cpu_arch='arm64-v8a',
    app_version='2.1.0',
    app_build_number='21',
    package_name='online.ta3alm.ta3alm_flutter',
    signing_cert_sha256='aa' * 32,
    installer_source='com.android.vending',
    extra_signals=None,
):
    signals = {
        'is_debug_build': False,
        'debugger_attached': False,
        'root_detected': False,
        'hooking_detected': False,
        'frida_detected': False,
        'emulator_detected': False,
        'vpn_interface_active': False,
        'external_display_detected': False,
        'screen_recording_suspected': False,
    }
    if extra_signals:
        signals.update(extra_signals)
    return {
        'manufacturer': manufacturer,
        'model': model,
        'device_name': f'{manufacturer} {model}',
        'os_name': 'Android',
        'android_version': android_version,
        'api_level': api_level,
        'cpu_arch': cpu_arch,
        'cpu_info': 'Qualcomm Technologies, Inc SM8550',
        'gpu_renderer': 'Adreno (TM) 740',
        'gpu_vendor': 'Qualcomm',
        'screen_resolution': '1080x2340@420dpi',
        'app_version': app_version,
        'app_build_number': app_build_number,
        'package_name': package_name,
        'signing_cert_sha256': signing_cert_sha256,
        'installer_source': installer_source,
        'integrity_signals': signals,
        **signals,
    }


@override_settings(
    ANDROID_APP_PACKAGE_NAME='online.ta3alm.ta3alm_flutter',
    ANDROID_SIGNING_CERT_SHA256='aa' * 32,
    SECURE_PROXY_SSL_HEADER=None,
)
class DeviceSecuritySystemTests(APITestCase):
    def setUp(self):
        self.policy = SecurityPolicyConfig.load()
        self.policy.student_device_limit = 2
        self.policy.teacher_device_limit = 3
        self.policy.max_concurrent_sessions = 2
        self.policy.max_concurrent_playback = 1
        self.policy.save()

        self.subject = Subject.objects.create(name='Mathematics')
        self.plan = SubscriptionPlan.objects.create(
            name='Gold Plan',
            price=300,
            student_limit=500,
            group_limit=10,
            assistant_limit=3,
            allow_online_packages=True,
        )
        self.teacher_user = User.objects.create_user(
            username='teacher_sec',
            email='teacher_sec@example.com',
            password='Password123!',
            role='teacher',
            first_name='Tarek',
            phone='01022223331',
        )
        self.teacher = TeacherProfile.objects.create(
            user=self.teacher_user,
            subject=self.subject,
            current_plan=self.plan,
            subscription_end_date=timezone.now() + timedelta(days=30),
        )
        self.group = Group.objects.create(teacher=self.teacher, name='Sec 3 Math', grade='3_sec')
        self.lecture = Lecture.objects.create(
            group=self.group,
            title='Calculus Protected Lesson',
            video_link='https://origin.private.ta3alm.online/raw/calculus.mp4',
            description='Protected calculus class',
            is_active=True,
        )
        self.asset = VideoAsset.objects.create(
            lecture=self.lecture,
            source_type='hls_protected',
            provider='bunny_stream',
            provider_asset_id='calc-001',
            manifest_url='https://cdn.example.net/calc-001/playlist.m3u8',
            duration_seconds=900,
            migration_status='verified',
        )

        self.student_user = User.objects.create_user(
            username='student_sec_1',
            email='student_sec_1@example.com',
            password='Password123!',
            role='student',
            first_name='Youssef',
            phone='01011112221',
        )
        self.student = StudentProfile.objects.create(user=self.student_user, parent_phone='01099998881')
        Enrollment.objects.create(student=self.student, group=self.group, is_active=True)
        self.video_code = VideoCode.objects.create(lecture=self.lecture, code='CALC99', max_views=5)

        self.other_student_user = User.objects.create_user(
            username='student_sec_2',
            email='student_sec_2@example.com',
            password='Password123!',
            role='student',
            first_name='Mona',
            phone='01011112222',
        )
        StudentProfile.objects.create(user=self.other_student_user, parent_phone='01099998882')

        self.admin_user = User.objects.create_superuser(
            username='sec_admin',
            email='sec_admin@example.com',
            password='AdminPassword123!',
            role='admin',
            first_name='Admin',
        )

        for u in (self.teacher_user, self.student_user, self.other_student_user):
            EmailVerification.objects.create(
                user=u,
                code='123456',
                is_verified=True,
                expires_at=timezone.now() + timedelta(days=1),
            )

    def _login_with_device(
        self,
        *,
        identifier='student_sec_1@example.com',
        password='Password123!',
        installation_id='inst_11111111111111111111111111111111',
        device_info=None,
        ip='41.33.10.1',
        country='EG',
        region='Cairo',
    ):
        return self.client.post(
            reverse('api_v1_login'),
            {
                'identifier': identifier,
                'password': password,
                'installation_id': installation_id,
                'device_info': device_info or _sample_device_info(),
            },
            format='json',
            REMOTE_ADDR=ip,
            HTTP_CF_IPCOUNTRY=country,
            HTTP_X_VERCEL_IP_COUNTRY_REGION=region,
        )

    def test_01_new_device_registration(self):
        inst_id = 'inst_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        resp = self._login_with_device(installation_id=inst_id)
        self.assertEqual(resp.status_code, 200)
        self.assertIn('device_security', resp.data)
        self.assertTrue(resp.data['device_security']['allowed'])
        self.assertEqual(resp.data['device_security']['fingerprint']['algorithm_version'], 'fp_v1')

        device = RegisteredDevice.objects.get(user=self.student_user, installation_id=inst_id)
        self.assertEqual(device.trust_status, DeviceTrustStatus.TRUSTED)
        self.assertEqual(device.manufacturer, 'Samsung')
        self.assertEqual(device.last_ip, '41.33.10.1')
        self.assertEqual(device.last_country, 'EG')
        self.assertTrue(DeviceFingerprint.objects.filter(device=device, algorithm_version='fp_v1').exists())
        self.assertTrue(DeviceSession.objects.filter(device=device, status='active').exists())
        self.assertTrue(DeviceActivity.objects.filter(device=device, activity_type='device_registered').exists())

    def test_02_existing_device_reuse_does_not_consume_new_slot(self):
        inst_id = 'inst_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
        self.assertEqual(self._login_with_device(installation_id=inst_id, ip='41.33.10.2').status_code, 200)
        self.assertEqual(self._login_with_device(installation_id=inst_id, ip='41.33.10.50').status_code, 200)

        self.assertEqual(
            RegisteredDevice.objects.filter(user=self.student_user, installation_id=inst_id).count(),
            1,
        )
        device = RegisteredDevice.objects.get(user=self.student_user, installation_id=inst_id)
        self.assertEqual(device.last_ip, '41.33.10.50')

    def test_03_device_limit_enforcement_without_silent_overwrite(self):
        d1 = 'inst_c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1'
        d2 = 'inst_c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2'
        d3 = 'inst_c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3'

        self.assertEqual(self._login_with_device(installation_id=d1).status_code, 200)
        self.assertEqual(
            self._login_with_device(
                installation_id=d2,
                device_info=_sample_device_info(manufacturer='Xiaomi', model='Redmi Note 12'),
            ).status_code,
            200,
        )
        third = self._login_with_device(
            installation_id=d3,
            device_info=_sample_device_info(manufacturer='OnePlus', model='12R'),
        )
        self.assertEqual(third.status_code, 403)
        self.assertEqual(third.data.get('code'), 'DEVICE_LIMIT_REACHED')
        self.assertEqual(third.data.get('device_limit'), 2)

        # الأجهزة الأول والثاني ما زالا موثوقين ولم يُستبدلا صامتاً
        self.assertTrue(
            RegisteredDevice.objects.filter(user=self.student_user, installation_id=d1, is_active=True).exists()
        )
        self.assertTrue(
            RegisteredDevice.objects.filter(user=self.student_user, installation_id=d2, is_active=True).exists()
        )
        self.assertFalse(
            RegisteredDevice.objects.filter(user=self.student_user, installation_id=d3).exists()
        )
        self.assertTrue(
            DeviceSecurityEvent.objects.filter(user=self.student_user, event_type='device_limit_reached').exists()
        )

    def test_04_device_revocation_frees_slot_and_logs(self):
        d1 = 'inst_d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1'
        d2 = 'inst_d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2'
        d3 = 'inst_d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3'

        self.assertEqual(self._login_with_device(installation_id=d1).status_code, 200)
        login2 = self._login_with_device(installation_id=d2)
        self.assertEqual(login2.status_code, 200)
        access2 = login2.data['access']

        dev1 = RegisteredDevice.objects.get(user=self.student_user, installation_id=d1)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access2}', HTTP_X_DEVICE_ID=d2)
        revoke_resp = self.client.post(
            reverse('api_v1_security_device_revoke', args=[dev1.id]),
            {'action': 'revoke', 'reason': 'Replaced old phone'},
            format='json',
        )
        self.assertEqual(revoke_resp.status_code, 200)
        dev1.refresh_from_db()
        self.assertEqual(dev1.trust_status, DeviceTrustStatus.REVOKED)
        self.assertFalse(dev1.is_active)
        self.assertFalse(DeviceSession.objects.filter(device=dev1, status='active').exists())
        self.assertTrue(
            DeviceSecurityEvent.objects.filter(user=self.student_user, event_type='device_revoked').exists()
        )

        # الآن يمكن تسجيل الجهاز الثالث بعد إلغاء الأول
        self.client.credentials()
        self.assertEqual(self._login_with_device(installation_id=d3).status_code, 200)

    def test_05_session_refresh_and_logout_termination(self):
        inst_id = 'inst_e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1'
        login_resp = self._login_with_device(installation_id=inst_id)
        self.assertEqual(login_resp.status_code, 200)
        access = login_resp.data['access']
        refresh = login_resp.data['refresh']

        # تجديد التوكن ينجح للجلسة النشطة
        ref_resp = self.client.post(
            reverse('api_v1_token_refresh'),
            {'refresh': refresh, 'installation_id': inst_id},
            format='json',
        )
        self.assertEqual(ref_resp.status_code, 200)
        self.assertIn('access', ref_resp.data)

        # تسجيل الخروج ينهي DeviceSession
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {ref_resp.data["access"]}', HTTP_X_DEVICE_ID=inst_id)
        logout_resp = self.client.post(
            reverse('api_v1_logout'),
            {'refresh': refresh, 'installation_id': inst_id},
            format='json',
        )
        self.assertEqual(logout_resp.status_code, 200)
        self.assertFalse(
            DeviceSession.objects.filter(user=self.student_user, installation_id=inst_id, status='active').exists()
        )
        self.assertTrue(
            DeviceSession.objects.filter(user=self.student_user, installation_id=inst_id, status='logged_out').exists()
        )

    def test_06_jwt_enforcement_rejects_revoked_or_blocked_device(self):
        inst_id = 'inst_f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1'
        login_resp = self._login_with_device(installation_id=inst_id)
        self.assertEqual(login_resp.status_code, 200)
        access = login_resp.data['access']

        dev = RegisteredDevice.objects.get(user=self.student_user, installation_id=inst_id)
        dev.trust_status = DeviceTrustStatus.REVOKED
        dev.is_active = False
        dev.save(update_fields=['trust_status', 'is_active'])

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access}', HTTP_X_DEVICE_ID=inst_id)
        me_resp = self.client.get(reverse('api_v1_me'))
        self.assertEqual(me_resp.status_code, 401)

    def test_07_cross_account_device_idor_rejected(self):
        inst_id = 'inst_71717171717171717171717171717171'
        self.assertEqual(self._login_with_device(installation_id=inst_id).status_code, 200)
        dev_student1 = RegisteredDevice.objects.get(user=self.student_user, installation_id=inst_id)

        self.client.force_authenticate(user=self.other_student_user)
        resp = self.client.post(
            reverse('api_v1_security_device_revoke', args=[dev_student1.id]),
            {'action': 'revoke'},
            format='json',
        )
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.data.get('code'), 'FORBIDDEN_DEVICE_OWNER')
        self.assertTrue(
            DeviceSecurityEvent.objects.filter(
                user=self.other_student_user,
                event_type='cross_account_device_idor_attempt',
            ).exists()
        )

    def test_08_device_limit_admin_configuration_and_audit(self):
        self.client.force_authenticate(user=self.admin_user)
        resp = self.client.post(
            reverse('api_v1_security_admin_actions'),
            {'action': 'update_policy_config', 'student_device_limit': 3},
            format='json',
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data['policy']['student_device_limit'], 3)
        self.assertTrue(AuditLog.objects.filter(action=AuditLog.ACTION_SECURITY_POLICY).exists())

        self.client.force_authenticate(user=None)
        for suffix in ('a', 'b', 'c'):
            r = self._login_with_device(installation_id=f'inst_{suffix * 32}')
            self.assertEqual(r.status_code, 200)

    def test_09_ip_history_and_rapid_geo_transition_without_ban(self):
        inst_id = 'inst_91919191919191919191919191919191'
        self.assertEqual(
            self._login_with_device(installation_id=inst_id, ip='41.33.10.1', country='EG', region='Cairo').status_code,
            200,
        )
        second = self._login_with_device(
            installation_id=inst_id,
            ip='198.51.100.77',
            country='JP',
            region='Tokyo',
        )
        self.assertEqual(second.status_code, 200)
        self.student_user.refresh_from_db()
        self.assertFalse(self.student_user.is_banned)
        dev = RegisteredDevice.objects.get(user=self.student_user, installation_id=inst_id)
        self.assertGreaterEqual(len(dev.ip_history), 2)
        self.assertTrue(
            DeviceSecurityEvent.objects.filter(user=self.student_user, event_type='rapid_geo_transition').exists()
        )

    def test_10_correlated_behavioral_risk_scoring(self):
        # 1) تجميع عدة إشارات متوسطة المخاطر بدون حجب تسجيل الدخول (Root + Emulator + Rapid Geo)
        inst_corr = 'inst_10101010101010101010101010101010'
        r1 = self._login_with_device(
            installation_id=inst_corr,
            ip='41.33.10.1',
            country='EG',
            device_info=_sample_device_info(),
        )
        self.assertEqual(r1.status_code, 200)

        r2 = self._login_with_device(
            installation_id=inst_corr,
            ip='198.51.100.88',
            country='FR',
            device_info=_sample_device_info(
                extra_signals={'root_detected': True, 'emulator_detected': True}
            ),
        )
        self.assertEqual(r2.status_code, 200)
        dev_corr = RegisteredDevice.objects.get(user=self.student_user, installation_id=inst_corr)
        self.assertGreaterEqual(dev_corr.risk_score, 60)
        self.assertIn(dev_corr.risk_level, ('high', 'critical'))
        self.assertTrue(dev_corr.requires_reauth)

        # 2) إشارات التلاعب الحرجة (Frida + Hooking) ترفض الدخول فورياً (403) وتقيد الجهاز والفيديو
        inst_tamper = 'inst_10b10b10b10b10b10b10b10b10b10b10'
        tamper_resp = self._login_with_device(
            installation_id=inst_tamper,
            device_info=_sample_device_info(
                extra_signals={
                    'frida_detected': True,
                    'hooking_detected': True,
                    'debugger_attached': True,
                }
            ),
        )
        self.assertEqual(tamper_resp.status_code, 403)
        self.assertEqual(tamper_resp.data.get('code'), 'APP_INTEGRITY_FAILED')
        dev_tamper = RegisteredDevice.objects.get(user=self.student_user, installation_id=inst_tamper)
        self.assertGreaterEqual(dev_tamper.risk_score, 85)
        self.assertEqual(dev_tamper.risk_level, 'critical')
        self.assertEqual(dev_tamper.trust_status, DeviceTrustStatus.RESTRICTED)
        self.assertTrue(dev_tamper.requires_reauth)

        # بعد التقييد الحرج، يجب رفض الوصول للفيديو المحمي حتى من هذا الجهاز
        self.client.force_authenticate(user=self.student_user)
        auth_vid = self.client.post(
            reverse('api_v1_video_authorize', args=[self.lecture.id]),
            {'code': 'CALC99', 'device_id': inst_tamper},
            format='json',
        )
        self.assertEqual(auth_vid.status_code, 403)

    def test_11_excessive_failed_logins_recorded_and_flagged(self):
        inst_id = 'inst_11a11a11a11a11a11a11a11a11a11a11'
        for _ in range(5):
            r = self.client.post(
                reverse('api_v1_login'),
                {
                    'identifier': 'student_sec_1@example.com',
                    'password': 'WrongPassword!',
                    'installation_id': inst_id,
                },
                format='json',
                REMOTE_ADDR='41.33.99.9',
            )
            self.assertEqual(r.status_code, 401)

        self.assertEqual(
            DeviceActivity.objects.filter(user=self.student_user, activity_type='login_failed').count(),
            5,
        )
        self.assertTrue(
            DeviceSecurityEvent.objects.filter(
                user=self.student_user,
                event_type='excessive_login_attempts',
            ).exists()
        )

    def test_12_account_sharing_concurrent_playback_detection(self):
        inst_a = 'inst_12a12a12a12a12a12a12a12a12a12a12'
        inst_b = 'inst_12b12b12b12b12b12b12b12b12b12b12'

        r1 = self._login_with_device(installation_id=inst_a, ip='41.33.10.1', country='EG')
        self.assertEqual(r1.status_code, 200)
        r2 = self._login_with_device(installation_id=inst_b, ip='41.33.10.2', country='EG')
        self.assertEqual(r2.status_code, 200)

        self.policy.max_concurrent_sessions = 1
        self.policy.max_concurrent_playback = 1
        self.policy.save()

        # جهاز A يشغل محاضرة حالياً
        PlaybackSession.objects.create(
            user=self.student_user,
            lecture=self.lecture,
            device_id=inst_a,
            status='active',
            expires_at=timezone.now() + timedelta(minutes=10),
        )

        # جهاز B (جلسات متزامنة + تشغيل متزامن + دولة أخرى عند طلب التشغيل)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {r2.data["access"]}', HTTP_X_DEVICE_ID=inst_b)
        with patch('api_v1.views_video.get_integrity_policy_mode', return_value='off'):
            vid_resp = self.client.post(
                reverse('api_v1_video_authorize', args=[self.lecture.id]),
                {'code': 'CALC99', 'device_id': inst_b},
                format='json',
                REMOTE_ADDR='85.203.10.5',
                HTTP_CF_IPCOUNTRY='DE',
            )
        self.assertEqual(vid_resp.status_code, 403)
        self.assertEqual(vid_resp.data.get('code'), 'ACCOUNT_SHARING_RESTRICTED')
        self.assertTrue(
            DeviceSecurityEvent.objects.filter(
                user=self.student_user,
                event_type='account_sharing_suspected',
            ).exists()
        )

    def test_13_fingerprint_versioning_and_suspicious_hardware_drift(self):
        inst_id = 'inst_13131313131313131313131313131313'
        base_traits = _sample_device_info()
        r1 = self._login_with_device(installation_id=inst_id, device_info=base_traits)
        self.assertEqual(r1.status_code, 200)

        dev = RegisteredDevice.objects.get(user=self.student_user, installation_id=inst_id)
        self.assertEqual(DeviceFingerprint.objects.filter(device=dev).count(), 1)

        # تغير مفاجئ في العتاد والشركة المصنعة لنفس installation_id مع الحفاظ على سجل البصمات
        drifted_traits = _sample_device_info(
            manufacturer='OnePlus',
            model='CPH2585',
            cpu_arch='x86_64',
        )
        r2 = self._login_with_device(installation_id=inst_id, device_info=drifted_traits)
        self.assertEqual(r2.status_code, 200)
        dev.refresh_from_db()
        self.assertEqual(DeviceFingerprint.objects.filter(device=dev).count(), 2)
        self.assertTrue(
            DeviceSecurityEvent.objects.filter(
                user=self.student_user,
                event_type='core_hardware_fingerprint_mismatch',
            ).exists()
        )
        self.assertGreaterEqual(dev.risk_score, 45)

    def test_14_screen_capture_event_reporting_and_escalation(self):
        inst_id = 'inst_14141414141414141414141414141414'
        login_resp = self._login_with_device(installation_id=inst_id)
        self.assertEqual(login_resp.status_code, 200)
        self.client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {login_resp.data["access"]}',
            HTTP_X_DEVICE_ID=inst_id,
        )

        url = reverse('api_v1_security_event_report')
        bad = self.client.post(url, {'event_type': 'unknown_event'}, format='json')
        self.assertEqual(bad.status_code, 400)

        shot = self.client.post(
            url,
            {
                'event_type': 'screenshot_attempt',
                'installation_id': inst_id,
                'screen_name': 'lecture_player_screen_1',
            },
            format='json',
        )
        self.assertEqual(shot.status_code, 201)
        self.assertTrue(shot.data['recorded'])

        rec = self.client.post(
            url,
            {
                'event_type': 'screen_recording_detected',
                'installation_id': inst_id,
                'screen_name': 'take_exam_1',
            },
            format='json',
        )
        self.assertEqual(rec.status_code, 201)
        dev = RegisteredDevice.objects.get(user=self.student_user, installation_id=inst_id)
        self.assertIn(dev.trust_status, (DeviceTrustStatus.SUSPICIOUS, DeviceTrustStatus.RESTRICTED))

    def test_15_play_integrity_failure_updates_registered_device_and_events(self):
        inst_id = 'inst_15151515151515151515151515151515'
        login_resp = self._login_with_device(installation_id=inst_id)
        self.assertEqual(login_resp.status_code, 200)
        self.client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {login_resp.data["access"]}',
            HTTP_X_DEVICE_ID=inst_id,
        )

        ch = self.client.post(reverse('api_v1_integrity_challenge'), {'action': 'video_authorize'}, format='json')
        self.assertEqual(ch.status_code, 200)
        with patch('api_v1.views_video.get_integrity_policy_mode', return_value='enforce'):
            ver = self.client.post(
                reverse('api_v1_integrity_verify'),
                {
                    'nonce_id': ch.data['nonce_id'],
                    'device_id': inst_id,
                    'is_debug_build': False,
                    'tamper_signals': {'frida_detected': True},
                },
                format='json',
            )
        self.assertEqual(ver.status_code, 200)
        self.assertEqual(ver.data['policy_decision'], 'block')

        dev = RegisteredDevice.objects.get(user=self.student_user, installation_id=inst_id)
        self.assertEqual(dev.trust_status, DeviceTrustStatus.RESTRICTED)
        self.assertTrue(dev.requires_reauth)
        self.assertTrue(
            DeviceSecurityEvent.objects.filter(
                user=self.student_user,
                event_type='integrity_verification_failed',
            ).exists()
        )

    def test_16_admin_block_unblock_and_html_dashboard_rendering(self):
        inst_id = 'inst_16161616161616161616161616161616'
        login_resp = self._login_with_device(installation_id=inst_id)
        self.assertEqual(login_resp.status_code, 200)
        dev = RegisteredDevice.objects.get(user=self.student_user, installation_id=inst_id)

        # حظر الجهاز عبر API المسؤول
        self.client.force_authenticate(user=self.admin_user)
        blk_resp = self.client.post(
            reverse('api_v1_security_admin_actions'),
            {'action': 'block_device', 'device_id': dev.id, 'block_type': 'permanent', 'reason': 'Policy abuse'},
            format='json',
        )
        self.assertEqual(blk_resp.status_code, 200)
        self.assertTrue(DeviceBlock.objects.filter(installation_id=inst_id, is_active=True).exists())

        # الطالب المحظور يُرفض عند إعادة الدخول من هذا الجهاز
        self.client.force_authenticate(user=None)
        denied = self._login_with_device(installation_id=inst_id)
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(denied.data.get('code'), 'DEVICE_BLOCKED')

        # فك الحظر واستعادة إمكانية الدخول
        self.client.force_authenticate(user=self.admin_user)
        unblk_resp = self.client.post(
            reverse('api_v1_security_admin_actions'),
            {'action': 'unblock_device', 'device_id': dev.id, 'reason': 'Appeal approved'},
            format='json',
        )
        self.assertEqual(unblk_resp.status_code, 200)
        self.assertFalse(DeviceBlock.objects.filter(installation_id=inst_id, is_active=True).exists())

        # اختبار لوحة تحكم الويب (HTML Templates) للمسؤول
        self.client.force_authenticate(user=None)
        self.client.force_login(self.admin_user)
        dash_resp = self.client.get(reverse('admin_panel:security_dashboard'))
        self.assertEqual(dash_resp.status_code, 200)
        detail_resp = self.client.get(reverse('admin_panel:security_device_detail', args=[dev.id]))
        self.assertEqual(detail_resp.status_code, 200)

        # التأكد أن الطالب العادي ممنوع من لوحة المسؤول
        self.client.force_login(self.student_user)
        student_dash = self.client.get(reverse('admin_panel:security_dashboard'))
        self.assertNotEqual(student_dash.status_code, 200)

    def test_17_privacy_validation_and_telemetry_retention_prune(self):
        # منع البريد الإلكتروني أو اسم المستخدم كمعرف جهاز
        ok_email, _, _ = validate_installation_id('student_sec_1@example.com', user=self.student_user)
        self.assertFalse(ok_email)
        ok_user, _, _ = validate_installation_id('student_sec_1', user=self.student_user)
        self.assertFalse(ok_user)
        ok_valid, cleaned, _ = validate_installation_id('inst_valid_1234567890abcdef', user=self.student_user)
        self.assertTrue(ok_valid)
        self.assertEqual(cleaned, 'inst_valid_1234567890abcdef')

        # التأكد من عدم تخزين أي حقول مقيدة (IMEI / MAC / SSAID / email) داخل خصائص البصمة
        inst_id = 'inst_17171717171717171717171717171717'
        traits = normalize_device_info({
            **_sample_device_info(),
            'imei': '359999999999999',
            'mac_address': 'AA:BB:CC:DD:EE:FF',
            'android_id': 'bad-ssaid',
        })
        fp = generate_versioned_fingerprint(inst_id, traits)
        self.assertTrue(fp['fingerprint_hash'].startswith('fp_v1:'))
        self.assertNotIn('imei', traits)
        self.assertNotIn('mac_address', traits)
        self.assertNotIn('android_id', traits)

        # اختبار سياسة الاحتفاظ بالبيانات وتنظيف السجلات القديمة المنتهية
        old_dt = timezone.now() - timedelta(days=120)
        act = DeviceActivity.objects.create(user=self.student_user, activity_type='login')
        DeviceActivity.objects.filter(pk=act.pk).update(created_at=old_dt)

        evt_old = DeviceSecurityEvent.objects.create(
            user=self.student_user,
            event_type='minor_test',
            severity='low',
            investigation_status='resolved',
        )
        DeviceSecurityEvent.objects.filter(pk=evt_old.pk).update(created_at=old_dt)

        pruned = prune_expired_telemetry(retention_days=30)
        self.assertGreaterEqual(pruned['activities_deleted'], 1)
        self.assertGreaterEqual(pruned['events_deleted'], 1)

    def test_18_false_positive_resilience_for_benign_updates_and_mobile_ip(self):
        inst_id = 'inst_18181818181818181818181818181818'
        r1 = self._login_with_device(
            installation_id=inst_id,
            device_info=_sample_device_info(android_version='13', api_level=33, app_version='2.0.0', app_build_number='20'),
            ip='41.33.10.10',
            country='EG',
            region='Cairo',
        )
        self.assertEqual(r1.status_code, 200)

        # تحديث طبيعي لنظام أندرويد + إصدار التطبيق + تبدل IP ضمن شبكة المحمول في نفس الدولة + تشغيل VPN
        r2 = self._login_with_device(
            installation_id=inst_id,
            device_info=_sample_device_info(
                android_version='14',
                api_level=34,
                app_version='2.2.0',
                app_build_number='22',
                extra_signals={'vpn_interface_active': True},
            ),
            ip='156.192.44.8',
            country='EG',
            region='Alexandria',
        )
        self.assertEqual(r2.status_code, 200)
        dev = RegisteredDevice.objects.get(user=self.student_user, installation_id=inst_id)
        self.assertEqual(dev.trust_status, DeviceTrustStatus.TRUSTED)
        self.assertFalse(dev.requires_reauth)
        self.student_user.refresh_from_db()
        self.assertFalse(self.student_user.is_banned)

    def test_19_mandatory_otp_verification_gate_mobile_and_web(self):
        # 1) تسجيل طالب جديد عبر Mobile API يولّد OTP من 6 أرقام ويفرض التحقق
        with patch('services.zoho_mail_service.ZohoMailService.is_connected', return_value=False):
            reg_res = self.client.post(
                reverse('api_v1_register'),
                {
                    'full_name': 'طالب جديد غير مؤكد',
                    'email': 'unverified_mobile@example.com',
                    'phone': '01055556666',
                    'password': 'Password123!',
                    'confirm_password': 'Password123!',
                    'role': 'student',
                    'installation_id': 'inst_19191919191919191919191919191919',
                    'device_info': _sample_device_info(),
                },
                format='json',
            )
        self.assertEqual(reg_res.status_code, 201)
        self.assertTrue(reg_res.data['requires_verification'])
        self.assertTrue(reg_res.data['user']['requires_verification'])
        self.assertFalse(reg_res.data['user']['is_email_verified'])

        new_user = User.objects.get(email='unverified_mobile@example.com')
        verification = EmailVerification.objects.get(user=new_user)
        self.assertFalse(verification.is_verified)
        self.assertEqual(len(verification.code), 6)

        token = reg_res.data['access']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        # 2) منع دخول الحساب غير المؤكد لكل واجهات المنصة في التطبيق
        dash_blocked = self.client.get(reverse('api_v1_student_dashboard'))
        self.assertEqual(dash_blocked.status_code, 403)
        self.assertEqual(dash_blocked.data.get('code'), 'EMAIL_VERIFICATION_REQUIRED')

        complete_blocked = self.client.post(
            reverse('api_v1_complete_profile'),
            {
                'full_name': 'طالب غير مؤكد',
                'national_id': '30501010109988',
                'phone': '01055556666',
                'parent_phone': '01077778888',
            },
            format='json',
        )
        self.assertEqual(complete_blocked.status_code, 403)
        self.assertEqual(complete_blocked.data.get('code'), 'EMAIL_VERIFICATION_REQUIRED')

        video_blocked = self.client.post(
            reverse('api_v1_video_authorize', args=[self.lecture.id]),
            {'device_id': 'inst_19191919191919191919191919191919'},
            format='json',
        )
        self.assertEqual(video_blocked.status_code, 403)
        self.assertEqual(video_blocked.data.get('code'), 'EMAIL_VERIFICATION_REQUIRED')

        # 3) فحص حجب الويب (Web EmailVerificationMiddleware) حتى للحسابات القديمة بدون سجل تفعيل
        legacy_unverified = User.objects.create_user(
            username='legacy_unverified',
            email='legacy_unverified@example.com',
            password='Password123!',
            role='student',
            first_name='Legacy',
            phone='01066667777',
            custom_id='S998877',
        )
        StudentProfile.objects.create(user=legacy_unverified, parent_phone='01099990000')
        self.client.credentials()
        self.client.force_login(legacy_unverified)
        web_blocked = self.client.get('/ar/student/dashboard/')
        self.assertEqual(web_blocked.status_code, 302)
        self.assertIn('/verify-email/', web_blocked['Location'])
        self.client.logout()

        # 4) اختبار رمز خطأ + مهلة إعادة الإرسال + التفعيل الصحيح في الموبايل
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        wrong_otp = self.client.post(reverse('api_v1_verify_otp'), {'code': '000000'}, format='json')
        self.assertEqual(wrong_otp.status_code, 400)
        self.assertEqual(wrong_otp.data.get('code'), 'INVALID_OTP')

        cooldown_res = self.client.post(reverse('api_v1_resend_otp'), {}, format='json')
        self.assertEqual(cooldown_res.status_code, 429)
        self.assertEqual(cooldown_res.data.get('code'), 'RESEND_COOLDOWN')

        valid_code = verification.code if verification.code != '000000' else '123456'
        ok_otp = self.client.post(reverse('api_v1_verify_otp'), {'code': valid_code}, format='json')
        self.assertEqual(ok_otp.status_code, 200)
        self.assertTrue(ok_otp.data['is_email_verified'])
        self.assertFalse(ok_otp.data['requires_verification'])

        # 5) بعد التفعيل يُفتح استكمال البيانات ولوحة الطالب
        complete_ok = self.client.post(
            reverse('api_v1_complete_profile'),
            {
                'full_name': 'طالب مؤكد الآن',
                'national_id': '30501010109988',
                'phone': '01055556666',
                'parent_phone': '01077778888',
            },
            format='json',
        )
        self.assertEqual(complete_ok.status_code, 200)
        dash_ok = self.client.get(reverse('api_v1_student_dashboard'))
        self.assertEqual(dash_ok.status_code, 200)

    def test_20_mandatory_in_app_update_version_gate(self):
        site_settings = SiteSetting.load()
        site_settings.android_latest_version_code = 25
        site_settings.android_min_required_version_code = 25
        site_settings.android_latest_version_name = '2.5.0'
        site_settings.android_force_update = True
        site_settings.android_apk_url = 'https://www.ta3alm.online/releases/ta3alm-v25.apk'
        site_settings.android_update_release_notes = 'تحديث أمني إلزامي وتطوير المشغل'
        site_settings.save()

        # 1) فحص نقطة التحقق من الإصدار لنسخة قديمة (21)
        ver_res = self.client.get(reverse('api_v1_app_version'), {'version_code': 21})
        self.assertEqual(ver_res.status_code, 200)
        self.assertTrue(ver_res.data['update_required'])
        self.assertEqual(ver_res.data['latest_version_code'], 25)
        self.assertEqual(ver_res.data['apk_download_url'], 'https://www.ta3alm.online/releases/ta3alm-v25.apk')

        # 2) حظر أي طلب API يأتي من إصدار قديم (HTTP_X_APP_BUILD=21) بـ 426 Upgrade Required
        self.client.force_authenticate(user=self.student_user)
        blocked_api = self.client.get(
            reverse('api_v1_student_dashboard'),
            HTTP_X_APP_BUILD='21',
        )
        self.assertEqual(blocked_api.status_code, 426)
        blocked_json = json.loads(blocked_api.content.decode('utf-8'))
        self.assertEqual(blocked_json.get('code'), 'APP_UPDATE_REQUIRED')

        # 3) حظر تسجيل الدخول من جهاز يحمل build قديم (21) في device_info أيضاً
        self.client.force_authenticate(user=None)
        login_blocked = self._login_with_device(
            installation_id='inst_20202020202020202020202020202020',
            device_info=_sample_device_info(app_build_number='21', app_version='2.1.0'),
        )
        self.assertEqual(login_blocked.status_code, 426)
        self.assertEqual(login_blocked.data.get('code'), 'APP_UPDATE_REQUIRED')

        # 4) السماح الكامل للنسخة الأحدث (HTTP_X_APP_BUILD=25)
        self.client.force_authenticate(user=self.student_user)
        ok_api = self.client.get(
            reverse('api_v1_student_dashboard'),
            HTTP_X_APP_BUILD='25',
        )
        self.assertEqual(ok_api.status_code, 200)

    def test_21_web_device_fingerprinting_limit_and_trusted_devices_ui(self):
        from django.test import Client
        from teachers.models import CoursePackage
        from students.models import PackageEnrollment
        from .models import PlaybackSession

        policy = SecurityPolicyConfig.load()
        policy.student_device_limit = 2
        policy.enforce_device_limits = True
        policy.enforce_single_playback_session = True
        policy.save()

        # 1) متصفح أول: تسجيل جهاز الويب تلقائياً وإصدار كوكي موقّع وتحديث بصمة fp_v1
        b1 = Client(
            HTTP_USER_AGENT='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0.0.0',
        )
        b1.force_login(self.student_user)
        resp1 = b1.get(reverse('student_dashboard'))
        self.assertEqual(resp1.status_code, 200)
        self.assertIn('ta3alm_web_inst_id', b1.cookies)

        web_devices = RegisteredDevice.objects.filter(
            user=self.student_user,
            package_name='web.ta3alm.online',
            is_active=True,
        )
        self.assertEqual(web_devices.count(), 1)

        sync_resp = b1.post(
            reverse('web_device_traits_sync'),
            data=json.dumps({
                'cpu_arch': 'Win32',
                'cpu_info': '8 cores',
                'gpu_renderer': 'ANGLE (NVIDIA RTX)',
                'gpu_vendor': 'Google Inc.',
                'screen_resolution': '1920x1080',
                'timezone': 'Africa/Cairo',
                'webdriver_detected': True,
            }),
            content_type='application/json',
        )
        self.assertEqual(sync_resp.status_code, 200)
        sync_data = json.loads(sync_resp.content.decode('utf-8'))
        self.assertTrue(sync_data.get('ok'))
        self.assertEqual(sync_data.get('trust_status'), DeviceTrustStatus.TRUSTED)
        self.assertTrue(
            DeviceSecurityEvent.objects.filter(
                user=self.student_user,
                event_type='automated_browser_webdriver',
            ).exists()
        )

        # 2) متصفح ثانٍ: مسموح ضمن الحد (2)
        b2 = Client(
            HTTP_USER_AGENT='Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Safari/605.1.15',
        )
        b2.force_login(self.student_user)
        resp2 = b2.get(reverse('student_dashboard'))
        self.assertEqual(resp2.status_code, 200)
        self.assertEqual(
            RegisteredDevice.objects.filter(user=self.student_user, is_active=True).count(),
            2,
        )

        # 3) متصفح ثالث: يُمنع بسبب حد الأجهزة ويُعاد توجيهه لشاشة الأجهزة المتصلة
        b3 = Client(
            HTTP_USER_AGENT='Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0',
        )
        b3.force_login(self.student_user)
        resp3 = b3.get(reverse('student_dashboard'))
        self.assertEqual(resp3.status_code, 302)
        self.assertIn(reverse('web_trusted_devices'), resp3['Location'])

        dev_page = b3.get(reverse('web_trusted_devices'))
        self.assertEqual(dev_page.status_code, 200)

        # إلغاء تفويض المتصفح الأول من واجهة الويب يحرر مقعدًا ويسمح للمتصفح الثالث تلقائيًا
        dev1 = RegisteredDevice.objects.filter(
            user=self.student_user,
            package_name='web.ta3alm.online',
            is_active=True,
        ).order_by('id').first()
        revoke_resp = b3.post(
            reverse('web_trusted_devices'),
            {'action': 'revoke', 'device_uuid': str(dev1.device_uuid)},
        )
        self.assertEqual(revoke_resp.status_code, 302)
        self.assertEqual(b3.get(reverse('student_dashboard')).status_code, 200)

        # المتصفح الأول يُطرد على الفور عند أي طلب تالٍ
        b1_after = b1.get(reverse('student_dashboard'))
        self.assertEqual(b1_after.status_code, 302)

        # 4) حظر الماك (b2) واللينكس (b3) عن المحاضرات عبر الويب، والسماح لآيفون وآيباد فقط + نبض التزامن 409
        pkg = CoursePackage.objects.create(
            teacher=self.teacher,
            title='Web Security Package',
            grade='3_sec',
            description='Pkg for playback concurrency test',
            price=250,
            view_limit=5,
            is_active=True,
        )
        pkg.lectures.add(self.lecture)
        PackageEnrollment.objects.create(student=self.student, package=pkg, is_paid=True)

        watch_url = reverse('watch_package_lecture', args=[pkg.id, self.lecture.id])
        # متصفح الماك و اللينكس يُمنعان صراحةً بـ 403 عن فتح المحاضرة
        self.assertEqual(b2.get(watch_url).status_code, 403)
        self.assertEqual(b3.get(watch_url).status_code, 403)

        # رفع حد الأجهزة مؤقتاً لاختبار تزامن التشغيل بين متصفحي iPhone و iPad حقيقيين
        policy.student_device_limit = 4
        policy.save()

        ios1 = Client(
            HTTP_USER_AGENT='Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
        )
        ios1.force_login(self.student_user)
        self.assertEqual(ios1.get(reverse('student_dashboard')).status_code, 200)
        self.assertEqual(
            ios1.post(
                reverse('web_device_traits_sync'),
                data=json.dumps({
                    'canvas_hash': 'ios1_canvas',
                    'webgl_hash': 'ios1_webgl',
                    'audio_hash': 'ios1_audio',
                    'webgl_vendor': 'Apple Inc.',
                    'webgl_renderer': 'Apple GPU',
                    'navigator_platform': 'iPhone',
                    'max_touch_points': 5,
                    'touch_support': True,
                    'color_depth': 24,
                    'languages': 'ar-EG,ar',
                    'screen_resolution': '390x844',
                }),
                content_type='application/json',
            ).status_code,
            200,
        )

        ios2 = Client(
            HTTP_USER_AGENT='Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
        )
        ios2.force_login(self.student_user)
        self.assertEqual(ios2.get(reverse('student_dashboard')).status_code, 200)
        self.assertEqual(
            ios2.post(
                reverse('web_device_traits_sync'),
                data=json.dumps({
                    'canvas_hash': 'ios2_canvas',
                    'webgl_hash': 'ios2_webgl',
                    'audio_hash': 'ios2_audio',
                    'webgl_vendor': 'Apple Inc.',
                    'webgl_renderer': 'Apple GPU',
                    'navigator_platform': 'iPad',
                    'max_touch_points': 5,
                    'touch_support': True,
                    'color_depth': 24,
                    'languages': 'ar-EG,ar',
                    'screen_resolution': '820x1180',
                }),
                content_type='application/json',
            ).status_code,
            200,
        )

        w_ios1 = ios1.get(watch_url)
        self.assertEqual(w_ios1.status_code, 200)
        sess_ios1 = PlaybackSession.objects.filter(
            user=self.student_user, lecture=self.lecture, status='active'
        ).latest('id')

        w_ios2 = ios2.get(watch_url)
        self.assertEqual(w_ios2.status_code, 200)
        sess_ios1.refresh_from_db()
        self.assertEqual(sess_ios1.status, 'revoked')

        # نبض الجلسة القديمة يُرفض بـ 409
        hb_old = ios1.post(
            reverse('web_lecture_heartbeat', args=[self.lecture.id]),
            data=json.dumps({'session_id': str(sess_ios1.session_id)}),
            content_type='application/json',
        )
        self.assertEqual(hb_old.status_code, 409)

    def test_22_web_vulnerabilities_remediation_idor_payment_and_exam_auth(self):
        from django.core.files.uploadedfile import SimpleUploadedFile
        from django.test import Client
        from core.models import ManualPayment, Notification
        from dashboard_admin.views import _sanitize_email_html
        from exams.models import Exam, Question
        from teachers.models import CoursePackage, TeacherProfile
        from students.models import PackageEnrollment

        # 1) رفض Paymob callback بدون توقيع HMAC صحيح
        pkg = CoursePackage.objects.create(
            teacher=self.teacher,
            title='Checkout Hardened Pkg',
            grade='3_sec',
            description='Protected checkout test',
            price=450,
            is_active=True,
        )
        pkg.lectures.add(self.lecture)

        stu_client = Client()
        stu_client.force_login(self.student_user)
        sess = stu_client.session
        sess['buying_package_id'] = pkg.id
        sess.save()

        forged_cb = stu_client.get(reverse('payment_callback') + '?success=true&id=99999')
        self.assertEqual(forged_cb.status_code, 403)
        self.assertFalse(
            PackageEnrollment.objects.filter(student=self.student, package=pkg, is_paid=True).exists()
        )

        # 2) منع التلاعب بالسعر في صفحة الدفع اليدوي (اعتماد سعر قاعدة البيانات)
        import io
        from PIL import Image
        buf = io.BytesIO()
        Image.new('RGB', (10, 10), color='blue').save(buf, format='PNG')
        buf.seek(0)
        fake_receipt = SimpleUploadedFile('receipt.png', buf.read(), content_type='image/png')
        checkout_resp = stu_client.post(
            reverse('manual_checkout') + f'?type=package&id={pkg.id}&amount=1',
            {
                'phone_number': '01012345678',
                'receipt_image': fake_receipt,
            },
        )
        self.assertEqual(checkout_resp.status_code, 302)
        mp = ManualPayment.objects.get(user=self.student_user, payment_type='package', target_id=pkg.id)
        self.assertEqual(mp.amount, 450)

        # 3) منع الطالب من مشاهدة محاضرة غير مرتبطة بالباقة المدفوعة (IDOR)
        PackageEnrollment.objects.create(student=self.student, package=pkg, is_paid=True)
        other_lecture = Lecture.objects.create(
            group=self.group,
            title='Unlinked Lecture',
            video_link='https://origin.private.ta3alm.online/raw/other.mp4',
            is_active=True,
        )
        unlinked_watch = stu_client.get(
            reverse('watch_package_lecture', args=[pkg.id, other_lecture.id])
        )
        self.assertEqual(unlinked_watch.status_code, 302)

        # 4) منع معلم آخر من استيراد محاضرة لا يملكها أو تعديل سؤال في امتحان حزمة أخرى
        other_t_user = User.objects.create_user(
            username='other_teacher_sec',
            email='other_teacher_sec@example.com',
            password='Password123!',
            role='teacher',
            first_name='Adel',
            phone='01055554444',
        )
        EmailVerification.objects.create(
            user=other_t_user,
            code='654321',
            is_verified=True,
            expires_at=timezone.now() + timedelta(days=1),
        )
        other_teacher = TeacherProfile.objects.create(
            user=other_t_user,
            subject=self.subject,
            current_plan=self.plan,
            subscription_end_date=timezone.now() + timedelta(days=30),
        )
        other_pkg = CoursePackage.objects.create(
            teacher=other_teacher,
            title='Other Teacher Pkg',
            grade='3_sec',
            description='Owned by other teacher',
            price=200,
        )
        pkg_exam = Exam.objects.create(group=None, title='Pkg Exam', duration_minutes=30, is_active=True)
        pkg.exams.add(pkg_exam)
        question = Question.objects.create(
            exam=pkg_exam,
            text='Original Protected Question?',
            option_a='A',
            option_b='B',
            option_c='C',
            option_d='D',
            correct_answer='A',
            marks=2,
        )

        other_t_client = Client()
        other_t_client.force_login(other_t_user)

        other_t_client.post(
            reverse('import_package_content', args=[other_pkg.id]),
            {'lecture_ids': [str(self.lecture.id)]},
        )
        self.assertFalse(other_pkg.lectures.filter(id=self.lecture.id).exists())

        edit_q_resp = other_t_client.post(
            reverse('edit_question_page', args=[question.id]),
            {
                'text': 'Hacked Question!',
                'option_a': 'A',
                'option_b': 'B',
                'option_c': 'C',
                'option_d': 'D',
                'correct_answer': 'B',
                'marks': '10',
            },
        )
        self.assertEqual(edit_q_resp.status_code, 302)
        question.refresh_from_db()
        self.assertEqual(question.text, 'Original Protected Question?')

        # 5) منع Open Redirect في الإشعارات وتنقية HTML البريد
        notif = Notification.objects.create(
            recipient=self.student_user,
            title='Notice',
            message='Msg',
            link='https://evil.example.com/phish',
        )
        notif_resp = stu_client.get(reverse('read_notification', args=[notif.id]))
        self.assertEqual(notif_resp.status_code, 302)
        self.assertNotIn('evil.example.com', notif_resp['Location'])

        sanitized = _sanitize_email_html(
            '<p onclick="alert(1)">Hello</p><script>evil()</script><a href="javascript:alert(2)">x</a>'
        )
        self.assertNotIn('<script', sanitized.lower())
        self.assertNotIn('onclick=', sanitized.lower())
        self.assertNotIn('javascript:', sanitized.lower())

    def test_23_app_links_assetlinks_and_github_release_apk_settings(self):
        import os
        from django.conf import settings as django_settings
        from django.core.files.uploadedfile import SimpleUploadedFile
        from django.test import Client
        from core.models import SiteSetting

        # 1) التحقق من استثناء /.well-known/assetlinks.json من التحويل الإجباري
        self.assertTrue(hasattr(django_settings, 'SECURE_REDIRECT_EXEMPT'))
        self.assertTrue(
            any('assetlinks' in pat for pat in django_settings.SECURE_REDIRECT_EXEMPT)
        )

        # 2) دمج بصمات SHA-256 من قاعدة البيانات ومتغيرات البيئة وعملها حتى في وضع الصيانة
        site_settings = SiteSetting.load()
        db_fp_raw = 'aa11' * 16
        env_fp_raw = 'BB22' * 16
        site_settings.is_maintenance_mode = True
        site_settings.android_assetlinks_sha256 = db_fp_raw
        site_settings.save()

        prev_env = os.environ.get('ANDROID_ASSETLINKS_SHA256')
        os.environ['ANDROID_ASSETLINKS_SHA256'] = env_fp_raw
        try:
            anon = Client()
            al_resp = anon.get('/.well-known/assetlinks.json')
            self.assertEqual(al_resp.status_code, 200)
            payload = al_resp.json()
            self.assertEqual(len(payload), 2)
            fps = payload[0]['target']['sha256_cert_fingerprints']
            self.assertIn(SiteSetting.format_sha256_colons(db_fp_raw), fps)
            self.assertIn(SiteSetting.format_sha256_colons(env_fp_raw), fps)
        finally:
            if prev_env is None:
                os.environ.pop('ANDROID_ASSETLINKS_SHA256', None)
            else:
                os.environ['ANDROID_ASSETLINKS_SHA256'] = prev_env
            site_settings.is_maintenance_mode = False
            site_settings.save()

        # 3) أولوية رابط GitHub Releases على الملف المرفوع في AppUpdateDownloadAPIView
        import tempfile
        from django.test import override_settings

        github_apk_url = 'https://github.com/ta3alm/releases/releases/download/v1.1.0/app-release.apk'
        with tempfile.TemporaryDirectory() as tmp_media:
            with override_settings(
                STORAGES={
                    'default': {
                        'BACKEND': 'django.core.files.storage.FileSystemStorage',
                        'OPTIONS': {'location': tmp_media},
                    },
                    'staticfiles': django_settings.STORAGES['staticfiles'],
                }
            ):
                site_settings.android_apk_file = SimpleUploadedFile('old.apk', b'PK\x03\x04old')
                site_settings.android_apk_url = github_apk_url
                site_settings.android_latest_version_code = 2
                site_settings.android_min_required_version_code = 2
                site_settings.android_latest_version_name = '1.1.0'
                site_settings.save()

                dl_resp = self.client.get(reverse('api_v1_app_update_download'))
                self.assertEqual(dl_resp.status_code, 302)
                self.assertEqual(dl_resp['Location'], github_apk_url)

                # 4) إدارة الرابط والإصدارات عبر صفحة الويب المخصصة و API الإدارة
                self.student_user.is_superuser = True
                self.student_user.is_staff = True
                self.student_user.save(update_fields=['is_superuser', 'is_staff'])

                owner_web = Client()
                owner_web.force_login(self.student_user)
                page_resp = owner_web.get(reverse('admin_panel:app_release_settings'))
                self.assertEqual(page_resp.status_code, 200)

                new_github_url = 'https://github.com/ta3alm/releases/releases/download/v1.2.0/app-release.apk'
                post_resp = owner_web.post(
                    reverse('admin_panel:app_release_settings'),
                    {
                        'android_apk_url': new_github_url,
                        'android_latest_version_code': 3,
                        'android_min_required_version_code': 3,
                        'android_latest_version_name': '1.2.0',
                        'android_force_update': '1',
                        'android_apk_sha256': 'sha256:' + ('CC33' * 16),
                        'android_assetlinks_sha256': 'dd44' * 16,
                        'android_update_release_notes': 'GitHub Release 1.2.0',
                        'clear_uploaded_apk': '1',
                    },
                )
                self.assertEqual(post_resp.status_code, 302)
                site_settings.refresh_from_db()
                self.assertEqual(site_settings.android_apk_url, new_github_url)
                self.assertEqual(site_settings.android_apk_sha256, 'cc33' * 16)
                self.assertEqual(site_settings.android_latest_version_code, 3)
                self.assertFalse(bool(site_settings.android_apk_file))

                # التحقق عبر AdminDashboardAPIView (GET و POST)
                self.client.force_authenticate(user=self.student_user)
                api_dash = self.client.get(reverse('api_v1_admin_dashboard'))
                self.assertEqual(api_dash.status_code, 200)
                self.assertEqual(api_dash.data['app_release_admin']['android_apk_url'], new_github_url)
                self.assertIn(
                    SiteSetting.format_sha256_colons('dd44' * 16),
                    api_dash.data['app_release_admin']['effective_assetlinks_fingerprints'],
                )

                api_post_url = 'https://github.com/ta3alm/releases/releases/download/v1.3.0/app-release.apk'
                api_post = self.client.post(
                    reverse('api_v1_admin_dashboard'),
                    {
                        'android_apk_url': api_post_url,
                        'android_latest_version_code': 4,
                        'android_min_required_version_code': 4,
                        'android_latest_version_name': '1.3.0',
                        'android_assetlinks_sha256': 'ee55' * 16,
                    },
                    format='json',
                )
                self.assertEqual(api_post.status_code, 200)
                site_settings.refresh_from_db()
                self.assertEqual(site_settings.android_apk_url, api_post_url)
                self.assertEqual(site_settings.android_latest_version_code, 4)

    def test_24_strict_web_fingerprint_cookie_hijack_and_trait_drift(self):
        from django.test import Client
        from .device_security_service import check_device_allowed
        from .models import PlaybackSession

        policy = SecurityPolicyConfig.load()
        policy.student_device_limit = 2
        policy.enforce_device_limits = True
        policy.save()

        win_chrome = Client(
            HTTP_USER_AGENT='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/129.0.0.0 Safari/537.36',
            HTTP_ACCEPT_LANGUAGE='ar-EG,ar;q=0.9',
        )
        win_chrome.force_login(self.student_user)
        self.assertEqual(win_chrome.get(reverse('student_dashboard')).status_code, 200)

        # مزامنة بصمة عتاد حقيقية أولية للمتصفح (تثري الجهاز ببيانات Canvas/WebGL/Audio)
        traits_payload = {
            'canvas_hash': 'win_canvas_abc123',
            'webgl_hash': 'win_webgl_xyz789',
            'audio_hash': 'win_audio_def456',
            'webgl_vendor': 'NVIDIA Corporation',
            'webgl_renderer': 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0)',
            'navigator_platform': 'Win32',
            'max_touch_points': 0,
            'touch_support': False,
            'color_depth': 24,
            'languages': 'ar-EG,ar',
            'screen_resolution': '1920x1080',
            'hardware_concurrency': '12',
            'device_memory': '16',
        }
        sync_ok = win_chrome.post(
            reverse('web_device_traits_sync'),
            data=json.dumps(traits_payload),
            content_type='application/json',
        )
        self.assertEqual(sync_ok.status_code, 200)
        dev = RegisteredDevice.objects.get(user=self.student_user, is_active=True)

        # استنساخ الكوكيز (Session + ta3alm_web_did) على متصفح مختلف تماماً (Linux Firefox)
        hijack = Client(
            HTTP_USER_AGENT='Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0',
            HTTP_ACCEPT_LANGUAGE='en-US,en;q=0.5',
        )
        for cname, morsel in win_chrome.cookies.items():
            hijack.cookies[cname] = morsel.value

        hijack_resp = hijack.get(reverse('student_dashboard'))
        self.assertEqual(hijack_resp.status_code, 302)
        self.assertIn(reverse('account_login'), hijack_resp['Location'])

        dev.refresh_from_db()
        self.assertEqual(dev.trust_status, DeviceTrustStatus.RESTRICTED)
        self.assertFalse(check_device_allowed(self.student_user, dev.installation_id)[0])
        self.assertFalse(DeviceSession.objects.filter(device=dev, status='active').exists())

        # متصفح ثانٍ: إثراء البصمة ثم تغيير قيم Canvas/WebGL فجأة يؤدي لتجميد الجلسة فوراً (403)
        RegisteredDevice.objects.filter(user=self.student_user).delete()
        win2 = Client(
            HTTP_USER_AGENT='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/129.0.0.0 Safari/537.36',
        )
        win2.force_login(self.student_user)
        self.assertEqual(win2.get(reverse('student_dashboard')).status_code, 200)
        self.assertEqual(
            win2.post(
                reverse('web_device_traits_sync'),
                data=json.dumps(traits_payload),
                content_type='application/json',
            ).status_code,
            200,
        )
        dev2 = RegisteredDevice.objects.get(user=self.student_user, is_active=True)

        pb_active = PlaybackSession.objects.create(
            user=self.student_user,
            lecture=self.lecture,
            device_id=dev2.installation_id,
            status='active',
            expires_at=timezone.now() + timedelta(minutes=20),
        )

        tampered = dict(traits_payload)
        tampered['canvas_hash'] = 'tampered_canvas_999'
        tampered['webgl_renderer'] = 'Mesa SwiftShader LLVM'
        tampered_resp = win2.post(
            reverse('web_device_traits_sync'),
            data=json.dumps(tampered),
            content_type='application/json',
        )
        self.assertEqual(tampered_resp.status_code, 403)
        self.assertEqual(tampered_resp.json().get('code'), 'WEB_FINGERPRINT_MISMATCH')

        dev2.refresh_from_db()
        pb_active.refresh_from_db()
        self.assertEqual(dev2.trust_status, DeviceTrustStatus.RESTRICTED)
        self.assertFalse(check_device_allowed(self.student_user, dev2.installation_id)[0])
        self.assertFalse(DeviceSession.objects.filter(device=dev2, status='active').exists())
        self.assertEqual(pb_active.status, 'revoked')

    def test_25_web_lectures_strict_iphone_ipad_only_and_anti_f12(self):
        from django.test import Client
        from teachers.models import CoursePackage, VideoCode
        from students.models import PackageEnrollment

        policy = SecurityPolicyConfig.load()
        policy.student_device_limit = 10
        policy.save()

        pkg = CoursePackage.objects.create(
            teacher=self.teacher,
            title='iOS Only Web Pkg',
            grade='3_sec',
            description='Strict iOS-only web gate test',
            price=300,
            view_limit=5,
            is_active=True,
        )
        pkg.lectures.add(self.lecture)
        PackageEnrollment.objects.create(student=self.student, package=pkg, is_paid=True)
        VideoCode.objects.create(lecture=self.lecture, code='IOSGATE1', max_views=5)

        group_watch_html = reverse('student_watch_lecture', args=[self.lecture.id])
        pkg_watch_html = reverse('watch_package_lecture', args=[pkg.id, self.lecture.id])
        pkg_content_html = reverse('my_package_content', args=[pkg.id])
        group_content_html = reverse('student_group_content', args=[self.group.id])

        # 1) متصفحات ممنوعة: Windows Chrome، Mac Safari، Mac Chrome، Android Chrome، ومحاكاة F12 لـ iPhone
        blocked_clients = [
            (
                'windows_chrome',
                {
                    'HTTP_USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/129.0.0.0 Safari/537.36',
                },
                None,
            ),
            (
                'mac_safari',
                {
                    'HTTP_USER_AGENT': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15',
                },
                {
                    'navigator_platform': 'MacIntel',
                    'max_touch_points': 0,
                    'touch_support': False,
                    'webgl_vendor': 'Apple',
                    'webgl_renderer': 'Apple M2',
                },
            ),
            (
                'mac_chrome',
                {
                    'HTTP_USER_AGENT': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/129.0.0.0 Safari/537.36',
                },
                None,
            ),
            (
                'android_web',
                {
                    'HTTP_USER_AGENT': 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/129.0.0.0 Mobile Safari/537.36',
                },
                None,
            ),
            (
                'f12_devtools_spoof',
                {
                    'HTTP_USER_AGENT': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1',
                    'HTTP_SEC_CH_UA_PLATFORM': '"Windows"',
                },
                None,
            ),
        ]

        for label, hdrs, sync_traits in blocked_clients:
            c = Client(**hdrs)
            c.force_login(self.student_user)
            dash_resp = c.get(reverse('student_dashboard'))
            if label == 'f12_devtools_spoof':
                # تزييف Sec-CH-UA-Platform مع UA آيفون يُرفض فوراً عند التسجيل نفسه (302/403)
                self.assertIn(dash_resp.status_code, (302, 403), label)
                self.assertIn(c.get(group_watch_html).status_code, (302, 403), f'{label} group_watch')
                self.assertIn(c.get(pkg_watch_html).status_code, (302, 403), f'{label} pkg_watch')
            else:
                self.assertEqual(dash_resp.status_code, 200, label)
                if sync_traits:
                    c.post(
                        reverse('web_device_traits_sync'),
                        data=json.dumps(sync_traits),
                        content_type='application/json',
                    )
                self.assertEqual(c.get(group_watch_html).status_code, 403, f'{label} group_watch')
                self.assertEqual(c.get(pkg_watch_html).status_code, 403, f'{label} pkg_watch')
                gc = c.get(group_content_html)
                self.assertEqual(gc.status_code, 200, label)
                self.assertFalse(gc.context['web_lectures_allowed'], label)
                self.assertEqual(list(gc.context['lectures']), [], label)
                pc = c.get(pkg_content_html)
                self.assertEqual(pc.status_code, 200, label)
                self.assertFalse(pc.context['web_lectures_allowed'], label)
                self.assertEqual(list(pc.context['lectures']), [], label)

            # التحقق أيضاً على DRF API عند إرسال X-Client-Platform: web
            self.client.force_authenticate(user=self.student_user)
            api_auth = self.client.post(
                reverse('api_v1_video_authorize', args=[self.lecture.id]),
                {'package_id': pkg.id, 'platform': 'web'},
                HTTP_X_CLIENT_PLATFORM='web',
                **hdrs,
            )
            self.assertEqual(api_auth.status_code, 403, f'{label} api_authorize')
            self.assertTrue(api_auth.data.get('blocked'), label)
            api_gc = self.client.get(
                reverse('api_v1_student_group_content', args=[self.group.id]),
                HTTP_X_CLIENT_PLATFORM='web',
                **hdrs,
            )
            self.assertEqual(api_gc.status_code, 200, label)
            self.assertTrue(api_gc.data.get('lectures_blocked'), label)
            self.assertEqual(api_gc.data.get('lectures'), [], label)
            api_cw = self.client.get(
                reverse('api_v1_video_continue_watching'),
                HTTP_X_CLIENT_PLATFORM='web',
                **hdrs,
            )
            self.assertEqual(api_cw.status_code, 200, label)
            self.assertTrue(api_cw.data.get('lectures_blocked'), label)
            self.assertEqual(api_cw.data.get('items'), [], label)

        # 2) محاكاة F12 لـ iPhone مع إرسال بصمة GPU ويندوز -> يُرفض بـ 403
        self.client.force_authenticate(user=self.student_user)
        RegisteredDevice.objects.filter(user=self.student_user).update(is_active=False)
        spoof_web = Client(
            HTTP_USER_AGENT='Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1',
        )
        spoof_web.force_login(self.student_user)
        spoof_web.get(reverse('student_dashboard'))
        spoof_sync = spoof_web.post(
            reverse('web_device_traits_sync'),
            data=json.dumps({
                'navigator_platform': 'Win32',
                'max_touch_points': 5,
                'touch_support': True,
                'webgl_renderer': 'ANGLE (NVIDIA GeForce Direct3D11)',
            }),
            content_type='application/json',
        )
        self.assertEqual(spoof_sync.status_code, 403)
        self.assertIn(spoof_web.get(pkg_watch_html).status_code, (302, 403))

        # 3) أجهزة مسموحة على الويب: iPhone حقيقي و iPadOS Desktop Safari الحقيقي
        iphone = Client(
            HTTP_USER_AGENT='Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
        )
        iphone.force_login(self.student_user)
        iphone.get(reverse('student_dashboard'))
        sync_iphone = iphone.post(
            reverse('web_device_traits_sync'),
            data=json.dumps({
                'navigator_platform': 'iPhone',
                'max_touch_points': 5,
                'touch_support': True,
                'webgl_vendor': 'Apple Inc.',
                'webgl_renderer': 'Apple GPU',
                'canvas_hash': 'iphone_c1',
                'webgl_hash': 'iphone_w1',
                'audio_hash': 'iphone_a1',
            }),
            content_type='application/json',
        )
        self.assertTrue(sync_iphone.json().get('ios_lecture_allowed'))
        self.assertEqual(iphone.get(pkg_watch_html).status_code, 200)

        ipad_desktop = Client(
            HTTP_USER_AGENT='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
        )
        ipad_desktop.force_login(self.student_user)
        ipad_desktop.get(reverse('student_dashboard'))
        sync_ipad = ipad_desktop.post(
            reverse('web_device_traits_sync'),
            data=json.dumps({
                'navigator_platform': 'MacIntel',
                'max_touch_points': 5,
                'touch_support': True,
                'webgl_vendor': 'Apple Inc.',
                'webgl_renderer': 'Apple GPU',
                'canvas_hash': 'ipad_c1',
                'webgl_hash': 'ipad_w1',
                'audio_hash': 'ipad_a1',
            }),
            content_type='application/json',
        )
        self.assertTrue(sync_ipad.json().get('ios_lecture_allowed'))
        self.assertEqual(ipad_desktop.get(pkg_watch_html).status_code, 200)

        # 4) تطبيق الأندرويد الأصلي يعمل بشكل طبيعي
        inst_android = 'inst_android_native_gate_0001'
        login_res = self._login_with_device(installation_id=inst_android)
        self.assertEqual(login_res.status_code, 200)
        android_token = login_res.data['access']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {android_token}')
        native_gc = self.client.get(
            reverse('api_v1_student_group_content', args=[self.group.id]),
            HTTP_X_DEVICE_ID=inst_android,
            HTTP_USER_AGENT='Dart/3.5 (dart:io)',
        )
        self.assertEqual(native_gc.status_code, 200)
        self.assertFalse(native_gc.data.get('lectures_blocked'))
        self.assertEqual(len(native_gc.data.get('lectures')), 1)





