"""
api_v1/tests_video_security.py
اختبارات شاملة لنظام حماية الفيديو، التوكنات قصيرة العمر، إبطال الجلسات المتزامنة،
تتبع التقدم والعلامات المرجعية، وحماية Google Play Integrity.
"""
from datetime import timedelta
import json

from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APITestCase

from accounts.models import StudentProfile
from core.models import Subject
from students.models import Enrollment, PackageEnrollment
from teachers.models import CoursePackage, Group, Lecture, SubscriptionPlan, TeacherProfile, VideoCode

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
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]['relation'], ['delegate_permission/common.handle_all_urls'])
        self.assertEqual(body[0]['target']['package_name'], 'online.ta3alm.ta3alm_flutter')
        self.assertEqual(body[0]['target']['sha256_cert_fingerprints'], [':'.join(['AB'] * 32)])
