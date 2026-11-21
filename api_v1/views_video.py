"""api_v1.views_video
Extracted from api_v1/views_video.py.
"""
from __future__ import annotations

import mimetypes
import os
from datetime import timedelta
from pathlib import Path
import jwt
from django.conf import settings
from django.http import (
    FileResponse,
    HttpResponse,
)
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import (
    AllowAny,
    IsAuthenticated,
)
from rest_framework.response import Response
from rest_framework.views import APIView
from teachers.models import (
    Lecture,
    PDFFile,
)
from api_v1.device_security_service import (
    check_device_allowed,
    check_web_ios_only_lecture_access,
    detect_account_sharing,
    record_device_activity,
    record_security_event,
)
from api_v1.integrity_service import (
    get_integrity_policy_mode,
    issue_integrity_challenge,
    verify_and_record_integrity,
)
from api_v1.models import (
    DeviceIntegrityRecord,
    DeviceTrustStatus,
    PlaybackSession,
    RegisteredDevice,
    VideoBookmark,
    VideoProgress,
)
from api_v1.permissions import IsNotBanned
from api_v1.serializers import (
    LectureSerializer,
    PDFFileSerializer,
)
from api_v1.video_security import (
    HEARTBEAT_INTERVAL_SECONDS,
    PLAYBACK_TOKEN_TTL_SECONDS,
    build_watermark_payload,
    clear_watch_window,
    create_or_rotate_playback_session,
    decode_playback_token,
    detect_and_record_anomaly,
    issue_playback_token,
    log_security_event,
    resolve_signed_playback_source,
)

from api_v1.services.video_access import (
    _check_user_lecture_entitlement,
    _neighbor_lectures_payload,
)
from api_v1.views.video.throttles import (
    IntegrityCheckThrottle,
    VideoAuthorizeThrottle,
    VideoHeartbeatThrottle,
)


def _check_required_integrity(request, user, device_id: str) -> tuple[bool, str, str | None]:
    """
    يتحقق من حالة Play Integrity الأخيرة للجهاز إذا كان فحص النزاهة إلزامياً في البيئة.
    """
    require_integrity = os.environ.get('VIDEO_REQUIRE_PLAY_INTEGRITY', 'False').lower() == 'true'
    latest = (
        DeviceIntegrityRecord.objects.filter(device_id=device_id)
        .filter(verified_at__gte=timezone.now() - timedelta(hours=12))
        .first()
    )
    if latest:
        if latest.policy_decision == 'block':
            return False, 'blocked', 'تم إيقاف التشغيل لأن التطبيق أو الجهاز لم يجتز فحص سلامة التشغيل (Play Integrity).'
        return True, latest.policy_decision, None

    if require_integrity and get_integrity_policy_mode() in ('strict', 'balanced'):
        return False, 'missing', 'مطلوب التحقق من سلامة التطبيق قبل تشغيل الفيديو المحمي.'

    return True, 'unverified', None


class VideoAuthorizeAPIView(APIView):
    """
    تصريح تشغيل الفيديو الآمن + إنشاء جلسة تشغيل + إصدار توكن قصير العمر + روابط موقعة.
    يدعم GET و POST لتمرير device_id أو كود التفعيل أو package_id.
    """
    permission_classes = [IsAuthenticated, IsNotBanned]
    throttle_classes = [VideoAuthorizeThrottle]

    def get(self, request, lecture_id):
        return self._handle(request, lecture_id)

    def post(self, request, lecture_id):
        return self._handle(request, lecture_id)

    def _handle(self, request, lecture_id):
        ios_access = check_web_ios_only_lecture_access(request, request.user)
        if not ios_access.get('allowed'):
            return Response(
                {
                    'error': ios_access.get('error'),
                    'blocked': True,
                    'code': ios_access.get('code') or 'WEB_LECTURES_IOS_ONLY',
                    'device_kind': ios_access.get('device_kind'),
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        if (
            hasattr(request.user, 'requires_email_verification')
            and request.user.requires_email_verification()
        ):
            return Response(
                {
                    'error': 'يرجى تأكيد حسابك برمز التحقق (OTP) أولاً.',
                    'code': 'EMAIL_VERIFICATION_REQUIRED',
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        lecture = get_object_or_404(Lecture, id=lecture_id, is_active=True)

        raw_pkg = request.data.get('package_id') or request.query_params.get('package_id')
        package_id = int(raw_pkg) if str(raw_pkg or '').isdigit() else None
        submitted_code = str(request.data.get('code') or '').strip()
        device_id = str(
            request.data.get('device_id')
            or request.query_params.get('device_id')
            or request.META.get('HTTP_X_DEVICE_ID')
            or f"user-{request.user.id}"
        ).strip()
        device_fingerprint = str(request.data.get('device_fingerprint') or '').strip()
        client_platform = str(request.data.get('platform') or request.query_params.get('platform') or 'android').strip()
        app_version = str(request.data.get('app_version') or request.META.get('HTTP_X_APP_VERSION') or '').strip()
        consume_view = True

        if detect_and_record_anomaly(request, request.user, lecture, device_id=device_id):
            return Response(
                {'error': 'تم رصد طلبات تشغيل متكررة بشكل غير طبيعي. يرجى الانتظار قليلاً.'},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        dev_allowed, dev_err_code, dev_err_msg = check_device_allowed(request.user, device_id)
        if not dev_allowed:
            record_security_event(
                event_type=(dev_err_code or 'device_access_denied').lower(),
                severity='high',
                risk_score=70,
                user=request.user,
                installation_id=device_id,
                request=request,
                action_taken='denied_video_authorize',
                details={'lecture_id': lecture.id, 'code': dev_err_code, 'reason': dev_err_msg},
            )
            return Response(
                {'error': dev_err_msg, 'code': dev_err_code},
                status=status.HTTP_403_FORBIDDEN,
            )

        sharing_result = detect_account_sharing(
            request,
            request.user,
            lecture=lecture,
            installation_id=device_id,
        )
        if sharing_result.get('suspected') and len(sharing_result.get('signals', [])) >= 2:
            return Response(
                {
                    'error': 'تم تقييد التشغيل مؤقتاً للاشتباه في مشاركة الحساب من عدة أجهزة ومواقع متزامنة.',
                    'code': 'ACCOUNT_SHARING_RESTRICTED',
                    'sharing': sharing_result,
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        reg_device = RegisteredDevice.objects.filter(user=request.user, installation_id=device_id).first()
        record_device_activity(
            request=request,
            user=request.user,
            device=reg_device,
            activity_type='lecture_access',
            metadata={'lecture_id': lecture.id, 'installation_id': device_id},
        )

        integrity_ok, integrity_verdict, integrity_err = _check_required_integrity(request, request.user, device_id)
        if not integrity_ok:
            log_security_event(
                event_type='authorize_denied',
                user=request.user,
                lecture=lecture,
                severity='high',
                request=request,
                device_id=device_id,
                details={'reason': 'play_integrity', 'verdict': integrity_verdict},
            )
            return Response(
                {'error': integrity_err, 'code': 'INTEGRITY_REQUIRED', 'integrity_verdict': integrity_verdict},
                status=status.HTTP_403_FORBIDDEN,
            )

        allowed, ctx = _check_user_lecture_entitlement(
            request,
            lecture,
            package_id=package_id,
            submitted_code=submitted_code,
            consume_view=consume_view,
        )
        if not allowed:
            log_security_event(
                event_type='authorize_denied',
                user=request.user,
                lecture=lecture,
                severity='warning',
                request=request,
                device_id=device_id,
                details={'reason': 'entitlement', 'package_id': package_id},
            )
            return Response(ctx['payload'], status=ctx['status_code'])

        package = ctx.get('package')
        session, revoked_count = create_or_rotate_playback_session(
            request=request,
            user=request.user,
            lecture=lecture,
            package=package,
            device_id=device_id,
            device_fingerprint=device_fingerprint,
            client_platform=client_platform,
            app_version=app_version,
            integrity_verdict=integrity_verdict,
            view_window_expires_at=ctx.get('watch_window_expires_at'),
        )
        playback_token, expires_in = issue_playback_token(
            user_id=request.user.id,
            lecture_id=lecture.id,
            session=session,
        )
        source_payload = resolve_signed_playback_source(
            request=request,
            lecture=lecture,
            session=session,
            playback_token=playback_token,
            ttl_seconds=expires_in,
        )

        progress, _ = VideoProgress.objects.get_or_create(user=request.user, lecture=lecture)
        bookmarks = [
            {
                'id': b.id,
                'timestamp_seconds': b.timestamp_seconds,
                'title': b.title,
                'note': b.note,
                'created_at': b.created_at,
            }
            for b in VideoBookmark.objects.filter(user=request.user, lecture=lecture)
        ]

        if package:
            pdfs = package.pdfs.all().order_by('-created_at')
            course_info = {
                'type': 'package',
                'id': package.id,
                'title': package.title,
                'teacher_name': package.teacher.user.get_full_name() or package.teacher.user.username,
            }
        elif lecture.group:
            pdfs = lecture.group.pdfs.all().order_by('-created_at')
            course_info = {
                'type': 'group',
                'id': lecture.group.id,
                'title': lecture.group.name,
                'teacher_name': lecture.group.teacher.user.get_full_name() or lecture.group.teacher.user.username,
            }
        else:
            pdfs = PDFFile.objects.none()
            course_info = None

        prev_lec, next_lec = _neighbor_lectures_payload(lecture, package)
        watermark = build_watermark_payload(request.user, session)

        log_security_event(
            event_type='authorize_success',
            user=request.user,
            lecture=lecture,
            session_id=str(session.session_id),
            severity='info',
            request=request,
            device_id=device_id,
            details={
                'source_type': source_payload['source_type'],
                'revoked_previous_sessions': revoked_count,
                'integrity_verdict': integrity_verdict,
            },
        )

        lecture_data = LectureSerializer(
            lecture,
            context={'hide_raw_url_for_student': True},
        ).data

        return Response({
            'is_unlocked': True,
            'session_id': str(session.session_id),
            'playback_token': playback_token,
            'expires_in': expires_in,
            'heartbeat_interval_seconds': HEARTBEAT_INTERVAL_SECONDS,
            'revoked_other_sessions': revoked_count,
            'integrity_verdict': integrity_verdict,
            'lecture': lecture_data,
            'course_info': course_info,
            'source': source_payload,
            'watermark': watermark,
            'progress': {
                'position_seconds': progress.position_seconds,
                'duration_seconds': progress.duration_seconds or source_payload['duration_seconds'],
                'watched_seconds': progress.watched_seconds,
                'progress_percent': round(progress.progress_percent, 1),
                'is_completed': progress.is_completed,
                'preferred_speed': progress.preferred_speed,
            },
            'bookmarks': bookmarks,
            'attachments': PDFFileSerializer(pdfs, many=True, context={'request': request}).data,
            'previous_lecture': prev_lec,
            'next_lecture': next_lec,
            'code_info': ctx.get('code_info'),
            'view_limit': ctx.get('view_limit'),
            'remaining_views': ctx.get('remaining_views'),
            'points_just_awarded': ctx.get('points_just_awarded', False),
        })


class VideoHeartbeatAPIView(APIView):
    """التحقق الدوري من صلاحية الجلسة واكتشاف الجلسات المسحوبة أو المتزامنة."""
    permission_classes = [IsAuthenticated, IsNotBanned]
    throttle_classes = [VideoHeartbeatThrottle]

    def post(self, request, lecture_id):
        ios_access = check_web_ios_only_lecture_access(request, request.user)
        if not ios_access.get('allowed'):
            return Response(
                {
                    'error': ios_access.get('error'),
                    'blocked': True,
                    'code': ios_access.get('code') or 'WEB_LECTURES_IOS_ONLY',
                    'device_kind': ios_access.get('device_kind'),
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        raw_token = str(request.data.get('playback_token') or '').strip()
        session_id = str(request.data.get('session_id') or '').strip()
        device_id = str(request.data.get('device_id') or request.META.get('HTTP_X_DEVICE_ID') or '').strip()
        refresh_requested = bool(request.data.get('refresh_token', False))

        if not raw_token or not session_id:
            return Response(
                {'error': 'playback_token و session_id مطلوبان.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            claims = decode_playback_token(raw_token)
        except jwt.ExpiredSignatureError:
            return Response({'error': 'انتهت صلاحية تصريح التشغيل.', 'code': 'TOKEN_EXPIRED'}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({'error': 'توكن التشغيل غير صالح.', 'code': 'TOKEN_INVALID'}, status=status.HTTP_401_UNAUTHORIZED)

        if str(claims.get('sub')) != str(request.user.id) or int(claims.get('lec', 0)) != int(lecture_id):
            return Response({'error': 'عدم تطابق بيانات جلسة الفيديو.'}, status=status.HTTP_403_FORBIDDEN)

        session = PlaybackSession.objects.filter(session_id=session_id, user=request.user, lecture_id=lecture_id).first()
        if not session:
            return Response({'error': 'الجلسة غير موجودة.'}, status=status.HTTP_404_NOT_FOUND)

        if session.status == 'revoked':
            return Response(
                {'error': 'تم إيقاف هذه الجلسة بسبب فتح الفيديو على جهاز أو نافذة أخرى.', 'code': 'SESSION_REVOKED'},
                status=status.HTTP_409_CONFLICT,
            )

        if session.status != 'active' or session.expires_at <= timezone.now():
            return Response({'error': 'انتهت جلسة المشاهدة.', 'code': 'SESSION_EXPIRED'}, status=status.HTTP_401_UNAUTHORIZED)

        if device_id and session.device_id and session.device_id != device_id:
            return Response({'error': 'عدم تطابق الجهاز المرتبط بالجلسة.', 'code': 'DEVICE_MISMATCH'}, status=status.HTTP_403_FORBIDDEN)

        effective_device_id = device_id or session.device_id
        dev_allowed, dev_err_code, dev_err_msg = check_device_allowed(request.user, effective_device_id)
        if not dev_allowed:
            session.status = 'revoked'
            session.revoked_reason = (dev_err_code or 'device_not_allowed').lower()
            session.save(update_fields=['status', 'revoked_reason'])
            return Response(
                {'error': dev_err_msg, 'code': dev_err_code},
                status=status.HTTP_403_FORBIDDEN,
            )

        session.last_heartbeat_at = timezone.now()
        session.expires_at = timezone.now() + timedelta(seconds=max(PLAYBACK_TOKEN_TTL_SECONDS * 2, 300))
        response_data = {
            'status': 'active',
            'session_id': str(session.session_id),
            'server_time': timezone.now().isoformat(),
        }

        if refresh_requested:
            new_token, expires_in = issue_playback_token(
                user_id=request.user.id,
                lecture_id=lecture_id,
                session=session,
            )
            response_data['playback_token'] = new_token
            response_data['expires_in'] = expires_in
            response_data['source'] = resolve_signed_playback_source(
                request=request,
                lecture=session.lecture,
                session=session,
                playback_token=new_token,
                ttl_seconds=expires_in,
            )

        session.save(update_fields=['last_heartbeat_at', 'expires_at'])
        return Response(response_data)


class VideoSessionRevokeAPIView(APIView):
    """إبطال أو إنهاء جلسة تشغيل فيديو نشطة."""
    permission_classes = [IsAuthenticated, IsNotBanned]

    def post(self, request, session_id):
        session = get_object_or_404(PlaybackSession, session_id=session_id)
        is_admin = getattr(request.user, 'is_superuser', False) or getattr(request.user, 'role', '') == 'admin'
        is_owner = session.user_id == request.user.id
        is_teacher = (
            getattr(request.user, 'role', '') == 'teacher'
            and session.lecture.group
            and session.lecture.group.teacher.user_id == request.user.id
        )
        if not (is_owner or is_admin or is_teacher):
            return Response({'error': 'غير مصرح لك بإبطال هذه الجلسة.'}, status=status.HTTP_403_FORBIDDEN)

        now = timezone.now()
        session.status = 'ended' if is_owner else 'revoked'
        session.revoked_reason = 'user_closed' if is_owner else 'revoked_by_staff'
        session.view_window_expires_at = now
        session.save(update_fields=['status', 'revoked_reason', 'view_window_expires_at'])
        clear_watch_window(session.user, lecture_id=session.lecture_id, now=now)
        log_security_event(
            event_type='session_revoked',
            user=request.user,
            lecture=session.lecture,
            session_id=str(session.session_id),
            severity='info',
            request=request,
            details={'reason': session.revoked_reason},
        )
        return Response({'status': session.status, 'session_id': str(session.session_id)})


class ProtectedVideoStreamProxyAPIView(APIView):
    """
    وكيل بث محلي موقّع للوسائط الخاصة المخزنة داخلياً مع التحقق من التوكن والجلسة ودعم Range Requests.
    يمنع الكاش العام للوسائط المحمية.
    """
    permission_classes = [AllowAny]

    def get(self, request, playback_token):
        try:
            claims = decode_playback_token(playback_token)
        except jwt.ExpiredSignatureError:
            return Response({'error': 'انتهت صلاحية رابط البث.'}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({'error': 'رابط البث غير صالح.'}, status=status.HTTP_403_FORBIDDEN)

        session = PlaybackSession.objects.filter(
            session_id=claims.get('sid'),
            user_id=claims.get('sub'),
            lecture_id=claims.get('lec'),
            status='active',
            expires_at__gt=timezone.now(),
        ).select_related('lecture__video_asset').first()

        if not session:
            return Response({'error': 'تم إيقاف أو انتهاء جلسة البث.'}, status=status.HTTP_403_FORBIDDEN)

        ios_access = check_web_ios_only_lecture_access(request, session.user)
        if not ios_access.get('allowed'):
            return Response(
                {
                    'error': ios_access.get('error'),
                    'blocked': True,
                    'code': ios_access.get('code') or 'WEB_LECTURES_IOS_ONLY',
                    'device_kind': ios_access.get('device_kind'),
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        asset = getattr(session.lecture, 'video_asset', None)
        if not asset or not asset.provider_asset_id:
            return Response({'error': 'ملف الوسائط غير متاح على الخادم المحلي.'}, status=status.HTTP_404_NOT_FOUND)

        private_root = (Path(settings.BASE_DIR) / 'private_media').resolve()
        target_path = (private_root / asset.provider_asset_id.lstrip('/')).resolve()
        if not str(target_path).startswith(str(private_root)) or not target_path.is_file():
            return Response({'error': 'ملف الفيديو غير موجود.'}, status=status.HTTP_404_NOT_FOUND)

        content_type, _ = mimetypes.guess_type(str(target_path))
        file_size = target_path.stat().st_size
        range_header = request.META.get('HTTP_RANGE', '').strip()

        if range_header.startswith('bytes='):
            byte_range = range_header.replace('bytes=', '').split('-')[0:2]
            start = int(byte_range[0]) if byte_range[0] else 0
            end = int(byte_range[1]) if len(byte_range) > 1 and byte_range[1] else min(start + 1024 * 1024 - 1, file_size - 1)
            end = min(end, file_size - 1)
            length = max(end - start + 1, 0)
            with open(target_path, 'rb') as fh:
                fh.seek(start)
                data = fh.read(length)
            resp = HttpResponse(data, status=206, content_type=content_type or 'video/mp4')
            resp['Content-Range'] = f'bytes {start}-{end}/{file_size}'
            resp['Content-Length'] = str(length)
        else:
            resp = FileResponse(open(target_path, 'rb'), content_type=content_type or 'video/mp4')
            resp['Content-Length'] = str(file_size)

        resp['Accept-Ranges'] = 'bytes'
        resp['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
        resp['X-Content-Type-Options'] = 'nosniff'
        return resp


class PlayIntegrityChallengeAPIView(APIView):
    """إصدار Nonce / Challenge قصير العمر ومرتبط بالعملية لمنع هجمات Replay."""
    permission_classes = [AllowAny]
    throttle_classes = [IntegrityCheckThrottle]

    def post(self, request):
        action = str(request.data.get('action') or 'app_startup').strip()
        binding_data = str(request.data.get('binding_data') or '').strip()
        nonce = issue_integrity_challenge(
            user=request.user if request.user.is_authenticated else None,
            action=action,
            binding_data=binding_data,
        )
        return Response({
            'nonce_id': str(nonce.nonce_id),
            'action': nonce.action,
            'expected_request_hash': nonce.expected_request_hash,
            'expires_at': nonce.expires_at.isoformat(),
            'policy_mode': get_integrity_policy_mode(),
        })


class PlayIntegrityVerifyAPIView(APIView):
    """فك توكن Google Play Integrity والتحقق منه على الخادم وإرجاع القرار الأمني."""
    permission_classes = [AllowAny]
    throttle_classes = [IntegrityCheckThrottle]

    def post(self, request):
        nonce_id = request.data.get('nonce_id')
        integrity_token = request.data.get('integrity_token')
        device_id = str(request.data.get('device_id') or request.META.get('HTTP_X_DEVICE_ID') or 'unknown-device').strip()
        tamper_signals = request.data.get('tamper_signals')
        if not isinstance(tamper_signals, dict):
            tamper_signals = {}
        is_debug_build = bool(request.data.get('is_debug_build', False))

        try:
            record, verdict = verify_and_record_integrity(
                request=request,
                user=request.user if request.user.is_authenticated else None,
                nonce_id=nonce_id,
                integrity_token=integrity_token,
                device_id=device_id,
                tamper_signals=tamper_signals,
                is_debug_build=is_debug_build,
            )
        except ValueError as exc:
            err_code = str(exc)
            messages = {
                'INVALID_NONCE': 'رمز التحقق (Nonce) غير صالح.',
                'NONCE_ALREADY_USED': 'تم استخدام رمز التحقق مسبقاً (مرفوض أمنياً).',
                'NONCE_EXPIRED': 'انتهت صلاحية رمز التحقق.',
            }
            return Response(
                {'error': messages.get(err_code, err_code), 'code': err_code},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except RuntimeError as exc:
            return Response(
                {'error': f'فشل التحقق من Play Integrity على الخادم: {exc}', 'code': str(exc)},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        if verdict.get('policy_decision') == 'block' or verdict.get('risk_level') in ('high', 'critical'):
            sev = 'critical' if verdict.get('risk_level') == 'critical' else 'high'
            verdict_score = int(verdict.get('risk_score') or 75)
            reg_devices = RegisteredDevice.objects.filter(installation_id=device_id)
            for reg_dev in reg_devices:
                if reg_dev.trust_status != DeviceTrustStatus.BLOCKED:
                    reg_dev.trust_status = (
                        DeviceTrustStatus.RESTRICTED
                        if verdict.get('policy_decision') == 'block'
                        else DeviceTrustStatus.SUSPICIOUS
                    )
                    reg_dev.requires_reauth = True
                    reg_dev.risk_score = max(reg_dev.risk_score, min(verdict_score, 100))
                    reg_dev.risk_level = sev
                    reg_dev.save(update_fields=['trust_status', 'requires_reauth', 'risk_score', 'risk_level'])

            record_security_event(
                event_type='integrity_verification_failed',
                severity=sev,
                risk_score=verdict_score,
                user=request.user if request.user.is_authenticated else None,
                installation_id=device_id,
                request=request,
                action_taken=verdict.get('policy_decision', 'block'),
                details={
                    'verdict': verdict.get('app_recognition_verdict'),
                    'risk_signals': tamper_signals,
                    'risk_score': verdict_score,
                    'title': 'فشل التحقق من سلامة التطبيق أو البيئة',
                },
            )

        return Response({
            'record_id': record.id,
            'policy_mode': get_integrity_policy_mode(),
            **verdict,
        })

# Compatibility re-exports for original imports and extracted video helpers/views
import mimetypes
import os
from datetime import timedelta
from pathlib import Path
import jwt
from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from django.http import FileResponse, HttpResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle
from rest_framework.views import APIView
from students.models import (
    Enrollment,
    PackageEnrollment,
    VideoViewTracking,
)
from students.views import check_student_access
from teachers.models import CoursePackage, Lecture, PDFFile, VideoCode
from .device_security_service import (
    check_device_allowed,
    check_web_ios_only_lecture_access,
    detect_account_sharing,
    record_device_activity,
    record_security_event,
)
from .integrity_service import (
    get_integrity_policy_mode,
    issue_integrity_challenge,
    verify_and_record_integrity,
)
from .models import (
    DeviceIntegrityRecord,
    DeviceTrustStatus,
    PlaybackSession,
    RegisteredDevice,
    VideoAsset,
    VideoBookmark,
    VideoProgress,
)
from .permissions import IsNotBanned
from .serializers import LectureSerializer, PDFFileSerializer
from .video_security import (
    HEARTBEAT_INTERVAL_SECONDS,
    PLAYBACK_TOKEN_TTL_SECONDS,
    build_watermark_payload,
    clear_watch_window,
    create_or_rotate_playback_session,
    decode_playback_token,
    detect_and_record_anomaly,
    get_active_watch_window_expiry,
    grant_watch_window,
    issue_playback_token,
    log_security_event,
    resolve_signed_playback_source,
)
from api_v1.views.video.throttles import (
    IntegrityCheckThrottle,
    VideoAuthorizeThrottle,
    VideoHeartbeatThrottle,
    VideoProgressThrottle,
)
from api_v1.services.video_access import (
    _check_user_lecture_entitlement,
    _has_recent_playback_session,
    _mark_watch_window,
    _neighbor_lectures_payload,
    _package_error,
    _user_can_access_lecture_metadata,
)
from api_v1.views.video.progress import (
    ContinueWatchingAPIView,
    VideoBookmarksAPIView,
    VideoProgressAPIView,
)
