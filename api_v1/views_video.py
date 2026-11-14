"""
api_v1/views_video.py
نقاط النهاية المحمية لتشغيل الفيديو، النبض (Heartbeat)، حفظ التقدم، العلامات المرجعية، إبطال الجلسات،
والتحقق من Google Play Integrity من جهة الخادم.
"""
from __future__ import annotations

import mimetypes
import os
from datetime import timedelta
from pathlib import Path

import jwt
from django.conf import settings
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

from .integrity_service import (
    get_integrity_policy_mode,
    issue_integrity_challenge,
    verify_and_record_integrity,
)
from .models import (
    DeviceIntegrityRecord,
    PlaybackSession,
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
    create_or_rotate_playback_session,
    decode_playback_token,
    detect_and_record_anomaly,
    issue_playback_token,
    log_security_event,
    resolve_signed_playback_source,
)


class VideoAuthorizeThrottle(UserRateThrottle):
    rate = '30/min'


class VideoHeartbeatThrottle(UserRateThrottle):
    rate = '120/min'


class IntegrityCheckThrottle(UserRateThrottle):
    rate = '30/min'


class VideoProgressThrottle(UserRateThrottle):
    rate = '60/min'


def _user_can_access_lecture_metadata(user, lecture: Lecture) -> bool:
    """يتحقق من أن المستخدم يملك صلاحية الوصول إلى المحاضرة قبل قراءة أو حفظ التقدم والعلامات."""
    if getattr(user, 'is_superuser', False) or getattr(user, 'role', '') == 'admin':
        return True

    role = getattr(user, 'role', '')
    if role in ('teacher', 'assistant'):
        if lecture.group:
            teacher = lecture.group.teacher
            if user == teacher.user or (
                hasattr(user, 'assistant_profile')
                and user.assistant_profile.assignments.filter(teacher=teacher).exists()
            ):
                return True
        for pkg in lecture.packages.all():
            if user == pkg.teacher.user or (
                hasattr(user, 'assistant_profile')
                and user.assistant_profile.assignments.filter(teacher=pkg.teacher).exists()
            ):
                return True
        return False

    student = getattr(user, 'student_profile', None)
    if not student:
        return False

    if PlaybackSession.objects.filter(user=user, lecture=lecture).exists():
        return True
    if VideoCode.objects.filter(lecture=lecture, used_by=student).exists():
        return True
    if lecture.group_id and Enrollment.objects.filter(
        student=student,
        group_id=lecture.group_id,
        is_active=True,
    ).exists():
        return True
    return PackageEnrollment.objects.filter(
        student=student,
        is_paid=True,
        package__lectures=lecture,
    ).exists()


def _package_error(msg: str, code: int = status.HTTP_403_FORBIDDEN) -> Response:
    return Response({'error': msg}, status=code)


def _check_user_lecture_entitlement(
    request,
    lecture: Lecture,
    *,
    package_id: int | None = None,
    submitted_code: str = '',
    consume_view: bool = True,
) -> tuple[bool, dict]:
    """
    يتحقق من أحقية المستخدم في مشاهدة المحاضرة:
    - المعلم/المساعد المصرح له أو الأدمن: وصول معاينة مباشر.
    - الطالب في حزمة مدفوعة: يتحقق من الاشتراك + ارتباط المحاضرة بالحزمة + حد المشاهدات.
    - الطالب في مجموعة: يتحقق من عضوية المجموعة + كود الفيديو + حد المشاهدات.
    """
    user = request.user

    if getattr(user, 'is_superuser', False) or getattr(user, 'role', '') == 'admin':
        pkg = CoursePackage.objects.filter(id=package_id).first() if package_id else None
        return True, {'package': pkg, 'role_preview': True}

    if getattr(user, 'role', '') in ('teacher', 'assistant'):
        if lecture.group:
            teacher = lecture.group.teacher
            if user == teacher.user or (
                hasattr(user, 'assistant_profile')
                and user.assistant_profile.assignments.filter(teacher=teacher).exists()
            ):
                return True, {'package': None, 'role_preview': True}
        if package_id:
            pkg = CoursePackage.objects.filter(id=package_id, lectures=lecture).first()
            if pkg and (
                user == pkg.teacher.user
                or (
                    hasattr(user, 'assistant_profile')
                    and user.assistant_profile.assignments.filter(teacher=pkg.teacher).exists()
                )
            ):
                return True, {'package': pkg, 'role_preview': True}
        return False, {
            'status_code': status.HTTP_403_FORBIDDEN,
            'payload': {'error': 'ليس لديك صلاحية معاينة هذه المحاضرة.'},
        }

    if getattr(user, 'role', '') != 'student' or not hasattr(user, 'student_profile'):
        return False, {
            'status_code': status.HTTP_403_FORBIDDEN,
            'payload': {'error': 'هذه الخدمة متاحة للطلاب فقط.'},
        }

    student = user.student_profile

    # 1. مسار الحزم الأونلاين المدفوعة
    if package_id is not None:
        package = get_object_or_404(CoursePackage, id=package_id)
        if not package.lectures.filter(id=lecture.id).exists():
            return False, {
                'status_code': status.HTTP_404_NOT_FOUND,
                'payload': {'error': 'هذه المحاضرة غير مدرجة ضمن الحزمة المحددة.'},
            }
        if not PackageEnrollment.objects.filter(student=student, package=package, is_paid=True).exists():
            return False, {
                'status_code': status.HTTP_403_FORBIDDEN,
                'payload': {'error': 'يجب شراء الحزمة أولاً للوصول إلى هذا الفيديو.'},
            }
        with transaction.atomic():
            tracker, _ = VideoViewTracking.objects.select_for_update().get_or_create(
                student=student,
                package=package,
                lecture=lecture,
            )
            if consume_view and tracker.views_count >= package.view_limit:
                return False, {
                    'status_code': status.HTTP_403_FORBIDDEN,
                    'payload': {'error': 'لقد استهلكت عدد مرات مشاهدة هذا الفيديو في الحزمة.'},
                }
            points_just_awarded = False
            if consume_view:
                if not tracker.is_completed:
                    tracker.is_completed = True
                    tracker.points_awarded = 10
                    points_just_awarded = True
                tracker.views_count += 1
                tracker.save()
        return True, {
            'package': package,
            'points_just_awarded': points_just_awarded,
            'view_limit': package.view_limit,
            'views_used': tracker.views_count,
            'remaining_views': max(package.view_limit - tracker.views_count, 0),
        }

    # 2. مسار محاضرات المجموعات المحمية بالأكواد
    if not lecture.group:
        return False, {
            'status_code': status.HTTP_400_BAD_REQUEST,
            'payload': {'error': 'يرجى تحديد معرّف الحزمة لمشاهدة هذه المحاضرة.'},
        }

    group, access_status = check_student_access(user, lecture.group.id)
    if access_status != 'ok':
        return False, {
            'status_code': status.HTTP_403_FORBIDDEN,
            'payload': {'error': 'أنت غير مصرح لك بالوصول إلى هذه المجموعة حالياً.', 'access_status': access_status},
        }

    with transaction.atomic():
        if submitted_code:
            try:
                new_code = VideoCode.objects.select_for_update().get(
                    code__iexact=submitted_code.upper(),
                    lecture=lecture,
                    is_used=False,
                )
            except VideoCode.DoesNotExist:
                return False, {
                    'status_code': status.HTTP_400_BAD_REQUEST,
                    'payload': {'error': 'الكود غير صحيح أو تم استخدامه مسبقاً.'},
                }
            new_code.is_used = True
            new_code.used_by = student
            new_code.used_at = timezone.now()
            new_code.save()
            active_code = new_code
        else:
            active_code = (
                VideoCode.objects.select_for_update()
                .filter(lecture=lecture, used_by=student)
                .order_by('-used_at')
                .first()
            )

        if not active_code or active_code.current_views >= active_code.max_views:
            return False, {
                'status_code': status.HTTP_403_FORBIDDEN,
                'payload': {
                    'is_unlocked': False,
                    'require_code': True,
                    'code': 'REQUIRE_CODE',
                    'error': 'يرجى إدخال كود المشاهدة لفتح الفيديو.'
                    if not active_code
                    else 'لقد استهلكت عدد مرات مشاهدة هذا الكود. يرجى إدخال كود جديد.',
                    'lecture': {
                        'id': lecture.id,
                        'title': lecture.title,
                        'description': lecture.description,
                    },
                },
            }

        if consume_view:
            active_code.current_views += 1
            active_code.save(update_fields=['current_views'])

        return True, {
            'package': None,
            'code_info': {
                'code': active_code.code,
                'current_views': active_code.current_views,
                'max_views': active_code.max_views,
                'remaining_views': max(active_code.max_views - active_code.current_views, 0),
            },
        }


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


def _neighbor_lectures_payload(lecture: Lecture, package: CoursePackage | None) -> tuple[dict | None, dict | None]:
    if package:
        ordered = list(package.lectures.filter(is_active=True).order_by('created_at', 'id').values('id', 'title'))
    elif lecture.group:
        ordered = list(lecture.group.lectures.filter(is_active=True).order_by('created_at', 'id').values('id', 'title'))
    else:
        return None, None

    ids = [item['id'] for item in ordered]
    if lecture.id not in ids:
        return None, None
    idx = ids.index(lecture.id)
    prev_lec = ordered[idx - 1] if idx > 0 else None
    next_lec = ordered[idx + 1] if idx + 1 < len(ordered) else None
    return prev_lec, next_lec


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
        consume_view = str(
            request.data.get('record_view') or request.query_params.get('record_view') or 'true'
        ).lower() != 'false'

        if detect_and_record_anomaly(request, request.user, lecture, device_id=device_id):
            return Response(
                {'error': 'تم رصد طلبات تشغيل متكررة بشكل غير طبيعي. يرجى الانتظار قليلاً.'},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
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
            'attachments': PDFFileSerializer(pdfs, many=True).data,
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
        raw_token = str(request.data.get('playback_token') or '').strip()
        session_id = str(request.data.get('session_id') or '').strip()
        device_id = str(request.data.get('device_id') or '').strip()
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


class VideoProgressAPIView(APIView):
    """حفظ واسترجاع تقدم المشاهدة وموضع الاستئناف والسرعة المفضلة."""
    permission_classes = [IsAuthenticated, IsNotBanned]
    throttle_classes = [VideoProgressThrottle]

    def get(self, request, lecture_id):
        lecture = get_object_or_404(Lecture, id=lecture_id)
        if not _user_can_access_lecture_metadata(request.user, lecture):
            return Response({'error': 'غير مصرح لك بالوصول إلى بيانات هذه المحاضرة.'}, status=status.HTTP_403_FORBIDDEN)
        progress, _ = VideoProgress.objects.get_or_create(user=request.user, lecture=lecture)
        return Response({
            'lecture_id': lecture.id,
            'position_seconds': progress.position_seconds,
            'duration_seconds': progress.duration_seconds,
            'watched_seconds': progress.watched_seconds,
            'progress_percent': round(progress.progress_percent, 1),
            'is_completed': progress.is_completed,
            'preferred_speed': progress.preferred_speed,
            'last_watched_at': progress.last_watched_at,
        })

    def post(self, request, lecture_id):
        lecture = get_object_or_404(Lecture, id=lecture_id)
        if not _user_can_access_lecture_metadata(request.user, lecture):
            return Response({'error': 'غير مصرح لك بتحديث تقدم هذه المحاضرة.'}, status=status.HTTP_403_FORBIDDEN)
        position = max(int(request.data.get('position_seconds', 0) or 0), 0)
        duration = max(int(request.data.get('duration_seconds', 0) or 0), 0)
        watched_delta = max(int(request.data.get('watched_delta_seconds', 0) or 0), 0)
        raw_speed = float(request.data.get('preferred_speed', 1.0) or 1.0)
        clamped_speed = min(max(raw_speed, 0.5), 2.0)

        progress, _ = VideoProgress.objects.get_or_create(user=request.user, lecture=lecture)
        if duration > 0:
            progress.duration_seconds = duration
        effective_duration = progress.duration_seconds or getattr(getattr(lecture, 'video_asset', None), 'duration_seconds', 0)
        if effective_duration > 0:
            position = min(position, effective_duration)
        progress.position_seconds = position
        progress.watched_seconds += min(watched_delta, 120)
        progress.preferred_speed = clamped_speed

        if effective_duration > 0:
            pct = min((position / effective_duration) * 100.0, 100.0)
            progress.progress_percent = max(progress.progress_percent, pct)
            if pct >= 90.0:
                progress.is_completed = True

        progress.save()
        return Response({
            'lecture_id': lecture.id,
            'position_seconds': progress.position_seconds,
            'duration_seconds': progress.duration_seconds,
            'watched_seconds': progress.watched_seconds,
            'progress_percent': round(progress.progress_percent, 1),
            'is_completed': progress.is_completed,
            'preferred_speed': progress.preferred_speed,
        })


class ContinueWatchingAPIView(APIView):
    """قائمة استكمال المشاهدة للطالب مع نسب الإنجاز وموضع التوقف."""
    permission_classes = [IsAuthenticated, IsNotBanned]

    def get(self, request):
        rows = (
            VideoProgress.objects.filter(user=request.user, position_seconds__gt=0)
            .select_related('lecture__group', 'lecture__video_asset')
            .order_by('-last_watched_at')[:12]
        )
        items = []
        for row in rows:
            lec = row.lecture
            pkg = lec.packages.first() if not lec.group else None
            items.append({
                'lecture_id': lec.id,
                'lecture_title': lec.title,
                'group_id': lec.group_id,
                'group_name': lec.group.name if lec.group else '',
                'package_id': pkg.id if pkg else None,
                'package_title': pkg.title if pkg else '',
                'is_package_lecture': bool(pkg and not lec.group_id),
                'position_seconds': row.position_seconds,
                'duration_seconds': row.duration_seconds,
                'progress_percent': round(row.progress_percent, 1),
                'is_completed': row.is_completed,
                'preferred_speed': row.preferred_speed,
                'last_watched_at': row.last_watched_at,
            })
        return Response({'items': items})


class VideoBookmarksAPIView(APIView):
    """إدارة العلامات المرجعية الشخصية داخل المحاضرة."""
    permission_classes = [IsAuthenticated, IsNotBanned]

    def get(self, request, lecture_id):
        lecture = get_object_or_404(Lecture, id=lecture_id)
        if not _user_can_access_lecture_metadata(request.user, lecture):
            return Response({'error': 'غير مصرح لك بالوصول إلى علامات هذه المحاضرة.'}, status=status.HTTP_403_FORBIDDEN)
        bookmarks = VideoBookmark.objects.filter(user=request.user, lecture=lecture)
        return Response({
            'bookmarks': [
                {
                    'id': b.id,
                    'timestamp_seconds': b.timestamp_seconds,
                    'title': b.title,
                    'note': b.note,
                    'created_at': b.created_at,
                }
                for b in bookmarks
            ]
        })

    def post(self, request, lecture_id):
        lecture = get_object_or_404(Lecture, id=lecture_id)
        if not _user_can_access_lecture_metadata(request.user, lecture):
            return Response({'error': 'غير مصرح لك بإضافة علامات لهذه المحاضرة.'}, status=status.HTTP_403_FORBIDDEN)
        ts = max(int(request.data.get('timestamp_seconds', 0) or 0), 0)
        title = str(request.data.get('title') or '').strip() or f'علامة عند {ts // 60:02d}:{ts % 60:02d}'
        note = str(request.data.get('note') or '').strip()
        bookmark = VideoBookmark.objects.create(
            user=request.user,
            lecture=lecture,
            timestamp_seconds=ts,
            title=title[:120],
            note=note,
        )
        return Response(
            {
                'bookmark': {
                    'id': bookmark.id,
                    'timestamp_seconds': bookmark.timestamp_seconds,
                    'title': bookmark.title,
                    'note': bookmark.note,
                    'created_at': bookmark.created_at,
                }
            },
            status=status.HTTP_201_CREATED,
        )

    def delete(self, request, bookmark_id=None, lecture_id=None):
        bookmark = get_object_or_404(VideoBookmark, id=bookmark_id, user=request.user)
        bookmark.delete()
        return Response({'message': 'تم حذف العلامة المرجعية.'})


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

        session.status = 'ended' if is_owner else 'revoked'
        session.revoked_reason = 'user_closed' if is_owner else 'revoked_by_staff'
        session.save(update_fields=['status', 'revoked_reason'])
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

        return Response({
            'record_id': record.id,
            'policy_mode': get_integrity_policy_mode(),
            **verdict,
        })

