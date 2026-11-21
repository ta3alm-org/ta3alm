"""api_v1.services.video_access
Extracted from api_v1/views_video.py.
"""
from __future__ import annotations

from django.db import transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from students.models import (
    Enrollment,
    PackageEnrollment,
    VideoViewTracking,
)
from students.views import check_student_access
from teachers.models import (
    CoursePackage,
    Lecture,
    VideoCode,
)
from api_v1.models import PlaybackSession
from api_v1.video_security import (
    get_active_watch_window_expiry,
    grant_watch_window,
)


def _has_recent_playback_session(user, lecture, window_minutes: int = 20) -> bool:
    return get_active_watch_window_expiry(user, lecture.id) is not None


def _mark_watch_window(user, lecture, window_seconds: int = 1200) -> None:
    grant_watch_window(user, lecture.id, minutes=max(int(window_seconds // 60), 1))


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
    watch_window_expiry = get_active_watch_window_expiry(
        user,
        lecture.id,
        package_id=package_id,
    )
    already_in_watch_window = watch_window_expiry is not None

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
            limit_reached = tracker.views_count >= package.view_limit
            can_resume = already_in_watch_window and tracker.views_count <= package.view_limit
            if limit_reached and not can_resume:
                return False, {
                    'status_code': status.HTTP_403_FORBIDDEN,
                    'payload': {'error': 'لقد استهلكت عدد مرات مشاهدة هذا الفيديو في الحزمة.'},
                }
            points_just_awarded = False
            if not already_in_watch_window:
                if not tracker.is_completed:
                    tracker.is_completed = True
                    tracker.points_awarded = 10
                    points_just_awarded = True
                tracker.views_count += 1
                tracker.save()
                watch_window_expiry = grant_watch_window(user, lecture.id)
        return True, {
            'package': package,
            'watch_window_expires_at': watch_window_expiry,
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

        can_resume_code = bool(
            active_code and already_in_watch_window and active_code.current_views <= active_code.max_views
        )
        if not active_code or (active_code.current_views >= active_code.max_views and not can_resume_code):
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

        should_consume = bool(submitted_code) or not already_in_watch_window
        if should_consume:
            with transaction.atomic():
                locked_code = VideoCode.objects.select_for_update().get(pk=active_code.pk)
                if locked_code.current_views >= locked_code.max_views:
                    return False, {
                        'status_code': status.HTTP_403_FORBIDDEN,
                        'payload': {
                            'is_unlocked': False,
                            'require_code': True,
                            'code': 'REQUIRE_CODE',
                            'error': 'تم استنفاد عدد المشاهدات المتاحة لهذا الكود. يرجى إدخال كود جديد.',
                        },
                    }
                locked_code.current_views += 1
                locked_code.save(update_fields=['current_views'])
                active_code = locked_code
                watch_window_expiry = grant_watch_window(user, lecture.id)

        return True, {
            'package': None,
            'watch_window_expires_at': watch_window_expiry,
            'code_info': {
                'code': active_code.code,
                'current_views': active_code.current_views,
                'max_views': active_code.max_views,
                'remaining_views': max(active_code.max_views - active_code.current_views, 0),
            },
        }


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
