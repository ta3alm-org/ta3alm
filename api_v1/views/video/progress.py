"""api_v1.views.video.progress
Extracted from api_v1/views_video.py.
"""
from __future__ import annotations

from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from teachers.models import Lecture
from api_v1.device_security_service import check_web_ios_only_lecture_access
from api_v1.models import (
    VideoBookmark,
    VideoProgress,
)
from api_v1.permissions import IsNotBanned

from api_v1.services.video_access import _user_can_access_lecture_metadata
from api_v1.views.video.throttles import VideoProgressThrottle


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
        ios_access = check_web_ios_only_lecture_access(request, request.user)
        if not ios_access.get('allowed'):
            return Response({
                'items': [],
                'lectures_blocked': True,
                'lectures_block_reason': ios_access.get('error') or '',
                'lectures_block_code': ios_access.get('code') or 'WEB_LECTURES_IOS_ONLY',
            })

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
