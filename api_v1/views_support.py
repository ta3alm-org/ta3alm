"""
api_v1/views_support.py
نقاط النهاية الخاصة بشات الدعم الفني المباشر، الرد المباشر من لوحة الإشعارات، وتقارير الأخطاء التقنية التلقائية.
"""
from __future__ import annotations

import hashlib
from datetime import timedelta

from django.db import transaction
from django.db.models import F, Q, Sum
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from core.models import ClientErrorReport, SupportMessage, SupportThread
from core.notifications_service import (
    _user_display_name,
    notify_platform_admins,
    notify_user,
    verify_support_reply_token,
)

from .permissions import IsNotBanned, IsPlatformModerator


def _is_support_admin_user(user) -> bool:
    if not user or not getattr(user, 'is_authenticated', False):
        return False
    if getattr(user, 'is_superuser', False) or getattr(user, 'role', '') == 'admin':
        return True
    admin_profile = getattr(user, 'admin_profile', None)
    return bool(admin_profile and getattr(admin_profile, 'is_active_admin', False))


def _serialize_user_brief(user) -> dict:
    if not user:
        return {}
    return {
        'id': user.id,
        'full_name': _user_display_name(user),
        'email': getattr(user, 'email', '') or '',
        'phone': getattr(user, 'phone', '') or '',
        'role': getattr(user, 'role', '') or '',
        'custom_id': getattr(user, 'custom_id', '') or '',
    }


def serialize_support_message(msg: SupportMessage) -> dict:
    return {
        'id': msg.id,
        'thread_id': msg.thread_id,
        'sender_id': msg.sender_id,
        'sender_name': _user_display_name(msg.sender),
        'is_from_admin': bool(msg.is_from_admin),
        'body': msg.body,
        'is_read': bool(msg.is_read),
        'via_notification_reply': bool(msg.via_notification_reply),
        'created_at': msg.created_at.isoformat() if msg.created_at else '',
    }


def serialize_support_thread(thread: SupportThread, include_user: bool = True) -> dict:
    data = {
        'id': thread.id,
        'subject': thread.subject,
        'status': thread.status,
        'last_message_preview': thread.last_message_preview,
        'last_message_at': thread.last_message_at.isoformat() if thread.last_message_at else '',
        'unread_for_admin': thread.unread_for_admin,
        'unread_for_user': thread.unread_for_user,
        'assigned_admin_id': thread.assigned_admin_id,
        'assigned_admin_name': _user_display_name(thread.assigned_admin) if thread.assigned_admin_id else '',
        'created_at': thread.created_at.isoformat() if thread.created_at else '',
        'updated_at': thread.updated_at.isoformat() if thread.updated_at else '',
    }
    if include_user:
        data['user'] = _serialize_user_brief(thread.user)
    return data


def append_support_message(
    *,
    thread: SupportThread,
    sender,
    body: str,
    is_from_admin: bool,
    via_notification_reply: bool = False,
) -> SupportMessage:
    """
    يسجّل رسالة دعم جديدة ويحدّث عدادات المحادثة ويرسل إشعاراً فورياً مع ميزة الرد المباشر للطرف الآخر.
    """
    clean_body = str(body or '').strip()
    now = timezone.now()
    with transaction.atomic():
        locked = SupportThread.objects.select_for_update().select_related('user').get(pk=thread.pk)
        msg = SupportMessage.objects.create(
            thread=locked,
            sender=sender,
            is_from_admin=bool(is_from_admin),
            body=clean_body,
            is_read=False,
            via_notification_reply=bool(via_notification_reply),
        )
        locked.last_message_preview = clean_body[:275]
        locked.last_message_at = now
        if is_from_admin:
            locked.unread_for_user = int(locked.unread_for_user or 0) + 1
            locked.unread_for_admin = 0
            locked.status = SupportThread.STATUS_OPEN
            if not locked.assigned_admin_id and getattr(sender, 'pk', None):
                locked.assigned_admin = sender
            SupportMessage.objects.filter(
                thread=locked,
                is_from_admin=False,
                is_read=False,
            ).update(is_read=True)
        else:
            locked.unread_for_admin = int(locked.unread_for_admin or 0) + 1
            locked.unread_for_user = 0
            if locked.status == SupportThread.STATUS_CLOSED:
                locked.status = SupportThread.STATUS_OPEN
            SupportMessage.objects.filter(
                thread=locked,
                is_from_admin=True,
                is_read=False,
            ).update(is_read=True)

        locked.save(
            update_fields=[
                'last_message_preview',
                'last_message_at',
                'unread_for_user',
                'unread_for_admin',
                'status',
                'assigned_admin',
                'updated_at',
            ]
        )

    thread_link = f'/support/chat/{thread.id}/'
    if is_from_admin:
        notify_user(
            thread.user,
            'رد جديد من الدعم الفني',
            clean_body[:240],
            link=thread_link,
        )
    else:
        sender_name = _user_display_name(thread.user)
        notify_platform_admins(
            f'رسالة دعم جديدة من {sender_name}',
            clean_body[:240],
            link=thread_link,
            roles=('owner', 'support', 'moderator'),
        )
    return msg


def _serialize_error_report(report: ClientErrorReport) -> dict:
    return {
        'id': report.id,
        'source': report.source,
        'screen': report.screen,
        'error_type': report.error_type,
        'error_message': report.error_message,
        'stack_trace': report.stack_trace,
        'app_version': report.app_version,
        'app_build': report.app_build,
        'platform': report.platform,
        'device_info': report.device_info or {},
        'extra_context': report.extra_context or {},
        'fingerprint': report.fingerprint,
        'occurrences': report.occurrences,
        'is_resolved': bool(report.is_resolved),
        'resolved_at': report.resolved_at.isoformat() if report.resolved_at else '',
        'resolved_by_name': _user_display_name(report.resolved_by) if report.resolved_by_id else '',
        'user': _serialize_user_brief(report.user) if report.user_id else None,
        'created_at': report.created_at.isoformat() if report.created_at else '',
        'last_seen_at': report.last_seen_at.isoformat() if report.last_seen_at else '',
    }


class ClientErrorReportSubmitAPIView(APIView):
    """استقبال تقارير الأخطاء التقنية التلقائية من تطبيق الموبايل أو الويب وإبلاغ الإدارة."""
    permission_classes = [AllowAny]

    def post(self, request):
        data = request.data if isinstance(request.data, dict) else {}
        raw_message = str(data.get('error_message') or data.get('message') or '').strip()
        if not raw_message:
            return Response(
                {'error': 'نص الخطأ مطلوب.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        source = str(data.get('source') or 'flutter_app').strip()[:40] or 'flutter_app'
        screen = str(data.get('screen') or '').strip()[:120]
        error_type = str(data.get('error_type') or '').strip()[:120]
        error_message = raw_message[:12000]
        stack_trace = str(data.get('stack_trace') or '').strip()[:30000]
        app_version = str(data.get('app_version') or '').strip()[:40]
        app_build = str(data.get('app_build') or '').strip()[:20]
        platform_name = str(data.get('platform') or 'android').strip()[:32]
        device_info = data.get('device_info') if isinstance(data.get('device_info'), dict) else {}
        extra_context = data.get('extra_context') if isinstance(data.get('extra_context'), dict) else {}

        norm_msg = ' '.join(error_message[:220].split())
        fp_raw = f'{source}|{screen}|{error_type}|{norm_msg}'
        fingerprint = hashlib.sha256(fp_raw.encode('utf-8')).hexdigest()

        req_user = request.user if getattr(request.user, 'is_authenticated', False) else None
        cutoff = timezone.now() - timedelta(hours=6)

        existing = (
            ClientErrorReport.objects.filter(
                fingerprint=fingerprint,
                is_resolved=False,
                last_seen_at__gte=cutoff,
            )
            .order_by('-last_seen_at')
            .first()
        )
        if existing is not None:
            update_fields = {'occurrences': F('occurrences') + 1, 'last_seen_at': timezone.now()}
            if req_user is not None and existing.user_id is None:
                update_fields['user'] = req_user
            ClientErrorReport.objects.filter(pk=existing.pk).update(**update_fields)
            existing.refresh_from_db()
            return Response(
                {'ok': True, 'report_id': existing.id, 'deduplicated': True},
                status=status.HTTP_200_OK,
            )

        report = ClientErrorReport.objects.create(
            user=req_user,
            source=source,
            screen=screen,
            error_type=error_type,
            error_message=error_message,
            stack_trace=stack_trace,
            app_version=app_version,
            app_build=app_build,
            platform=platform_name,
            device_info=device_info,
            extra_context=extra_context,
            fingerprint=fingerprint,
        )

        screen_label = screen or 'شاشة غير محددة'
        who = _user_display_name(req_user) if req_user else 'زائر/جهاز غير مسجل'
        try:
            notify_platform_admins(
                f'خطأ تقني في التطبيق ({screen_label})',
                f'المستخدم: {who} — {error_message[:140]}',
                link='/admin-panel/errors/',
                roles=('owner', 'moderator'),
            )
        except Exception:
            pass

        return Response(
            {'ok': True, 'report_id': report.id, 'deduplicated': False},
            status=status.HTTP_201_CREATED,
        )


class AdminClientErrorReportsAPIView(APIView):
    """عرض وإدارة تقارير الأخطاء التقنية المرسلة تلقائياً في لوحة الإدارة."""
    permission_classes = [IsAuthenticated, IsPlatformModerator]

    def get(self, request):
        status_filter = str(request.query_params.get('status') or 'unresolved').strip().lower()
        q = str(request.query_params.get('q') or '').strip()

        qs = ClientErrorReport.objects.select_related('user', 'resolved_by').order_by('-last_seen_at', '-id')
        if status_filter == 'unresolved':
            qs = qs.filter(is_resolved=False)
        elif status_filter == 'resolved':
            qs = qs.filter(is_resolved=True)

        if q:
            qs = qs.filter(
                Q(error_message__icontains=q)
                | Q(error_type__icontains=q)
                | Q(screen__icontains=q)
                | Q(user__email__icontains=q)
                | Q(user__first_name__icontains=q)
            )

        reports = [_serialize_error_report(r) for r in qs[:80]]
        unresolved_count = ClientErrorReport.objects.filter(is_resolved=False).count()
        total_count = ClientErrorReport.objects.count()
        return Response({
            'reports': reports,
            'unresolved_count': unresolved_count,
            'total_count': total_count,
        })

    def post(self, request):
        action = str(request.data.get('action') or '').strip().lower()
        report_id = request.data.get('report_id')

        if action == 'resolve_all':
            updated = ClientErrorReport.objects.filter(is_resolved=False).update(
                is_resolved=True,
                resolved_at=timezone.now(),
                resolved_by=request.user,
            )
            return Response({'message': f'تم إغلاق {updated} تقرير خطأ كمُعالج.'})

        report = get_object_or_404(ClientErrorReport, pk=report_id)
        if action == 'resolve':
            report.is_resolved = True
            report.resolved_at = timezone.now()
            report.resolved_by = request.user
            report.save(update_fields=['is_resolved', 'resolved_at', 'resolved_by'])
            return Response({'message': 'تم تحديد الخطأ كمُعالج.', 'report': _serialize_error_report(report)})

        if action == 'reopen':
            report.is_resolved = False
            report.resolved_at = None
            report.resolved_by = None
            report.save(update_fields=['is_resolved', 'resolved_at', 'resolved_by'])
            return Response({'message': 'تمت إعادة فتح تقرير الخطأ.', 'report': _serialize_error_report(report)})

        if action == 'delete':
            report.delete()
            return Response({'message': 'تم حذف تقرير الخطأ.'})

        return Response({'error': 'إجراء غير معروف.'}, status=status.HTTP_400_BAD_REQUEST)


class SupportChatAPIView(APIView):
    """شات الدعم الفني للمستخدم الحالي (عرض المحادثة وإرسال الرسائل)."""
    permission_classes = [IsAuthenticated, IsNotBanned]

    def _get_or_create_thread(self, user) -> SupportThread:
        thread = (
            SupportThread.objects.select_related('user', 'assigned_admin')
            .filter(user=user)
            .order_by('-last_message_at', '-id')
            .first()
        )
        if thread is None:
            thread = SupportThread.objects.create(user=user)
        return thread

    def get(self, request):
        thread = self._get_or_create_thread(request.user)
        raw_after = str(request.query_params.get('after_id') or '').strip()

        if thread.unread_for_user:
            thread.unread_for_user = 0
            thread.save(update_fields=['unread_for_user'])
        SupportMessage.objects.filter(
            thread=thread,
            is_from_admin=True,
            is_read=False,
        ).update(is_read=True)

        msgs_qs = thread.messages.select_related('sender')
        if raw_after.isdigit():
            msgs_qs = msgs_qs.filter(id__gt=int(raw_after)).order_by('id')
            messages_data = [serialize_support_message(m) for m in msgs_qs]
        else:
            recent = list(msgs_qs.order_by('-id')[:120])
            recent.reverse()
            messages_data = [serialize_support_message(m) for m in recent]

        return Response({
            'thread': serialize_support_thread(thread, include_user=False),
            'messages': messages_data,
        })

    def post(self, request):
        body = str(request.data.get('body') or request.data.get('message') or '').strip()
        subject = str(request.data.get('subject') or '').strip()[:200]
        if not body:
            return Response(
                {'error': 'يرجى كتابة نص الرسالة قبل الإرسال.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if len(body) > 4000:
            body = body[:4000]

        thread = self._get_or_create_thread(request.user)
        if subject and thread.subject == 'محادثة الدعم الفني':
            thread.subject = subject
            thread.save(update_fields=['subject'])

        msg = append_support_message(
            thread=thread,
            sender=request.user,
            body=body,
            is_from_admin=False,
        )
        thread.refresh_from_db()
        return Response(
            {
                'thread': serialize_support_thread(thread, include_user=False),
                'message': serialize_support_message(msg),
            },
            status=status.HTTP_201_CREATED,
        )


class AdminSupportChatListAPIView(APIView):
    """قائمة جميع محادثات الدعم الفني لإدارة المنصة."""
    permission_classes = [IsAuthenticated, IsPlatformModerator]

    def get(self, request):
        status_filter = str(request.query_params.get('status') or '').strip().lower()
        q = str(request.query_params.get('q') or '').strip()

        qs = (
            SupportThread.objects.select_related('user', 'assigned_admin')
            .order_by('-last_message_at', '-id')
        )
        if status_filter in (
            SupportThread.STATUS_OPEN,
            SupportThread.STATUS_PENDING,
            SupportThread.STATUS_CLOSED,
        ):
            qs = qs.filter(status=status_filter)

        if q:
            qs = qs.filter(
                Q(user__first_name__icontains=q)
                | Q(user__last_name__icontains=q)
                | Q(user__email__icontains=q)
                | Q(user__phone__icontains=q)
                | Q(user__custom_id__icontains=q)
                | Q(subject__icontains=q)
                | Q(last_message_preview__icontains=q)
            )

        threads = [serialize_support_thread(t, include_user=True) for t in qs[:100]]
        total_unread = SupportThread.objects.aggregate(total=Sum('unread_for_admin')).get('total') or 0
        return Response({
            'threads': threads,
            'total_unread': int(total_unread),
        })


class AdminSupportChatDetailAPIView(APIView):
    """عرض محادثة دعم معينة والرد عليها أو إغلاقها/إعادة فتحها من قِبل الإدارة."""
    permission_classes = [IsAuthenticated, IsPlatformModerator]

    def get(self, request, thread_id: int):
        thread = get_object_or_404(
            SupportThread.objects.select_related('user', 'assigned_admin'),
            pk=thread_id,
        )
        raw_after = str(request.query_params.get('after_id') or '').strip()

        if thread.unread_for_admin:
            thread.unread_for_admin = 0
            thread.save(update_fields=['unread_for_admin'])
        SupportMessage.objects.filter(
            thread=thread,
            is_from_admin=False,
            is_read=False,
        ).update(is_read=True)

        msgs_qs = thread.messages.select_related('sender')
        if raw_after.isdigit():
            msgs_qs = msgs_qs.filter(id__gt=int(raw_after)).order_by('id')
            messages_data = [serialize_support_message(m) for m in msgs_qs]
        else:
            recent = list(msgs_qs.order_by('-id')[:150])
            recent.reverse()
            messages_data = [serialize_support_message(m) for m in recent]

        return Response({
            'thread': serialize_support_thread(thread, include_user=True),
            'messages': messages_data,
        })

    def post(self, request, thread_id: int):
        thread = get_object_or_404(
            SupportThread.objects.select_related('user', 'assigned_admin'),
            pk=thread_id,
        )
        action = str(request.data.get('action') or 'reply').strip().lower()

        if action == 'close':
            thread.status = SupportThread.STATUS_CLOSED
            thread.save(update_fields=['status', 'updated_at'])
            return Response({
                'message': 'تم إغلاق المحادثة.',
                'thread': serialize_support_thread(thread, include_user=True),
            })

        if action == 'reopen':
            thread.status = SupportThread.STATUS_OPEN
            thread.save(update_fields=['status', 'updated_at'])
            return Response({
                'message': 'تمت إعادة فتح المحادثة.',
                'thread': serialize_support_thread(thread, include_user=True),
            })

        body = str(request.data.get('body') or request.data.get('message') or '').strip()
        if not body:
            return Response(
                {'error': 'يرجى كتابة نص الرد.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if len(body) > 4000:
            body = body[:4000]

        msg = append_support_message(
            thread=thread,
            sender=request.user,
            body=body,
            is_from_admin=True,
        )
        thread.refresh_from_db()
        return Response(
            {
                'thread': serialize_support_thread(thread, include_user=True),
                'message': serialize_support_message(msg),
            },
            status=status.HTTP_201_CREATED,
        )


class SupportChatQuickReplyAPIView(APIView):
    """
    الرد المباشر من لوحة الإشعارات على أندرويد (مثل واتساب) عبر رمز موقّع X-Ta3alm-Reply-Token.
    """
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        token = str(
            request.META.get('HTTP_X_TA3ALM_REPLY_TOKEN')
            or request.data.get('reply_token')
            or ''
        ).strip()
        verified = verify_support_reply_token(token)
        if not verified:
            return Response(
                {'error': 'رمز الرد المباشر غير صالح أو منتهي الصلاحية.'},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        user, thread_id = verified
        thread = (
            SupportThread.objects.select_related('user', 'assigned_admin')
            .filter(pk=thread_id)
            .first()
        )
        if thread is None:
            return Response(
                {'error': 'محادثة الدعم غير موجودة.'},
                status=status.HTTP_404_NOT_FOUND,
            )

        is_admin = _is_support_admin_user(user)
        if thread.user_id != user.id and not is_admin:
            return Response(
                {'error': 'ليس لديك صلاحية للرد على هذه المحادثة.'},
                status=status.HTTP_403_FORBIDDEN,
            )

        body = str(
            request.data.get('message')
            or request.data.get('body')
            or request.data.get('reply')
            or ''
        ).strip()
        if not body:
            return Response(
                {'error': 'نص الرد فارغ.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if len(body) > 4000:
            body = body[:4000]

        is_from_admin = is_admin and thread.user_id != user.id
        msg = append_support_message(
            thread=thread,
            sender=user,
            body=body,
            is_from_admin=is_from_admin,
            via_notification_reply=True,
        )
        return Response(
            {
                'ok': True,
                'message_id': msg.id,
                'thread_id': thread.id,
                'is_from_admin': is_from_admin,
                'created_at': msg.created_at.isoformat() if msg.created_at else '',
            },
            status=status.HTTP_201_CREATED,
        )
