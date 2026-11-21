"""api_v1.views.admin.notifications
Extracted from api_v1/views_admin.py.
"""

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from core.notifications_service import (
    CUSTOM_TARGET_ALL,
    get_custom_notification_metadata,
    parse_user_ids_input,
    preview_custom_notification_audience,
    search_custom_notification_users,
    send_custom_notification,
)
from dashboard_admin.models import AuditLog
from api_v1.permissions import IsPlatformModerator
from api_v1.serializers import AuditLogSerializer


def _extract_admin_notif_params(data, query_params=None) -> dict:
    """استخراج معاملات استهداف الإشعارات المخصصة بصيغة موحدة من JSON أو QueryParams."""
    if query_params is not None:
        raw_user_ids = query_params.getlist('user_ids') or query_params.get('user_ids')
    else:
        raw_user_ids = data.get('user_ids')

    raw_exclude = data.get('exclude_banned', True)
    if isinstance(raw_exclude, bool):
        exclude_banned = raw_exclude
    else:
        exclude_banned = str(raw_exclude).strip().lower() not in ('0', 'false', 'no')

    return {
        'target_mode': str(data.get('target_mode') or CUSTOM_TARGET_ALL).strip(),
        'segment': str(data.get('segment') or '').strip(),
        'user_ids': parse_user_ids_input(raw_user_ids),
        'grade': str(data.get('grade') or '').strip(),
        'teacher_id': data.get('teacher_id'),
        'plan_id': data.get('plan_id'),
        'subject_id': data.get('subject_id'),
        'exclude_banned': exclude_banned,
    }


class AdminNotificationsAPIView(APIView):
    """إرسال إشعارات مخصصة لمستخدمين محددين أو فئة أو جميع المستخدمين + المعاينة وسجل الإرسالات."""
    permission_classes = [IsAuthenticated, IsPlatformModerator]

    def get(self, request):
        if 'q' in request.query_params or 'search_users' in request.query_params:
            query = (request.query_params.get('q') or request.query_params.get('search_users') or '').strip()
            role = (request.query_params.get('role') or '').strip()
            return Response({
                'users': search_custom_notification_users(query=query, role=role, limit=30),
            })

        if str(request.query_params.get('preview', '')).strip().lower() in ('1', 'true', 'yes'):
            params = _extract_admin_notif_params(request.query_params, query_params=request.query_params)
            return Response(preview_custom_notification_audience(**params))

        meta = get_custom_notification_metadata()
        recent_dispatches = AuditLog.objects.filter(
            action=AuditLog.ACTION_SEND_NOTIFICATION
        ).select_related('admin').order_by('-created_at')[:15]

        return Response({
            **meta,
            'initial_users': search_custom_notification_users(limit=20),
            'recent_dispatches': AuditLogSerializer(recent_dispatches, many=True).data,
        })

    def post(self, request):
        params = _extract_admin_notif_params(request.data)
        res = send_custom_notification(
            title=request.data.get('title', ''),
            message=request.data.get('message', ''),
            link=request.data.get('link'),
            **params,
        )
        if not res.get('ok'):
            return Response(
                {'error': res.get('error') or 'تعذّر إرسال الإشعار المخصص.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        AuditLog.log_custom_notification(request, res)
        return Response({
            'message': f"تم إرسال الإشعار بنجاح إلى {res['recipient_count']} مستخدم ({res['audience_label']}).",
            'recipient_count': res['recipient_count'],
            'fcm_user_count': res['fcm_user_count'],
            'fcm_configured': res['fcm_configured'],
            'audience_label': res['audience_label'],
            'title': res['title'],
            'link': res['link'],
        })
