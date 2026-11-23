"""dashboard_admin.views.notifications
Extracted from dashboard_admin/views.py.
"""

from django.shortcuts import (
    render,
    redirect,
)
from django.contrib import messages
from django.contrib.auth import get_user_model
from dashboard_admin.models import AuditLog
from dashboard_admin.decorators import moderator_required

from django.template.loader import render_to_string

from dashboard_admin.views.base import _base_context
from dashboard_admin.views.ajax import (
    ajax_error,
    ajax_success,
    is_ajax_request,
)

User = get_user_model()


# ==========================================================
# 15. إرسال الإشعارات المخصصة (لمستخدمين معينين / فئة / الكل)
# ==========================================================
@moderator_required
def send_notifications(request):
    """صفحة إرسال إشعار مخصص لمستخدمين محددين أو فئة أو جميع المستخدمين."""
    from core.notifications_service import (
        CUSTOM_TARGET_ALL,
        CUSTOM_TARGET_USERS,
        get_custom_notification_metadata,
        parse_user_ids_input,
        preview_custom_notification_audience,
        search_custom_notification_users,
        send_custom_notification,
    )

    ctx = _base_context(request)
    metadata = get_custom_notification_metadata()

    target_mode = (request.GET.get('mode') or CUSTOM_TARGET_ALL).strip()
    segment = (request.GET.get('segment') or 'students').strip()
    grade = (request.GET.get('grade') or '').strip()
    teacher_id = (request.GET.get('teacher_id') or '').strip()
    plan_id = (request.GET.get('plan_id') or '').strip()
    subject_id = (request.GET.get('subject_id') or '').strip()
    exclude_banned = True
    title_val = ''
    message_val = ''
    link_val = ''

    preselected_ids = parse_user_ids_input(
        request.GET.getlist('user_id') or request.GET.get('user_ids')
    )
    if preselected_ids and not request.GET.get('mode'):
        target_mode = CUSTOM_TARGET_USERS

    if request.method == 'POST':
        target_mode = (request.POST.get('target_mode') or CUSTOM_TARGET_ALL).strip()
        segment = (request.POST.get('segment') or '').strip()
        grade = (request.POST.get('grade') or '').strip()
        teacher_id = (request.POST.get('teacher_id') or '').strip()
        plan_id = (request.POST.get('plan_id') or '').strip()
        subject_id = (request.POST.get('subject_id') or '').strip()
        exclude_banned = request.POST.get('exclude_banned') == '1'
        title_val = (request.POST.get('title') or '').strip()
        message_val = (request.POST.get('message') or '').strip()
        link_val = (request.POST.get('link') or '').strip()
        preselected_ids = parse_user_ids_input(request.POST.getlist('user_ids'))

        res = send_custom_notification(
            title=title_val,
            message=message_val,
            link=link_val,
            target_mode=target_mode,
            segment=segment,
            user_ids=preselected_ids,
            grade=grade,
            teacher_id=teacher_id,
            plan_id=plan_id,
            subject_id=subject_id,
            exclude_banned=exclude_banned,
        )
        if res.get('ok'):
            AuditLog.log_custom_notification(request, res)
            fcm_note = (
                f" (منهم {res['fcm_user_count']} لديهم إشعارات فورية FCM مفعّلة)"
                if res.get('fcm_configured')
                else " (ملاحظة: إشعارات FCM الفورية غير مهيأة على الخادم حالياً)"
            )
            msg = f"تم إرسال الإشعار بنجاح إلى {res['recipient_count']} مستخدم ضمن «{res['audience_label']}»{fcm_note}."
            if is_ajax_request(request):
                recent_dispatches = AuditLog.objects.filter(
                    action=AuditLog.ACTION_SEND_NOTIFICATION
                ).select_related('admin').order_by('-created_at')[:15]
                dispatches_html = render_to_string(
                    'admin_panel/partials/_notification_dispatches.html',
                    {'recent_dispatches': recent_dispatches},
                    request=request,
                )
                return ajax_success(
                    msg,
                    data={
                        'recipient_count': res.get('recipient_count', 0),
                        'fcm_user_count': res.get('fcm_user_count', 0),
                        'fcm_configured': bool(res.get('fcm_configured')),
                        'audience_label': res.get('audience_label', ''),
                        'dispatches_html': dispatches_html,
                    },
                )
            messages.success(request, msg)
            return redirect('admin_panel:send_notifications')

        err_msg = res.get('error') or 'تعذّر إرسال الإشعار.'
        if is_ajax_request(request):
            return ajax_error(err_msg, status=400)
        messages.error(request, err_msg)

    selected_users = []
    if preselected_ids:
        selected_qs = User.objects.filter(id__in=preselected_ids).order_by('-id')
        fcm_ids = set(
            selected_qs.filter(fcm_tokens__is_active=True).values_list('id', flat=True)
        )
        for u in selected_qs:
            selected_users.append({
                'id': u.pk,
                'full_name': (u.get_full_name() or '').strip() or u.username or u.email,
                'email': u.email or '',
                'phone': getattr(u, 'phone', '') or '',
                'custom_id': getattr(u, 'custom_id', '') or '',
                'role': u.role,
                'role_display': u.get_role_display(),
                'has_fcm': u.pk in fcm_ids,
            })

    preview = preview_custom_notification_audience(
        target_mode=target_mode,
        segment=segment,
        user_ids=preselected_ids,
        grade=grade,
        teacher_id=teacher_id,
        plan_id=plan_id,
        subject_id=subject_id,
        exclude_banned=exclude_banned,
    )
    recent_dispatches = AuditLog.objects.filter(
        action=AuditLog.ACTION_SEND_NOTIFICATION
    ).select_related('admin').order_by('-created_at')[:15]

    ctx.update({
        'notif_meta': metadata,
        'target_mode': target_mode,
        'segment': segment,
        'grade': grade,
        'teacher_id': teacher_id,
        'plan_id': plan_id,
        'subject_id': subject_id,
        'exclude_banned': exclude_banned,
        'title_val': title_val,
        'message_val': message_val,
        'link_val': link_val,
        'selected_users': selected_users,
        'initial_users': search_custom_notification_users(limit=15),
        'preview': preview,
        'recent_dispatches': recent_dispatches,
    })
    return render(request, 'admin_panel/send_notifications.html', ctx)


@moderator_required
def notifications_recipient_preview(request):
    """نقطة JSON للمعاينة الحية والبحث عن المستخدمين في صفحة إرسال الإشعارات."""
    from django.http import JsonResponse
    from core.notifications_service import (
        CUSTOM_TARGET_ALL,
        preview_custom_notification_audience,
        search_custom_notification_users,
    )

    if 'q' in request.GET or request.GET.get('action') == 'search_users':
        q = (request.GET.get('q') or '').strip()
        role = (request.GET.get('role') or '').strip()
        return JsonResponse({
            'users': search_custom_notification_users(query=q, role=role, limit=25),
        })

    user_ids = request.GET.getlist('user_ids') or request.GET.get('user_ids', '')
    exclude_banned = str(request.GET.get('exclude_banned', '1')).lower() not in ('0', 'false', 'no')
    preview = preview_custom_notification_audience(
        target_mode=(request.GET.get('target_mode') or CUSTOM_TARGET_ALL).strip(),
        segment=(request.GET.get('segment') or '').strip(),
        user_ids=user_ids,
        grade=(request.GET.get('grade') or '').strip(),
        teacher_id=(request.GET.get('teacher_id') or '').strip(),
        plan_id=(request.GET.get('plan_id') or '').strip(),
        subject_id=(request.GET.get('subject_id') or '').strip(),
        exclude_banned=exclude_banned,
    )
    return JsonResponse(preview)
