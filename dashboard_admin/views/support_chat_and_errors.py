"""
dashboard_admin/views/support_chat_and_errors.py
صفحات لوحة إدارة الويب لشات الدعم المباشر وتقارير الأخطاء التقنية التلقائية.
"""
from django.contrib import messages
from django.db.models import Q, Sum
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string
from django.utils import timezone

from api_v1.views_support import append_support_message, serialize_support_message
from core.models import ClientErrorReport, SupportMessage, SupportThread
from dashboard_admin.decorators import admin_required
from dashboard_admin.models import AuditLog
from dashboard_admin.views.ajax import ajax_error, ajax_success, is_ajax_request
from dashboard_admin.views.base import _base_context


@admin_required
def admin_support_chat(request, thread_id=None):
    """إدارة محادثات الدعم المباشر والرد الفوري على الطلاب والمعلمين."""
    ctx = _base_context(request)
    if not ctx['can_manage_support']:
        msg = "ليس لديك صلاحية الوصول لمحادثات الدعم المباشر."
        if is_ajax_request(request):
            return ajax_error(msg, status=403)
        messages.error(request, msg)
        return redirect('admin_panel:dashboard')

    status_filter = str(request.GET.get('status') or '').strip().lower()
    search_query = str(request.GET.get('q') or '').strip()

    threads_qs = SupportThread.objects.select_related('user', 'assigned_admin').order_by('-last_message_at', '-id')
    if status_filter in (
        SupportThread.STATUS_OPEN,
        SupportThread.STATUS_PENDING,
        SupportThread.STATUS_CLOSED,
    ):
        threads_qs = threads_qs.filter(status=status_filter)

    if search_query:
        threads_qs = threads_qs.filter(
            Q(user__first_name__icontains=search_query)
            | Q(user__last_name__icontains=search_query)
            | Q(user__email__icontains=search_query)
            | Q(user__phone__icontains=search_query)
            | Q(user__custom_id__icontains=search_query)
            | Q(subject__icontains=search_query)
            | Q(last_message_preview__icontains=search_query)
        )

    threads = list(threads_qs[:80])

    is_ajax = is_ajax_request(request)
    is_partial = is_ajax and request.GET.get('partial') == '1'
    is_pane = is_ajax and request.GET.get('pane') == '1'
    is_poll = request.GET.get('poll') == '1'

    active_thread = None
    if thread_id is not None:
        active_thread = get_object_or_404(
            SupportThread.objects.select_related('user', 'assigned_admin'),
            pk=thread_id,
        )
    elif is_partial:
        raw_active = str(request.GET.get('active_thread_id') or '').strip()
        if raw_active.isdigit():
            active_thread = SupportThread.objects.select_related('user', 'assigned_admin').filter(
                pk=int(raw_active)
            ).first()
    elif threads:
        active_thread = threads[0]

    if request.method == 'POST':
        target_tid = thread_id or request.POST.get('thread_id')
        if not target_tid:
            if is_ajax:
                return ajax_error("لم يتم تحديد المحادثة.", status=400)
            return redirect('admin_panel:support_chat')

        target_thread = get_object_or_404(
            SupportThread.objects.select_related('user', 'assigned_admin'),
            pk=target_tid,
        )
        action = str(request.POST.get('action') or 'reply').strip().lower()

        if action == 'close':
            target_thread.status = SupportThread.STATUS_CLOSED
            target_thread.save(update_fields=['status', 'updated_at'])
            msg_text = "تم إغلاق المحادثة."
            if is_ajax:
                return ajax_success(msg_text, data={
                    'action': 'close',
                    'thread_id': target_thread.id,
                    'status': target_thread.status,
                })
            messages.info(request, msg_text)
            return redirect('admin_panel:support_chat_thread', thread_id=target_thread.id)

        if action == 'reopen':
            target_thread.status = SupportThread.STATUS_OPEN
            target_thread.save(update_fields=['status', 'updated_at'])
            msg_text = "تمت إعادة فتح المحادثة."
            if is_ajax:
                return ajax_success(msg_text, data={
                    'action': 'reopen',
                    'thread_id': target_thread.id,
                    'status': target_thread.status,
                })
            messages.success(request, msg_text)
            return redirect('admin_panel:support_chat_thread', thread_id=target_thread.id)

        body = str(request.POST.get('body') or '').strip()
        if not body:
            err_msg = "يرجى كتابة نص الرد أولاً."
            if is_ajax:
                return ajax_error(err_msg, errors={'body': [err_msg]}, status=400)
            messages.error(request, err_msg)
            return redirect('admin_panel:support_chat_thread', thread_id=target_thread.id)

        msg = append_support_message(
            thread=target_thread,
            sender=request.user,
            body=body[:4000],
            is_from_admin=True,
        )
        if is_ajax:
            return ajax_success(
                "تم إرسال الرد بنجاح.",
                data={
                    'message': serialize_support_message(msg),
                    'thread_id': target_thread.id,
                    'status': target_thread.status,
                    'preview': target_thread.last_message_preview,
                },
            )
        return redirect('admin_panel:support_chat_thread', thread_id=target_thread.id)

    if active_thread is not None and not is_partial:
        if active_thread.unread_for_admin:
            active_thread.unread_for_admin = 0
            active_thread.save(update_fields=['unread_for_admin'])
            for t in threads:
                if t.id == active_thread.id:
                    t.unread_for_admin = 0
            ctx['support_chat_unread_count'] = int(
                SupportThread.objects.aggregate(total=Sum('unread_for_admin')).get('total') or 0
            )
        SupportMessage.objects.filter(
            thread=active_thread,
            is_from_admin=False,
            is_read=False,
        ).update(is_read=True)

    if is_partial:
        ctx.update({
            'threads': threads,
            'active_thread': active_thread,
            'status_filter': status_filter,
            'search_query': search_query,
        })
        html = render_to_string('admin_panel/partials/_support_chat_threads.html', ctx, request=request)
        return ajax_success(data={
            'html': html,
            'total_unread': ctx['support_chat_unread_count'],
        })

    if is_pane:
        chat_messages = []
        if active_thread is not None:
            chat_messages = list(active_thread.messages.select_related('sender').order_by('-id')[:150])
            chat_messages.reverse()
        last_msg_id = chat_messages[-1].id if chat_messages else 0
        ctx.update({
            'active_thread': active_thread,
            'chat_messages': chat_messages,
            'last_msg_id': last_msg_id,
            'status_filter': status_filter,
            'search_query': search_query,
        })
        html = render_to_string('admin_panel/partials/_support_chat_pane.html', ctx, request=request)
        return ajax_success(data={
            'html': html,
            'thread_id': active_thread.id if active_thread else None,
            'last_msg_id': last_msg_id,
            'status': active_thread.status if active_thread else '',
            'total_unread': ctx['support_chat_unread_count'],
        })

    if is_poll:
        new_msgs = []
        if active_thread is not None:
            raw_after = str(request.GET.get('after_id') or '').strip()
            poll_qs = active_thread.messages.select_related('sender')
            if raw_after.isdigit():
                poll_qs = poll_qs.filter(id__gt=int(raw_after)).order_by('id')
            else:
                poll_qs = poll_qs.order_by('id')
            new_msgs = list(poll_qs[:100])
        threads_html = render_to_string(
            'admin_panel/partials/_support_chat_threads.html',
            {
                **ctx,
                'threads': threads,
                'active_thread': active_thread,
                'status_filter': status_filter,
                'search_query': search_query,
            },
            request=request,
        )
        return JsonResponse({
            'success': True,
            'messages': [serialize_support_message(m) for m in new_msgs],
            'thread_status': active_thread.status if active_thread else '',
            'total_unread': ctx['support_chat_unread_count'],
            'threads_html': threads_html,
        })

    chat_messages = []
    if active_thread is not None:
        chat_messages = list(active_thread.messages.select_related('sender').order_by('-id')[:150])
        chat_messages.reverse()

    ctx.update({
        'threads': threads,
        'active_thread': active_thread,
        'chat_messages': chat_messages,
        'last_msg_id': chat_messages[-1].id if chat_messages else 0,
        'status_filter': status_filter,
        'search_query': search_query,
    })
    return render(request, 'admin_panel/support_chat.html', ctx)


def _get_error_report_stats():
    """إرجاع إحصاءات تقارير الأخطاء التقنية بصيغة موحدة."""
    unresolved_count = ClientErrorReport.objects.filter(is_resolved=False).count()
    total_count = ClientErrorReport.objects.count()
    resolved_count = max(0, total_count - unresolved_count)
    total_occurrences = int(
        ClientErrorReport.objects.aggregate(total=Sum('occurrences')).get('total') or 0
    )
    return {
        'unresolved': unresolved_count,
        'resolved': resolved_count,
        'total': total_count,
        'occurrences': total_occurrences,
    }


@admin_required
def admin_error_reports(request):
    """عرض وإدارة تقارير الأخطاء التقنية المرسلة تلقائياً من أجهزة المستخدمين."""
    ctx = _base_context(request)
    if not ctx['can_manage_users']:
        msg = "ليس لديك صلاحية عرض تقارير الأخطاء التقنية."
        if is_ajax_request(request):
            return ajax_error(msg, status=403)
        messages.error(request, msg)
        return redirect('admin_panel:dashboard')

    if request.method == 'POST':
        action = str(request.POST.get('action') or '').strip().lower()
        report_id = request.POST.get('report_id')

        if action == 'resolve_all':
            updated = ClientErrorReport.objects.filter(is_resolved=False).update(
                is_resolved=True,
                resolved_at=timezone.now(),
                resolved_by=request.user,
            )
            AuditLog.log(
                request,
                AuditLog.ACTION_EDIT_USER,
                target_label='إغلاق جميع تقارير الأخطاء التقنية',
                details={'updated': updated},
            )
            msg = f"تم تعليم {updated} تقرير خطأ كمُعالج."
            stats = _get_error_report_stats()
            if is_ajax_request(request):
                return ajax_success(msg, data={
                    'action': 'resolve_all',
                    'stats': stats,
                })
            messages.success(request, msg)
            return redirect('admin_panel:error_reports')

        report = get_object_or_404(ClientErrorReport, pk=report_id)
        if action == 'resolve':
            report.is_resolved = True
            report.resolved_at = timezone.now()
            report.resolved_by = request.user
            report.save(update_fields=['is_resolved', 'resolved_at', 'resolved_by'])
            msg = "تم تحديد الخطأ كمُعالج."
        elif action == 'reopen':
            report.is_resolved = False
            report.resolved_at = None
            report.resolved_by = None
            report.save(update_fields=['is_resolved', 'resolved_at', 'resolved_by'])
            msg = "تمت إعادة فتح تقرير الخطأ."
        elif action == 'delete':
            report.delete()
            msg = "تم حذف تقرير الخطأ."
        else:
            if is_ajax_request(request):
                return ajax_error("إجراء غير معروف.", status=400)
            messages.error(request, "إجراء غير معروف.")
            return redirect('admin_panel:error_reports')

        stats = _get_error_report_stats()
        if is_ajax_request(request):
            return ajax_success(
                msg,
                data={
                    'action': action,
                    'report_id': report_id,
                    'stats': stats,
                },
            )
        messages.success(request, msg)
        return redirect('admin_panel:error_reports')

    status_filter = str(request.GET.get('status') or 'unresolved').strip().lower()
    search_query = str(request.GET.get('q') or '').strip()

    qs = ClientErrorReport.objects.select_related('user', 'resolved_by').order_by('-last_seen_at', '-id')
    if status_filter == 'unresolved':
        qs = qs.filter(is_resolved=False)
    elif status_filter == 'resolved':
        qs = qs.filter(is_resolved=True)

    if search_query:
        qs = qs.filter(
            Q(error_message__icontains=search_query)
            | Q(error_type__icontains=search_query)
            | Q(screen__icontains=search_query)
            | Q(user__email__icontains=search_query)
            | Q(user__first_name__icontains=search_query)
        )

    stats = _get_error_report_stats()
    ctx.update({
        'reports': list(qs[:80]),
        'status_filter': status_filter,
        'search_query': search_query,
        'unresolved_count': stats['unresolved'],
        'resolved_count': stats['resolved'],
        'total_count': stats['total'],
        'total_occurrences': stats['occurrences'],
    })

    if is_ajax_request(request) and request.GET.get('partial') == '1':
        html = render_to_string('admin_panel/partials/_error_reports_list.html', ctx, request=request)
        return ajax_success(data={
            'html': html,
            'status_filter': status_filter,
            'search_query': search_query,
            'stats': stats,
        })

    return render(request, 'admin_panel/error_reports.html', ctx)
