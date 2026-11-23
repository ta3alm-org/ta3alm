"""dashboard_admin.views.support
Extracted from dashboard_admin/views.py.
"""

from django.shortcuts import (
    render,
    redirect,
)
from django.contrib import messages
from core.notifications_service import maybe_notify_zoho_inbox
from dashboard_admin.models import AuditLog
from dashboard_admin.decorators import admin_required
from services.zoho_mail_service import ZohoMailService
from django.urls import reverse
import logging

from django.template.loader import render_to_string

from dashboard_admin.views.base import _base_context
from dashboard_admin.views.ajax import (
    ajax_error,
    ajax_success,
    is_ajax_request,
)

logger = logging.getLogger('dashboard_admin.views')


@admin_required
def support_inbox(request):
    """صندوق البريد الوارد لإيميلات الدعم الفني support@ta3alm.online"""
    ctx = _base_context(request)
    if not ctx['can_manage_support']:
        msg = "ليس لديك صلاحية الوصول لصندوق الدعم الفني."
        if is_ajax_request(request):
            return ajax_error(msg, status=403)
        messages.error(request, msg)
        return redirect('admin_panel:dashboard')

    service = ZohoMailService()
    ctx['is_configured'] = service.is_configured()
    ctx['is_connected'] = service.is_connected()
    ctx['support_email'] = service.support_email
    ctx['messages_list'] = []
    ctx['error_message'] = None
    ctx['search_query'] = request.GET.get('q', '').strip()

    if service.is_connected():
        try:
            res = service.list_messages(limit=30, search_key=ctx['search_query'] or None)
            raw_data = res.get('data', []) if isinstance(res, dict) else []
            ctx['messages_list'] = raw_data
            maybe_notify_zoho_inbox(raw_data)
        except Exception as e:
            ctx['error_message'] = str(e)
            logger.error("Zoho list messages view error: %s", e)

    if is_ajax_request(request) and request.GET.get('partial') == '1':
        html = render_to_string('admin_panel/partials/_support_inbox_table.html', ctx, request=request)
        return ajax_success(
            data={
                'html': html,
                'count': len(ctx['messages_list']),
                'search_query': ctx['search_query'],
                'error_message': ctx['error_message'],
            }
        )

    return render(request, 'admin_panel/support_inbox.html', ctx)


def _sanitize_email_html(raw_html: str) -> str:
    """ينقّي محتوى البريد الإلكتروني HTML من الوسوم والخصائص التنفيذية الخطرة قبل العرض المعزول."""
    import re as _re

    if not raw_html:
        return ''
    cleaned = str(raw_html)
    for tag in ('script', 'iframe', 'object', 'embed', 'form'):
        cleaned = _re.sub(
            rf'<{tag}\b[^>]*>.*?</{tag}>',
            '',
            cleaned,
            flags=_re.IGNORECASE | _re.DOTALL,
        )
        cleaned = _re.sub(
            rf'</?{tag}\b[^>]*>',
            '',
            cleaned,
            flags=_re.IGNORECASE,
        )
    cleaned = _re.sub(r'</?(?:meta|base)\b[^>]*>', '', cleaned, flags=_re.IGNORECASE)
    cleaned = _re.sub(
        r'\s+on[a-z]+\s*=\s*(?:"[^"]*"|\'[^\']*\'|[^\s>]+)',
        '',
        cleaned,
        flags=_re.IGNORECASE,
    )
    cleaned = _re.sub(
        r'(href|src|action|formaction|xlink:href)\s*=\s*(["\']?)\s*(?:javascript|vbscript|data:text/html):[^\2\s>]*\2',
        r'\1=\2#\2',
        cleaned,
        flags=_re.IGNORECASE,
    )
    return cleaned


@admin_required
def support_message_detail(request, message_id):
    """عرض تفاصيل البريد الإلكتروني مع نموذج الرد المباشر"""
    ctx = _base_context(request)
    if not ctx['can_manage_support']:
        messages.error(request, "ليس لديك صلاحية الوصول لصندوق الدعم الفني.")
        return redirect('admin_panel:dashboard')

    service = ZohoMailService()
    if not service.is_connected():
        messages.warning(request, "يرجى ربط حساب Zoho Mail أولاً.")
        return redirect('admin_panel:support_settings')

    folder_id = request.GET.get('folder_id')
    msg_metadata = {}
    try:
        raw_msgs = service.list_messages(limit=50).get('data', [])
        for m in raw_msgs:
            if str(m.get('messageId')) == str(message_id):
                msg_metadata = m
                if not folder_id:
                    folder_id = m.get('folderId')
                break
    except Exception as e:
        logger.warning("Could not pre-fetch message metadata: %s", e)

    try:
        msg_data = service.get_message_content(message_id, folder_id=folder_id)
        data = msg_data.get('data', {}) if isinstance(msg_data, dict) else {}
        
        # دمج الميتاداتا (الموضوع، المرسل، التاريخ) مع جسم الرسالة وتنقيته
        merged = dict(msg_metadata)
        if isinstance(data, dict):
            merged.update(data)
        merged['sanitized_content'] = _sanitize_email_html(merged.get('content', ''))

        ctx['message_data'] = merged
        ctx['message_id'] = message_id
        ctx['support_email'] = service.support_email
    except Exception as e:
        messages.error(request, f"فشل جلب تفاصيل الرسالة: {e}")
        return redirect('admin_panel:support_inbox')

    return render(request, 'admin_panel/support_message_detail.html', ctx)


@admin_required
def support_send_reply(request):
    """إرسال رد على رسالة عبر Zoho Mail API"""
    if request.method != 'POST':
        if is_ajax_request(request):
            return ajax_error("طريقة الطلب غير مدعومة.", status=405)
        return redirect('admin_panel:support_inbox')

    ctx = _base_context(request)
    if not ctx['can_manage_support']:
        msg = "ليس لديك صلاحية الرد على إيميلات الدعم."
        if is_ajax_request(request):
            return ajax_error(msg, status=403)
        messages.error(request, msg)
        return redirect('admin_panel:dashboard')

    to_email = request.POST.get('to_email', '').strip()
    subject = request.POST.get('subject', '').strip()
    content = request.POST.get('content', '').strip()
    message_id = request.POST.get('message_id', '').strip()

    if not to_email or not content:
        msg = "يرجى كتابة البريد الإلكتروني ومحتوى الرد."
        if is_ajax_request(request):
            errs = {}
            if not to_email:
                errs['to_email'] = ["يرجى إدخال البريد الإلكتروني للمرسل إليه."]
            if not content:
                errs['content'] = ["يرجى كتابة محتوى الرد."]
            return ajax_error(msg, errors=errs, status=400)
        messages.error(request, msg)
        if message_id:
            return redirect('admin_panel:support_message_detail', message_id=message_id)
        return redirect('admin_panel:support_inbox')

    service = ZohoMailService()
    try:
        service.send_reply(to_email=to_email, subject=subject, content=content, message_id=message_id or None)
        AuditLog.log(
            request,
            AuditLog.ACTION_ZOHO_REPLY,
            target_label=f"إرسال رد إلى {to_email}",
            details={'to': to_email, 'subject': subject, 'message_id': message_id}
        )
        msg = f"تم إرسال الرد بنجاح إلى {to_email} من {service.support_email}!"
        if is_ajax_request(request):
            return ajax_success(msg, data={'to_email': to_email, 'subject': subject})
        messages.success(request, msg)
    except Exception as e:
        logger.error("Failed to send reply: %s", e)
        err_msg = f"فشل إرسال الرد عبر Zoho: {e}"
        if is_ajax_request(request):
            return ajax_error(err_msg, status=502)
        messages.error(request, err_msg)

    if message_id:
        return redirect('admin_panel:support_message_detail', message_id=message_id)
    return redirect('admin_panel:support_inbox')


@admin_required
def support_compose(request):
    """إنشاء وإرسال رسالة جديدة لأي مستخدم من support@ta3alm.online"""
    if request.method != 'POST':
        if is_ajax_request(request):
            return ajax_error("طريقة الطلب غير مدعومة.", status=405)
        return redirect('admin_panel:support_inbox')

    ctx = _base_context(request)
    if not ctx['can_manage_support']:
        msg = "ليس لديك صلاحية إرسال إيميلات الدعم."
        if is_ajax_request(request):
            return ajax_error(msg, status=403)
        messages.error(request, msg)
        return redirect('admin_panel:dashboard')

    to_email = request.POST.get('to_email', '').strip()
    subject = request.POST.get('subject', '').strip()
    content = request.POST.get('content', '').strip()

    if not to_email or not subject or not content:
        msg = "جميع الحقول (المستقبل، الموضوع، المحتوى) مطلوبة."
        if is_ajax_request(request):
            errs = {}
            if not to_email:
                errs['to_email'] = ["يرجى إدخال البريد الإلكتروني."]
            if not subject:
                errs['subject'] = ["يرجى إدخال الموضوع."]
            if not content:
                errs['content'] = ["يرجى كتابة نص الرسالة."]
            return ajax_error(msg, errors=errs, status=400)
        messages.error(request, msg)
        return redirect('admin_panel:support_inbox')

    service = ZohoMailService()
    try:
        service.compose_new_message(to_email=to_email, subject=subject, content=content)
        AuditLog.log(
            request,
            AuditLog.ACTION_ZOHO_COMPOSE,
            target_label=f"رسالة جديدة إلى {to_email}",
            details={'to': to_email, 'subject': subject}
        )
        msg = f"تم إرسال الرسالة بنجاح إلى {to_email}!"
        if is_ajax_request(request):
            return ajax_success(msg, data={'to_email': to_email, 'subject': subject})
        messages.success(request, msg)
    except Exception as e:
        err_msg = f"فشل إرسال الرسالة: {e}"
        if is_ajax_request(request):
            return ajax_error(err_msg, status=502)
        messages.error(request, err_msg)

    return redirect('admin_panel:support_inbox')


@admin_required
def support_settings(request):
    """صفحة إعدادات وحالة اتصال Zoho Mail REST API"""
    ctx = _base_context(request)
    if not ctx['is_owner']:
        msg = "إعدادات الربط متاحة لمالك المنصة فقط."
        if is_ajax_request(request):
            return ajax_error(msg, status=403)
        messages.error(request, msg)
        return redirect('admin_panel:support_inbox')

    from dashboard_admin.models import ZohoMailConfig
    config = ZohoMailConfig.load()
    service = ZohoMailService(config=config)

    redirect_uri = request.build_absolute_uri(reverse('admin_panel:support_oauth_callback'))
    ctx['redirect_uri'] = redirect_uri
    ctx['config'] = config
    ctx['service'] = service

    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'save_keys':
            config.client_id = request.POST.get('client_id', '').strip()
            config.client_secret = request.POST.get('client_secret', '').strip()
            config.support_email = request.POST.get('support_email', '').strip() or 'support@ta3alm.online'
            refresh_token = request.POST.get('refresh_token', '').strip()
            if refresh_token:
                config.refresh_token = refresh_token
            config.save()
            msg = "تم حفظ الإعدادات بنجاح."
            if is_ajax_request(request):
                service = ZohoMailService(config=config)
                return ajax_success(
                    msg,
                    data={
                        'action': 'save_keys',
                        'is_connected': service.is_connected(),
                        'is_configured': service.is_configured(),
                        'support_email': config.get_effective_support_email(),
                    },
                )
            messages.success(request, msg)
            return redirect('admin_panel:support_settings')
        elif action == 'disconnect':
            config.refresh_token = ''
            config.access_token = ''
            config.account_id = ''
            config.token_expires_at = None
            config.save()
            msg = "تم قطع الاتصال بـ Zoho Mail."
            if is_ajax_request(request):
                service = ZohoMailService(config=config)
                return ajax_success(
                    msg,
                    data={
                        'action': 'disconnect',
                        'is_connected': service.is_connected(),
                        'is_configured': service.is_configured(),
                        'support_email': config.get_effective_support_email(),
                    },
                )
            messages.info(request, msg)
            return redirect('admin_panel:support_settings')
        elif is_ajax_request(request):
            return ajax_error("إجراء غير معروف.", status=400)

    return render(request, 'admin_panel/support_settings.html', ctx)


@admin_required
def support_oauth_connect(request):
    """بدء جلسة المصادقة السريعة عبر OAuth 2.0 في Zoho"""
    service = ZohoMailService()
    if not service.client_id:
        messages.error(request, "يرجى إدخال Client ID أولاً في الإعدادات قبل بدء الربط.")
        return redirect('admin_panel:support_settings')

    redirect_uri = request.build_absolute_uri(reverse('admin_panel:support_oauth_callback'))
    auth_url = service.get_authorization_url(redirect_uri=redirect_uri)
    return redirect(auth_url)


@admin_required
def support_oauth_callback(request):
    """استقبال الكود من Zoho وحفظ التوكنات تلقائياً"""
    error = request.GET.get('error')
    if error:
        messages.error(request, f"تم رفض التخويل من Zoho أو حدث خطأ: {error}")
        return redirect('admin_panel:support_settings')

    code = request.GET.get('code')
    if not code:
        messages.error(request, "لم يتم استلام كود التخويل من Zoho.")
        return redirect('admin_panel:support_settings')

    service = ZohoMailService()
    redirect_uri = request.build_absolute_uri(reverse('admin_panel:support_oauth_callback'))
    try:
        service.exchange_code(code=code, redirect_uri=redirect_uri)
        messages.success(request, "تم ربط بريد Zoho Mail بنجاح! يمكنك الآن إدارة الرسائل والرد عليها مباشرة.")
        return redirect('admin_panel:support_inbox')
    except Exception as e:
        messages.error(request, str(e))
        return redirect('admin_panel:support_settings')
