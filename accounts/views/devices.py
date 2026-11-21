"""accounts.views.devices
Extracted from accounts/views.py.
"""

from django.shortcuts import (
    render,
    redirect,
)
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.utils.translation import gettext as _
from django.views.decorators.http import require_POST
import json
from django.contrib.auth import logout


@login_required
def web_trusted_devices(request):
    """
    شاشة إدارة الأجهزة المتصلة (تطبيق الأندرويد ومتصفحات الويب) على موقع المنصة،
    تتيح عرض حد الأجهزة، إنهاء جلسة، إلغاء تفويض جهاز، أو الإبلاغ عن جهاز غير مألوف.
    """
    from api_v1.device_security_service import (
        WEB_PACKAGE_NAME,
        build_web_device_info,
        check_device_allowed,
        get_or_create_web_installation_id,
        get_user_device_limit,
        record_security_event,
        register_or_update_device,
        revoke_user_device,
        serialize_device_summary,
    )
    from api_v1.models import DeviceTrustStatus, RegisteredDevice

    user = request.user
    installation_id = get_or_create_web_installation_id(request)
    if not request.session.session_key:
        request.session.save()

    def _try_activate_current_browser() -> bool:
        reg = register_or_update_device(
            request=request,
            user=user,
            installation_id=installation_id,
            device_info=build_web_device_info(request),
            token_jti=f"web:{request.session.session_key or installation_id[:24]}",
        )
        if reg.get('allowed'):
            request.session['web_device_registered_id'] = installation_id
            request.session['web_device_session_uuid'] = reg.get('session_uuid', '')
            request.session.pop('web_device_limit_error', None)
            return True
        if reg.get('error'):
            request.session['web_device_limit_error'] = reg['error']
        return False

    if request.method == 'POST':
        action = (request.POST.get('action') or '').strip()

        if action == 'activate_current':
            if _try_activate_current_browser():
                messages.success(request, _("تم تفعيل وتسجيل هذا المتصفح بنجاح."))
            else:
                err = request.session.get('web_device_limit_error') or _(
                    "تعذر تسجيل هذا المتصفح. يرجى إزالة أحد الأجهزة القديمة أولاً."
                )
                messages.error(request, err)
            return redirect('web_trusted_devices')

        device_uuid = (request.POST.get('device_uuid') or '').strip()
        device = None
        if device_uuid:
            try:
                device = RegisteredDevice.objects.filter(user=user, device_uuid=device_uuid).first()
            except Exception:
                device = None

        if device is None:
            messages.error(request, _("الجهاز المطلوب غير موجود أو لا ينتمي لحسابك."))
            return redirect('web_trusted_devices')

        is_same_browser = device.installation_id == installation_id

        if action == 'revoke':
            revoke_user_device(
                device=device,
                actor=user,
                request=request,
                mode='revoke',
                reason='Revoked by user from web trusted devices panel',
            )
            if is_same_browser:
                request.session.pop('web_device_registered_id', None)
                request.session.pop('web_device_session_uuid', None)
                logout(request)
                messages.info(request, _("تم إلغاء تفويض هذا المتصفح وتسجيل الخروج منه."))
                return redirect('account_login')

            if request.session.get('web_device_limit_error') and _try_activate_current_browser():
                messages.success(request, _("تم إلغاء تفويض الجهاز المحدد وتفعيل متصفحك الحالي تلقائيًا."))
            else:
                messages.success(request, _("تم إلغاء تفويض الجهاز وإنهاء كافة جلساته بنجاح."))
            return redirect('web_trusted_devices')

        if action == 'logout':
            revoke_user_device(
                device=device,
                actor=user,
                request=request,
                mode='logout',
                reason='Logged out remotely from web trusted devices panel',
            )
            if is_same_browser:
                request.session.pop('web_device_registered_id', None)
                request.session.pop('web_device_session_uuid', None)
                logout(request)
                messages.info(request, _("تم تسجيل الخروج من هذا المتصفح."))
                return redirect('account_login')

            messages.success(request, _("تم إنهاء الجلسة النشطة على الجهاز المحدد."))
            return redirect('web_trusted_devices')

        if action == 'report_unfamiliar':
            reason = (request.POST.get('reason') or '').strip()[:255] or _(
                "أبلغ المستخدم أن هذا الجهاز غير مألوف له عبر لوحة الويب"
            )
            revoke_user_device(
                device=device,
                actor=user,
                request=request,
                mode='revoke',
                reason=str(reason),
            )
            device.unfamiliar_reported = True
            device.save(update_fields=['unfamiliar_reported', 'updated_at'])
            record_security_event(
                event_type='unfamiliar_device_reported',
                severity='high',
                risk_score=35,
                user=user,
                device=device,
                installation_id=device.installation_id,
                request=request,
                action_taken='device_revoked_and_flagged',
                details={'reason': str(reason), 'source': 'web'},
            )
            if is_same_browser:
                request.session.pop('web_device_registered_id', None)
                request.session.pop('web_device_session_uuid', None)
                logout(request)
                messages.warning(request, _("تم تسجيل الخروج وحظر الجلسة وتوثيق بلاغ الجهاز غير المألوف."))
                return redirect('account_login')

            if request.session.get('web_device_limit_error'):
                _try_activate_current_browser()
            messages.warning(request, _("تم تسجيل البلاغ وإلغاء تفويض الجهاز المريب فورًا."))
            return redirect('web_trusted_devices')

        messages.warning(request, _("إجراء غير معروف."))
        return redirect('web_trusted_devices')

    devices_qs = RegisteredDevice.objects.filter(user=user).order_by('-is_active', '-last_active_at')
    device_limit = get_user_device_limit(user)
    active_count = devices_qs.filter(is_active=True).exclude(
        trust_status__in=[DeviceTrustStatus.REVOKED, DeviceTrustStatus.BLOCKED]
    ).count()
    current_allowed, current_code, current_err = check_device_allowed(user, installation_id)

    if current_allowed:
        request.session.pop('web_device_limit_error', None)
        limit_error = ''
    else:
        limit_error = request.session.get('web_device_limit_error') or current_err or ''

    device_rows = []
    for dev in devices_qs:
        summary = serialize_device_summary(dev, current_installation_id=installation_id)
        device_rows.append({
            'device': dev,
            'summary': summary,
            'is_web': dev.package_name == WEB_PACKAGE_NAME,
            'is_current': summary['is_current_device'],
            'current_session_active': summary['current_session_active'],
        })

    return render(request, 'accounts/devices.html', {
        'device_rows': device_rows,
        'device_limit': device_limit,
        'active_count': active_count,
        'current_installation_id': installation_id,
        'current_allowed': current_allowed,
        'current_code': current_code,
        'limit_error': limit_error,
    })


@login_required
@require_POST
def web_device_traits_sync(request):
    """
    يستقبل خصائص المتصفح غير الحساسة (الدقة، معالج الرسوميات WebGL، المنطقة الزمنية، إشارات WebDriver)
    ليدمجها مع ترويسات الطلب في الخادم وتحديث بصمة fp_v1 وتقييم المخاطر.
    """
    user = request.user
    if getattr(user, 'is_superuser', False) or getattr(user, 'role', '') == 'admin':
        return JsonResponse({'ok': True, 'skipped': 'admin'})

    from api_v1.device_security_service import (
        build_web_device_info,
        check_web_ios_only_lecture_access,
        get_or_create_web_installation_id,
        register_or_update_device,
    )

    payload: dict = {}
    if request.content_type and 'application/json' in request.content_type:
        try:
            loaded = json.loads((request.body or b'{}').decode('utf-8'))
            if isinstance(loaded, dict):
                payload = loaded
        except Exception:
            payload = {}
    else:
        payload = request.POST.dict()

    client_traits = {
        'cpu_arch': payload.get('cpu_arch', ''),
        'cpu_info': payload.get('cpu_info', ''),
        'gpu_renderer': payload.get('gpu_renderer', ''),
        'gpu_vendor': payload.get('gpu_vendor', ''),
        'screen_resolution': payload.get('screen_resolution', ''),
        'timezone': payload.get('timezone', ''),
        'webdriver_detected': bool(payload.get('webdriver_detected')),
        'canvas_hash': payload.get('canvas_hash', ''),
        'webgl_hash': payload.get('webgl_hash', ''),
        'audio_hash': payload.get('audio_hash', ''),
        'navigator_platform': payload.get('navigator_platform', ''),
        'max_touch_points': payload.get('max_touch_points'),
        'touch_support': payload.get('touch_support'),
        'color_depth': payload.get('color_depth', ''),
        'languages': payload.get('languages', ''),
    }

    installation_id = get_or_create_web_installation_id(request)
    if not request.session.session_key:
        request.session.save()

    reg = register_or_update_device(
        request=request,
        user=user,
        installation_id=installation_id,
        device_info=build_web_device_info(request, client_traits=client_traits),
        token_jti=f"web:{request.session.session_key or installation_id[:24]}",
    )
    if reg.get('allowed'):
        request.session['web_device_registered_id'] = installation_id
        request.session['web_device_session_uuid'] = reg.get('session_uuid', '')
        request.session.pop('web_device_limit_error', None)
        dev_summary = reg.get('device') or {}
        dev_obj = reg.get('device_obj')
        ios_res = check_web_ios_only_lecture_access(
            request,
            user,
            client_traits=client_traits,
            force_web=True,
        )
        return JsonResponse({
            'ok': True,
            'fingerprint': getattr(dev_obj, 'current_fingerprint', '') if dev_obj else '',
            'trust_status': dev_summary.get('trust_status', ''),
            'risk_score': dev_summary.get('risk_score', 0),
            'risk_level': dev_summary.get('risk_level', 'low'),
            'ios_lecture_allowed': bool(ios_res.get('allowed')),
            'device_kind': ios_res.get('device_kind', ''),
        })

    if reg.get('code') == 'WEB_FINGERPRINT_MISMATCH':
        request.session.pop('web_device_registered_id', None)
        request.session.pop('web_device_session_uuid', None)

    return JsonResponse({
        'ok': False,
        'code': reg.get('code', 'DEVICE_NOT_ALLOWED'),
        'error': reg.get('error', ''),
    }, status=403)
