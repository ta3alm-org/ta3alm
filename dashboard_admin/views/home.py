"""dashboard_admin.views.home
Extracted from dashboard_admin/views.py.
"""

from django.shortcuts import (
    render,
    redirect,
)
from django.contrib import messages
from django.utils import timezone
from teachers.models import TeacherProfile
from accounts.models import StudentProfile
from assistants.models import AssistantProfile
from core.models import SiteSetting
from dashboard_admin.models import AuditLog
from dashboard_admin.decorators import (
    admin_required,
    owner_required,
)

from dashboard_admin.views.base import _base_context
from dashboard_admin.views.ajax import (
    ajax_error,
    ajax_success,
    is_ajax_request,
)


def _app_release_preview_data(request, site_settings):
    """بناء بيانات معاينة إعدادات إصدار الأندرويد وملف assetlinks.json."""
    import json
    import os

    package_name = (
        os.environ.get('PLAY_INTEGRITY_PACKAGE_NAME', 'online.ta3alm.ta3alm_flutter').strip()
        or 'online.ta3alm.ta3alm_flutter'
    )
    fingerprints = site_settings.get_assetlinks_fingerprints()
    packages = [package_name]
    if not package_name.endswith('.debug'):
        packages.append(f'{package_name}.debug')
    assetlinks_preview = json.dumps(
        [
            {
                'relation': ['delegate_permission/common.handle_all_urls'],
                'target': {
                    'namespace': 'android_app',
                    'package_name': pkg,
                    'sha256_cert_fingerprints': fingerprints,
                },
            }
            for pkg in packages
        ],
        ensure_ascii=False,
        indent=2,
    )
    return {
        'effective_apk_url': site_settings.get_effective_apk_url(request=request),
        'assetlinks_fingerprints': fingerprints,
        'assetlinks_preview': assetlinks_preview,
        'env_sha256_configured': bool(
            os.environ.get('ANDROID_ASSETLINKS_SHA256', '').strip()
            or os.environ.get('ANDROID_RELEASE_CERT_SHA256', '').strip()
        ),
    }


def _app_release_ajax_payload(request, site_settings):
    """حزمة JSON الموحّدة لحالة إصدار التطبيق بعد التحديث."""
    preview_data = _app_release_preview_data(request, site_settings)
    return {
        'latest_version_code': site_settings.android_latest_version_code,
        'min_required_version_code': site_settings.android_min_required_version_code,
        'latest_version_name': site_settings.android_latest_version_name,
        'force_update': bool(site_settings.android_force_update),
        'android_apk_url': site_settings.android_apk_url,
        'android_apk_sha256': site_settings.android_apk_sha256,
        'effective_apk_url': preview_data['effective_apk_url'],
        'has_apk_file': bool(site_settings.android_apk_file),
        'apk_file_name': site_settings.android_apk_file.name if site_settings.android_apk_file else '',
        'assetlinks_fingerprints_count': len(preview_data['assetlinks_fingerprints']),
        'assetlinks_preview': preview_data['assetlinks_preview'],
    }


# ==========================================================
# 1. لوحة الإحصاءات الرئيسية (Dashboard)
# ==========================================================
@admin_required
def dashboard(request):
    ctx = _base_context(request)

    # إحصاءات
    ctx['total_teachers']   = TeacherProfile.objects.count()
    ctx['total_students']   = StudentProfile.objects.count()
    ctx['total_assistants'] = AssistantProfile.objects.count()

    # ✅ إصلاح N+1: استعلام واحد يستخدم filter بدلاً من Python loop
    ctx['active_teachers_count'] = TeacherProfile.objects.filter(
        subscription_end_date__gt=timezone.now()
    ).count()

    # آخر الأحداث
    ctx['recent_logs'] = AuditLog.objects.select_related('admin').order_by('-created_at')[:10]

    return render(request, 'admin_panel/dashboard.html', ctx)


# ==========================================================
# 2. تبديل وضع الصيانة
# ==========================================================
@owner_required
def toggle_maintenance(request):
    if request.method == 'POST':
        settings = SiteSetting.load()
        settings.is_maintenance_mode = not settings.is_maintenance_mode
        settings.save()
        status = "تفعيل" if settings.is_maintenance_mode else "إلغاء"
        AuditLog.log(request, AuditLog.ACTION_TOGGLE_MAINT,
                     details={'maintenance': settings.is_maintenance_mode})
        msg = f"تم {status} وضع الصيانة."
        if is_ajax_request(request):
            return ajax_success(msg, data={'is_maintenance_mode': settings.is_maintenance_mode})
        messages.warning(request, msg)
    elif is_ajax_request(request):
        return ajax_error("طريقة الطلب غير مدعومة.", status=405)
    return redirect('admin_panel:dashboard')


@owner_required
def update_platform_commission(request):
    if request.method == 'POST':
        raw_val = request.POST.get('platform_commission_percentage')
        try:
            commission = int(raw_val)
        except (TypeError, ValueError):
            msg = "يرجى إدخال نسبة عمولة صحيحة بين 0 و 100."
            if is_ajax_request(request):
                return ajax_error(msg, errors={'platform_commission_percentage': [msg]}, status=400)
            messages.error(request, msg)
            return redirect(request.META.get('HTTP_REFERER') or 'admin_panel:dashboard')

        if commission < 0 or commission > 100:
            msg = "يجب أن تكون نسبة العمولة بين 0% و 100%."
            if is_ajax_request(request):
                return ajax_error(msg, errors={'platform_commission_percentage': [msg]}, status=400)
            messages.error(request, msg)
            return redirect(request.META.get('HTTP_REFERER') or 'admin_panel:dashboard')

        site_settings = SiteSetting.load()
        site_settings.platform_commission_percentage = commission
        site_settings.save()
        AuditLog.log(
            request,
            AuditLog.ACTION_EDIT_USER,
            target_label='تحديث عمولة المنصة',
            details={'platform_commission_percentage': commission},
        )
        msg = f"تم تحديث نسبة عمولة المنصة إلى {commission}%."
        if is_ajax_request(request):
            return ajax_success(msg, data={'platform_commission_percentage': commission})
        messages.success(request, msg)
    elif is_ajax_request(request):
        return ajax_error("طريقة الطلب غير مدعومة.", status=405)
    return redirect(request.META.get('HTTP_REFERER') or 'admin_panel:dashboard')


def _apply_app_release_post(request, site_settings):
    """منطق موحّد لحفظ إعدادات إصدار التطبيق ورابط GitHub APK وبصمة App Links."""
    import hashlib

    old_url = SiteSetting.normalize_apk_download_url(site_settings.android_apk_url)
    old_version_code = int(site_settings.android_latest_version_code or 1)
    old_sha = SiteSetting.normalize_file_sha256(site_settings.android_apk_sha256)

    try:
        latest_code = max(
            1,
            int(request.POST.get('android_latest_version_code', site_settings.android_latest_version_code or 1)),
        )
    except (TypeError, ValueError):
        return False, "يرجى إدخال رقم بناء أحدث صحيح."

    try:
        min_code = max(
            1,
            int(request.POST.get('android_min_required_version_code', site_settings.android_min_required_version_code or 1)),
        )
    except (TypeError, ValueError):
        return False, "يرجى إدخال أقل رقم بناء مسموح صحيح."

    apk_url = SiteSetting.normalize_apk_download_url(request.POST.get('android_apk_url', ''))[:500]
    if apk_url and not apk_url.lower().startswith(('https://', 'http://')):
        return False, "يجب أن يبدأ رابط ملف APK بـ https:// أو http://."

    site_settings.android_latest_version_code = latest_code
    site_settings.android_min_required_version_code = min_code
    site_settings.android_latest_version_name = str(
        request.POST.get('android_latest_version_name', site_settings.android_latest_version_name or '1.0.0')
    ).strip()[:32]
    site_settings.android_apk_url = apk_url
    site_settings.android_update_release_notes = str(
        request.POST.get('android_update_release_notes', '')
    ).strip()
    site_settings.android_force_update = request.POST.get('android_force_update') in ('1', 'true', 'on', 'yes')
    raw_manual_sha = str(request.POST.get('android_apk_sha256', '')).strip()
    manual_sha = SiteSetting.normalize_file_sha256(raw_manual_sha) if raw_manual_sha else ''
    if raw_manual_sha and not manual_sha:
        return False, "صيغة بصمة SHA-256 لملف APK غير صالحة (يجب أن تكون 64 حرفاً Hex، ويمكن نسخها من GitHub حتى لو بدأت بـ sha256:)."

    if 'android_assetlinks_sha256' in request.POST:
        site_settings.android_assetlinks_sha256 = str(
            request.POST.get('android_assetlinks_sha256', '')
        ).strip()

    if request.POST.get('clear_uploaded_apk') in ('1', 'true', 'on', 'yes') and site_settings.android_apk_file:
        try:
            site_settings.android_apk_file.delete(save=False)
        except Exception:
            pass
        site_settings.android_apk_file = None

    stale_sha_cleared = False
    uploaded_apk = request.FILES.get('android_apk_file')
    if uploaded_apk is not None:
        sha256 = hashlib.sha256()
        for chunk in uploaded_apk.chunks():
            sha256.update(chunk)
        uploaded_apk.seek(0)
        site_settings.android_apk_file = uploaded_apk
        if not manual_sha or (old_sha and manual_sha == old_sha):
            manual_sha = sha256.hexdigest().lower()
    elif apk_url and old_sha and manual_sha == old_sha and (apk_url != old_url or latest_code != old_version_code):
        # تفريغ بصمة SHA-256 القديمة تلقائياً عند تغيير رابط الـ APK أو رقم الإصدار دون تغيير البصمة
        manual_sha = ''
        stale_sha_cleared = True

    site_settings.android_apk_sha256 = manual_sha
    site_settings.save()
    AuditLog.log(
        request,
        AuditLog.ACTION_EDIT_USER,
        target_label='تحديث إصدار تطبيق الأندرويد',
        details={
            'latest_version_code': site_settings.android_latest_version_code,
            'min_required_version_code': site_settings.android_min_required_version_code,
            'latest_version_name': site_settings.android_latest_version_name,
            'force_update': site_settings.android_force_update,
            'has_external_apk_url': bool(site_settings.android_apk_url),
        },
    )
    msg = (
        f"تم حفظ إعدادات تحديث تطبيق الأندرويد (الإصدار {site_settings.android_latest_version_name}"
        f" · بناء {site_settings.android_latest_version_code})."
    )
    if stale_sha_cleared:
        msg += " تم مسح بصمة SHA-256 القديمة تلقائياً حتى لا تفشل تحديثات المستخدمين؛ يمكنك إدخال بصمة الملف الجديد يدوياً إذا أردت التحقق الصارم."
    return True, msg


@owner_required
def app_release_settings(request):
    """صفحة مخصصة لإدارة رابط APK الخارجي (GitHub Releases) وإصدارات التطبيق وروابط App Links."""
    site_settings = SiteSetting.load()
    if request.method == 'POST':
        ok, msg = _apply_app_release_post(request, site_settings)
        if is_ajax_request(request):
            if ok:
                return ajax_success(msg, data=_app_release_ajax_payload(request, site_settings))
            return ajax_error(msg, status=400)
        if ok:
            messages.success(request, msg)
        else:
            messages.error(request, msg)
        return redirect('admin_panel:app_release_settings')

    context = _base_context(request)
    context.update(_app_release_preview_data(request, site_settings))
    return render(request, 'admin_panel/app_release.html', context)


@owner_required
def update_app_release_settings(request):
    """تحديث إعدادات أحدث إصدار لتطبيق الأندرويد ورابط/ملف APK والتحديث الإجباري."""
    if request.method == 'POST':
        site_settings = SiteSetting.load()
        ok, msg = _apply_app_release_post(request, site_settings)
        if is_ajax_request(request):
            if ok:
                return ajax_success(msg, data=_app_release_ajax_payload(request, site_settings))
            return ajax_error(msg, status=400)
        if ok:
            messages.success(request, msg)
        else:
            messages.error(request, msg)
        next_target = request.POST.get('next', '').strip()
        if next_target == 'app_release':
            return redirect('admin_panel:app_release_settings')
    elif is_ajax_request(request):
        return ajax_error("طريقة الطلب غير مدعومة.", status=405)
    return redirect('admin_panel:dashboard')
