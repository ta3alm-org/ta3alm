from .models import Notification, SiteSetting


def _get_android_app_release_context(request):
    """توفير رابط تحميل تطبيق الأندرويد ورقم الإصدار المعتمد في الإدارة لجميع صفحات الموقع."""
    try:
        site_cfg = SiteSetting.load()
        external_url = (site_cfg.android_apk_url or '').strip()
        effective_url = site_cfg.get_effective_apk_url(request=request)
        download_url = external_url or effective_url
        return {
            'download_url': download_url,
            'has_download_url': bool(download_url),
            'is_external_url': bool(external_url),
            'version_name': (site_cfg.android_latest_version_name or '').strip(),
            'version_code': max(1, int(site_cfg.android_latest_version_code or 1)),
        }
    except Exception:
        return {
            'download_url': '',
            'has_download_url': False,
            'is_external_url': False,
            'version_name': '',
            'version_code': 1,
        }


def notifications(request):
    """
    Context processor للإشعارات وإعدادات تحميل تطبيق الأندرويد — يُشغَّل مع كل request.
    """
    context = {
        'android_app_release': _get_android_app_release_context(request),
    }

    user = getattr(request, 'user', None)
    if not user or not user.is_authenticated:
        return context

    # استعلام واحد يجلب آخر 5 إشعارات وعدد غير المقروءة
    notifs = Notification.objects.filter(
        recipient=user
    ).order_by('-created_at')[:5]

    unread_count = Notification.objects.filter(
        recipient=user,
        is_read=False
    ).count()

    context['notifications'] = notifs
    context['unread_count'] = unread_count
    return context