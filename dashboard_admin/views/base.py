"""dashboard_admin.views.base
Extracted from dashboard_admin/views.py.
"""

from dashboard_admin.models import AdminRole


# ----------------------------------------------------------
# مساعد: يُعيد context الـ sidebar الموحَّد
# ----------------------------------------------------------
def _base_context(request):
    """Context مشترك لكل صفحات الإدارة (sidebar + صلاحيات)."""
    user = request.user
    profile = getattr(user, 'admin_profile', None)

    # جلب عدد الإشعارات غير المقروءة
    from core.models import Notification
    unread_count = Notification.objects.filter(recipient=user, is_read=False).count()

    from core.models import SiteSetting
    site_settings = SiteSetting.load()

    zoho_connected = False
    try:
        from dashboard_admin.models import ZohoMailConfig
        z_cfg = ZohoMailConfig.load()
        zoho_connected = z_cfg.is_connected()
    except Exception:
        pass

    support_chat_unread_count = 0
    client_errors_unresolved_count = 0
    try:
        from django.db.models import Sum
        from core.models import ClientErrorReport, SupportThread
        support_chat_unread_count = int(
            SupportThread.objects.aggregate(total=Sum('unread_for_admin')).get('total') or 0
        )
        client_errors_unresolved_count = ClientErrorReport.objects.filter(is_resolved=False).count()
    except Exception:
        pass

    return {
        'admin_user':         user,
        'admin_profile':      profile,
        'is_owner':           user.is_superuser or (profile and profile.is_owner),
        'can_manage_users':   user.is_superuser or (profile and profile.can_manage_users),
        'can_delete_users':   user.is_superuser or (profile and profile.can_delete_users),
        'can_view_finance':   user.is_superuser or (profile and profile.can_view_finance),
        'can_manage_plans':   user.is_superuser or (profile and profile.can_manage_plans),
        'can_manage_content': user.is_superuser or (profile and profile.is_active_admin),
        'can_view_audit':     user.is_superuser or (profile and profile.can_view_audit_log),
        'can_manage_support': user.is_superuser or (profile and (profile.is_owner or profile.can_manage_users or profile.admin_role == AdminRole.SUPPORT)),
        'unread_count':       unread_count,
        'site_settings':      site_settings,
        'zoho_connected':     zoho_connected,
        'support_chat_unread_count': support_chat_unread_count,
        'client_errors_unresolved_count': client_errors_unresolved_count,
    }
