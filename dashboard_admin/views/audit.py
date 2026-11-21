"""dashboard_admin.views.audit
Extracted from dashboard_admin/views.py.
"""

from django.shortcuts import render
from dashboard_admin.models import AuditLog
from dashboard_admin.decorators import owner_required

from dashboard_admin.views.base import _base_context


# ==========================================================
# 10. سجل الأحداث (Audit Log)
# ==========================================================
@owner_required
def audit_log(request):
    ctx = _base_context(request)

    logs = AuditLog.objects.select_related('admin').order_by('-created_at')

    action_filter = request.GET.get('action', '')
    if action_filter:
        logs = logs.filter(action=action_filter)

    ctx.update({
        'logs':           logs[:200],
        'action_choices': AuditLog.ACTION_CHOICES,
        'action_filter':  action_filter,
    })
    return render(request, 'admin_panel/audit_log.html', ctx)
