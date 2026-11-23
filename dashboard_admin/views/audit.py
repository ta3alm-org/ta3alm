"""dashboard_admin.views.audit
Extracted from dashboard_admin/views.py.
"""

from django.shortcuts import render
from dashboard_admin.models import AuditLog
from dashboard_admin.decorators import owner_required

from django.template.loader import render_to_string

from dashboard_admin.views.base import _base_context
from dashboard_admin.views.ajax import (
    ajax_success,
    is_ajax_request,
)


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

    logs_list = list(logs[:200])
    ctx.update({
        'logs':           logs_list,
        'action_choices': AuditLog.ACTION_CHOICES,
        'action_filter':  action_filter,
    })
    if is_ajax_request(request) and request.GET.get('partial') == '1':
        html = render_to_string('admin_panel/partials/_audit_list.html', ctx, request=request)
        return ajax_success(
            data={
                'html': html,
                'count': len(logs_list),
                'action_filter': action_filter,
            }
        )
    return render(request, 'admin_panel/audit_log.html', ctx)
