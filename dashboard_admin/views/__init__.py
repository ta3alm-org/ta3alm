"""
dashboard_admin/views package compatibility exports.
"""

from django.shortcuts import (
    render,
    redirect,
    get_object_or_404,
)
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.db.models import (
    Sum,
    Count,
    Q,
)
from django.utils import timezone
from datetime import timedelta
from teachers.models import (
    TeacherProfile,
    PaymentTransaction,
    SubscriptionPlan,
    WithdrawRequest,
)
from accounts.models import StudentProfile
from assistants.models import AssistantProfile
from students.models import PackageEnrollment
from core.models import SiteSetting
from core.notifications_service import (
    maybe_notify_zoho_inbox,
    notify_user,
)
from dashboard_admin.models import (
    AdminProfile,
    AdminRole,
    AuditLog,
)
from dashboard_admin.decorators import (
    admin_required,
    owner_required,
    finance_required,
    moderator_required,
)
from dashboard_admin.forms import (
    AdminUserEditForm,
    AdminTeacherEditForm,
    AdminStudentEditForm,
    AdminAssistantEditForm,
    AppointAdminForm,
    CreateAdminForm,
)
from core.models import CurriculumUnit
from dashboard_admin.forms import (
    CurriculumUnitForm,
    CurriculumLessonFormSet,
)
from services.zoho_mail_service import ZohoMailService
from django.urls import reverse
import logging

from dashboard_admin.views.users import User
import logging
logger = logging.getLogger('dashboard_admin.views')
from dashboard_admin.views.base import _base_context
from dashboard_admin.views.home import (
    _apply_app_release_post,
    app_release_settings,
    dashboard,
    toggle_maintenance,
    update_app_release_settings,
    update_platform_commission,
)
from dashboard_admin.views.users import (
    edit_user,
    manage_users,
    user_action,
)
from dashboard_admin.views.finance import (
    finance_report,
    manual_payments,
    student_payments,
    withdrawals,
)
from dashboard_admin.views.plans import manage_plans
from dashboard_admin.views.audit import audit_log
from dashboard_admin.views.staff import manage_staff
from dashboard_admin.views.curriculum import (
    curriculum_unit_create,
    curriculum_unit_delete,
    curriculum_unit_edit,
    manage_curriculum,
)
from dashboard_admin.views.support import (
    _sanitize_email_html,
    support_compose,
    support_inbox,
    support_message_detail,
    support_oauth_callback,
    support_oauth_connect,
    support_send_reply,
    support_settings,
)
from dashboard_admin.views.security import (
    security_admin_action,
    security_dashboard,
    security_device_detail,
)
from dashboard_admin.views.notifications import (
    notifications_recipient_preview,
    send_notifications,
)
