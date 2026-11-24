"""
Compatibility facade for api_v1.views_admin.
"""

from datetime import timedelta
import random
import string
from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.models import (
    Q,
    Sum,
)
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from accounts.models import (
    StudentProfile,
    OneTimeLoginLink,
)
from assistants.models import AssistantProfile
from decimal import (
    Decimal,
    ROUND_HALF_UP,
)
from core.models import (
    SiteSetting,
    ManualPayment,
    Subject,
    CurriculumUnit,
    CurriculumLesson,
    reconcile_teacher_wallet,
)
from core.notifications_service import (
    CUSTOM_TARGET_ALL,
    get_custom_notification_metadata,
    maybe_notify_zoho_inbox,
    notify_user,
    parse_user_ids_input,
    preview_custom_notification_audience,
    search_custom_notification_users,
    send_custom_notification,
)
from dashboard_admin.models import (
    AdminProfile,
    AdminRole,
    AuditLog,
    ZohoMailConfig,
)
from services.zoho_mail_service import ZohoMailService
from students.models import PackageEnrollment
from teachers.models import (
    TeacherProfile,
    SubscriptionPlan,
    PaymentTransaction,
    WithdrawRequest,
)
from api_v1.permissions import (
    IsPlatformAdmin,
    IsPlatformOwner,
    IsPlatformFinance,
    IsPlatformModerator,
)
from api_v1.serializers import (
    UserDetailSerializer,
    SubscriptionPlanSerializer,
    WithdrawRequestSerializer,
    ManualPaymentSerializer,
    PackageEnrollmentSerializer,
    AdminProfileSerializer,
    AuditLogSerializer,
    CurriculumUnitSerializer,
    SubjectSerializer,
)
from api_v1.models import UserSecurityProfile
from api_v1.security_engine import (
    enforce_security_ban,
    unban_user_and_devices,
)

from api_v1.views.admin.dashboard import User
from api_v1.views.admin.dashboard import (
    AdminDashboardAPIView,
    AdminToggleMaintenanceAPIView,
    _backfill_missing_user_profiles,
)
from api_v1.views.admin.users import AdminManageUsersAPIView
from api_v1.views.admin.finance import AdminFinanceAPIView
from api_v1.views.admin.plans_staff import AdminPlansAndStaffAPIView
from api_v1.views.admin.support import AdminSupportInboxAPIView
from api_v1.views.admin.notifications import (
    AdminNotificationsAPIView,
    _extract_admin_notif_params,
)
from api_v1.views.admin.content_hub import AdminContentHubAPIView
