"""
Compatibility facade for api_v1.views_auth.
"""

from datetime import timedelta
import json
import random
import re
import secrets
import string
import urllib.parse
import urllib.request
import uuid
from django.contrib.auth import (
    authenticate,
    get_user_model,
)
from django.db import transaction
from django.db.models import Q
from django.http import HttpResponse
from django.utils import timezone
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.permissions import (
    AllowAny,
    IsAuthenticated,
)
from rest_framework.response import Response
from rest_framework.views import APIView
from accounts.email_verification import (
    issue_email_verification,
    send_verification_email,
)
from accounts.models import (
    EmailVerification,
    StudentProfile,
    OneTimeLoginLink,
)
from assistants.models import AssistantProfile
from core.models import (
    SiteSetting,
    Subject,
)
from teachers.models import (
    TeacherProfile,
    SubscriptionPlan,
)
from api_v1.authentication import (
    generate_jwt_pair,
    decode_jwt_token,
)
from api_v1.device_security_service import (
    extract_network_context,
    get_active_device_block,
    get_server_observed_ip,
    record_device_activity,
    record_security_event,
    register_or_update_device,
)
from api_v1.models import (
    DeviceActivity,
    DeviceSession,
    DeviceTrustStatus,
    PlaybackSession,
    RegisteredDevice,
)
from api_v1.permissions import IsNotBanned
from api_v1.serializers import UserDetailSerializer
from api_v1.security_engine import record_behavioral_activity

from api_v1.services.auth_service import User
from api_v1.services.auth_service import (
    _ensure_verification_otp_sent,
    _extract_installation_id,
    _handle_auth_device_registration,
    _notify_admins_teacher_pending,
    _resolve_subject_input,
    _verify_google_tokens,
    ensure_user_role_profile,
)
from api_v1.views.auth.login import (
    LoginAPIView,
    LogoutAPIView,
    OneTimeLoginAPIView,
    TokenRefreshAPIView,
)
from api_v1.views.auth.registration import (
    CompleteProfileAPIView,
    RegisterAPIView,
)
from api_v1.views.auth.profile import (
    ChangePasswordAPIView,
    MeProfileAPIView,
    ResetPasswordByNationalIdAPIView,
)
from api_v1.views.auth.google import (
    GoogleLoginAPIView,
    GoogleMobileCallbackView,
)
from api_v1.views.auth.otp import (
    ResendEmailOTPAPIView,
    VerifyEmailOTPAPIView,
)
