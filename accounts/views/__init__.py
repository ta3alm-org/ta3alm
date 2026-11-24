"""
accounts/views package compatibility exports.
"""

from django.shortcuts import (
    render,
    redirect,
    get_object_or_404,
)
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.utils import timezone
from django.utils.translation import gettext as _
from django.views.decorators.http import require_POST
from datetime import timedelta
import json
import random
import secrets
import string
from django.contrib.auth import (
    login,
    logout,
    update_session_auth_hash,
)
from accounts.email_verification import (
    issue_email_verification,
    send_verification_email,
)
from accounts.forms import (
    CompleteStudentProfileForm,
    CompleteTeacherProfileForm,
    CompleteAssistantProfileForm,
)
from accounts.models import (
    EmailVerification,
    StudentProfile,
    User,
)
from teachers.models import (
    TeacherProfile,
    SubscriptionPlan,
)
from assistants.models import AssistantProfile

from accounts.views.profile import complete_gender, complete_profile
from accounts.views.signup import (
    RESEND_COOLDOWN_SECONDS,
    _remaining_resend_seconds,
    _resolve_pending_verification_user,
    manual_signup,
    resend_verification_email,
    verify_email_link,
    verify_email_page,
)
from accounts.views.devices import (
    web_device_traits_sync,
    web_trusted_devices,
)
