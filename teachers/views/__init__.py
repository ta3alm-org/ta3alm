"""
teachers/views package compatibility exports.
"""

import os
import uuid
import requests
import random
import string
from datetime import timedelta
from django.core.files.storage import default_storage
from django.db.models import Sum
from students.models import (
    VideoViewTracking,
    PackageExamResult,
)
from assistants.models import AssistantJob
from core.models import (
    SiteSetting,
    credit_teacher_wallet_for_sale,
    reconcile_teacher_wallet,
)
from core.notifications_service import maybe_notify_teacher_subscription_expiry
from django.utils import timezone
from django.shortcuts import (
    render,
    redirect,
    get_object_or_404,
)
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.conf import settings
from django.db.models import Q
from django.http import HttpResponse
from core.utils import send_notification
from teachers.models import (
    TeacherProfile,
    Group,
    Lecture,
    VideoCode,
    PaymentTransaction,
    Wallet,
)
from accounts.models import StudentProfile
from exams.models import (
    Exam,
    Question,
)
from students.models import (
    Enrollment,
    PerformanceLog,
)
from teachers.models import PDFFile
from teachers.forms import PDFForm
from django.urls import reverse
from teachers.forms import (
    GroupForm,
    LectureForm,
    TeacherSettingsForm,
    CoursePackageForm,
)
from exams.forms import (
    ExamForm,
    QuestionForm,
)
from students.forms import PerformanceForm
from assistants.forms import AssistantPermissionsForm
from teachers.models import SubscriptionPlan
from students.models import PackageEnrollment
from teachers.models import CoursePackage
import hashlib
import hmac
import logging
from decimal import (
    Decimal,
    InvalidOperation,
)
from django.conf import settings as django_settings
from django.db import transaction
from django.utils.http import url_has_allowed_host_and_scheme
from exams.models import ExamResult
from core.utils import (
    get_optimized_group_leaderboard,
    get_optimized_package_leaderboard,
)
from teachers.models import WithdrawRequest
from rest_framework.decorators import (
    api_view,
    permission_classes,
)
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from teachers.serializers import (
    TeacherSerializer,
    PackageSerializer,
)

from teachers.views.permissions import (
    get_group_permission,
    get_package_permission,
)
from teachers.views.dashboard import teacher_dashboard
from teachers.views.groups import (
    bulk_log,
    calculate_leaderboard,
    delete_group,
    delete_lecture,
    edit_group,
    group_detail,
    group_exams,
    group_ranking,
    group_requests,
    group_students,
    import_group_content,
    manage_video_codes,
    remove_student_from_group,
    student_full_log,
    toggle_lecture_status,
)
from teachers.views.account import (
    delete_teacher_account,
    manage_assistants,
    subscription_info,
    teacher_settings,
)
from teachers.views.payments import (
    _PAYMOB_HMAC_FIELDS,
    _pay_logger,
    _verify_paymob_hmac,
    payment_callback,
    paymob_checkout,
)
from teachers.views.packages import (
    add_exam_to_package,
    add_lecture_to_package,
    calculate_package_leaderboard,
    create_package,
    edit_package,
    import_package_content,
    remove_package_content,
    teacher_package_detail,
    teacher_package_ranking,
    teacher_package_students,
    teacher_packages,
)
from teachers.views.wallet import teacher_wallet
from teachers.views.files import (
    _resolve_pdf_link_from_request,
    _safe_referer_redirect,
    add_pdf_to_group,
    add_pdf_to_package,
    delete_pdf,
    group_files_teacher,
    package_files_teacher,
)
from teachers.views.legacy_api import (
    api_all_packages,
    api_all_teachers,
)
