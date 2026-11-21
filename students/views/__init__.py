"""
students/views package compatibility exports.
"""

from django.shortcuts import (
    render,
    redirect,
    get_object_or_404,
)
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Q
from teachers.models import Group
from students.models import Enrollment
from accounts.models import StudentProfile
from django.utils import timezone
from teachers.models import (
    Lecture,
    VideoCode,
)
from exams.models import (
    Exam,
    Question,
    ExamResult,
)
from students.models import PerformanceLog
import time
import requests
import random
import string
from datetime import timedelta
from django.conf import settings
from django.db import transaction
from django.http import HttpResponse
from core.utils import send_notification
from core.models import Subject
import json as _json
from django.http import JsonResponse as _JsonResponse
from django.views.decorators.http import require_POST as _require_POST
from core.utils import (
    get_optimized_group_leaderboard,
    get_optimized_package_leaderboard,
)
from students.models import (
    PackageEnrollment,
    VideoViewTracking,
)
from teachers.models import CoursePackage
from django.db import models
from django.db.models import Sum
from django.urls import reverse
from students.models import PackageExamResult
from teachers.models import PDFFile

from students.views.access import (
    _clear_student_web_watch_state,
    calculate_leaderboard,
    check_student_access,
    get_package_leaderboard,
)
from students.views.dashboard import (
    join_group,
    list_packages,
    search_groups,
    student_dashboard,
    student_settings,
)
from students.views.groups import (
    student_group_contact,
    student_group_content,
    student_group_exams,
    student_group_files,
    student_group_marks,
    student_group_ranking,
    student_take_exam,
    student_watch_lecture,
    web_lecture_end,
    web_lecture_heartbeat,
)
from students.views.packages import (
    my_package_content,
    my_package_marks,
    package_detail,
    package_leaderboard,
    paymob_package_checkout,
    student_package_files,
    student_take_package_exam,
    watch_package_lecture,
)
