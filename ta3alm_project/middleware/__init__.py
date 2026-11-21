"""
ta3alm_project/middleware package compatibility exports.
"""

from django.shortcuts import (
    render,
    redirect,
)
from django.urls import (
    reverse,
    resolve,
    Resolver404,
)
from django.http import (
    Http404,
    JsonResponse,
)
from rest_framework.authtoken.models import Token
from django.contrib.auth import (
    login,
    logout,
)
from django.conf import settings as django_settings
from core.models import SiteSetting

from ta3alm_project.middleware.routing import SubdomainAdminMiddleware
from ta3alm_project.middleware.auth import (
    BanMiddleware,
    EmailVerificationMiddleware,
    TokenAuthMiddleware,
)
from ta3alm_project.middleware.platform import (
    AppVersionEnforcementMiddleware,
    MaintenanceMiddleware,
)
from ta3alm_project.middleware.api_audit import ApiSecurityAndActivityAuditMiddleware
from ta3alm_project.middleware.web_device import WebDeviceSecurityMiddleware
