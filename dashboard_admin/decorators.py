"""
dashboard_admin/decorators.py
Decorators للتحقق من صلاحيات الإدارة
"""
from functools import wraps
from django.shortcuts import redirect
from django.contrib import messages
from django.urls import reverse

from dashboard_admin.views.ajax import (
    ajax_error,
    is_ajax_request,
)


def _get_admin_profile(user):
    """يُعيد admin_profile لو وجد، أو None."""
    try:
        return user.admin_profile if user.admin_profile.is_active_admin else None
    except Exception:
        return None


def _unauthenticated_response(request):
    """استجابة موحدة لعدم تسجيل الدخول (JSON لطلبات AJAX و Redirect لطلبات المتصفح)."""
    if is_ajax_request(request):
        return ajax_error(
            "انتهت جلسة العمل. يرجى تسجيل الدخول مجدداً.",
            status=401,
            data={'login_url': reverse('account_login')},
        )
    return redirect('account_login')


def _forbidden_response(request, msg, redirect_to='admin_panel:dashboard'):
    """استجابة موحدة لرفض الصلاحية (403 JSON لطلبات AJAX و Redirect لطلبات المتصفح)."""
    if is_ajax_request(request):
        return ajax_error(msg, status=403)
    messages.error(request, msg)
    return redirect(redirect_to)


def admin_required(view_func):
    """
    يسمح فقط لـ: superuser أو user.role == 'admin' مع AdminProfile نشط.
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        user = request.user
        if not user.is_authenticated:
            return _unauthenticated_response(request)

        if user.is_superuser:
            return view_func(request, *args, **kwargs)

        profile = _get_admin_profile(user)
        if profile:
            return view_func(request, *args, **kwargs)

        return _forbidden_response(
            request,
            "ليس لديك صلاحية للوصول لهذه الصفحة.",
            redirect_to='home',
        )

    return wrapper


def owner_required(view_func):
    """
    يسمح فقط لـ: superuser أو admin_role == 'owner'.
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        user = request.user
        if not user.is_authenticated:
            return _unauthenticated_response(request)

        if user.is_superuser:
            return view_func(request, *args, **kwargs)

        profile = _get_admin_profile(user)
        if profile and profile.is_owner:
            return view_func(request, *args, **kwargs)

        return _forbidden_response(request, "هذه الصفحة للمالك فقط.")

    return wrapper


def finance_required(view_func):
    """
    يسمح لـ: superuser, owner, finance.
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        user = request.user
        if not user.is_authenticated:
            return _unauthenticated_response(request)

        if user.is_superuser:
            return view_func(request, *args, **kwargs)

        profile = _get_admin_profile(user)
        if profile and profile.can_view_finance:
            return view_func(request, *args, **kwargs)

        return _forbidden_response(request, "ليس لديك صلاحية عرض التقارير المالية.")

    return wrapper


def moderator_required(view_func):
    """
    يسمح لـ: superuser, owner, moderator.
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        user = request.user
        if not user.is_authenticated:
            return _unauthenticated_response(request)

        if user.is_superuser:
            return view_func(request, *args, **kwargs)

        profile = _get_admin_profile(user)
        if profile and profile.can_manage_users:
            return view_func(request, *args, **kwargs)

        return _forbidden_response(request, "ليس لديك صلاحية إدارة المستخدمين.")

    return wrapper
