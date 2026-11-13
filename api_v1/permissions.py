"""
api_v1/permissions.py
صلاحيات مبنية على الأدوار والملكية وحالة الحظر/الاشتراك.
"""
from rest_framework.permissions import BasePermission


class IsNotBanned(BasePermission):
    message = 'حسابك محظور. يرجى التواصل مع الدعم الفني.'

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        return not getattr(request.user, 'is_banned', False)


class IsStudentRole(IsNotBanned):
    message = 'هذه الخدمة مخصصة للطلاب فقط.'

    def has_permission(self, request, view):
        return super().has_permission(request, view) and request.user.role == 'student'


class IsTeacherRole(IsNotBanned):
    message = 'هذه الخدمة مخصصة للمعلمين فقط.'

    def has_permission(self, request, view):
        return super().has_permission(request, view) and request.user.role == 'teacher'


class IsAssistantRole(IsNotBanned):
    message = 'هذه الخدمة مخصصة للمساعدين فقط.'

    def has_permission(self, request, view):
        return super().has_permission(request, view) and request.user.role == 'assistant'


class IsTeacherOrAssistantRole(IsNotBanned):
    message = 'هذه الخدمة مخصصة للمعلمين أو المساعدين فقط.'

    def has_permission(self, request, view):
        return super().has_permission(request, view) and request.user.role in ('teacher', 'assistant')


class IsPlatformAdmin(IsNotBanned):
    message = 'ليس لديك صلاحيات إدارية للوصول إلى هذا المورد.'

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        user = request.user
        if user.is_superuser:
            return True
        profile = getattr(user, 'admin_profile', None)
        return bool(profile and profile.is_active_admin)


class IsPlatformOwner(IsPlatformAdmin):
    message = 'هذا الإجراء متاح لمالك المنصة فقط.'

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        user = request.user
        if user.is_superuser:
            return True
        profile = getattr(user, 'admin_profile', None)
        return bool(profile and profile.is_owner)


class IsPlatformFinance(IsPlatformAdmin):
    message = 'ليس لديك صلاحية الوصول للتقارير والعمليات المالية.'

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        user = request.user
        if user.is_superuser:
            return True
        profile = getattr(user, 'admin_profile', None)
        return bool(profile and profile.can_view_finance)


class IsPlatformModerator(IsPlatformAdmin):
    message = 'ليس لديك صلاحية إدارة المستخدمين.'

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        user = request.user
        if user.is_superuser:
            return True
        profile = getattr(user, 'admin_profile', None)
        return bool(profile and profile.can_manage_users)

