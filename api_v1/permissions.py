"""
api_v1/permissions.py
صلاحيات مبنية على الأدوار والملكية وحالة الحظر/الاشتراك.
"""
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import BasePermission


class IsNotBanned(BasePermission):
    message = 'حسابك محظور. يرجى التواصل مع الدعم الفني.'

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        if getattr(request.user, 'is_banned', False):
            return False
        if (
            hasattr(request.user, 'requires_email_verification')
            and request.user.requires_email_verification()
        ):
            raise PermissionDenied(
                detail={
                    'error': 'يرجى تأكيد حسابك برمز التحقق (OTP) أولاً قبل استخدام المنصة.',
                    'detail': 'يرجى تأكيد حسابك برمز التحقق (OTP) أولاً قبل استخدام المنصة.',
                    'code': 'EMAIL_VERIFICATION_REQUIRED',
                    'requires_verification': True,
                }
            )
        return True


class IsStudentRole(IsNotBanned):
    message = 'هذه الخدمة مخصصة للطلاب فقط.'

    def has_permission(self, request, view):
        return super().has_permission(request, view) and request.user.role == 'student'


class IsTeacherRole(IsNotBanned):
    message = 'هذه الخدمة مخصصة للمعلمين المعتمدين فقط.'

    def has_permission(self, request, view):
        if not (super().has_permission(request, view) and request.user.role == 'teacher'):
            return False
        tp = getattr(request.user, 'teacher_profile', None)
        if tp is None or not getattr(tp, 'is_approved', False):
            raise PermissionDenied(
                detail={
                    'error': 'حسابك كمعلم قيد المراجعة حالياً من قِبل إدارة المنصة. ستتمكن من إضافة المجموعات والكورسات فور الموافقة على الحساب.',
                    'detail': 'حسابك كمعلم قيد المراجعة حالياً من قِبل إدارة المنصة.',
                    'code': 'TEACHER_APPROVAL_PENDING',
                    'is_teacher_approved': False,
                }
            )
        return True


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

