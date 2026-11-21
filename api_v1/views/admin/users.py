"""api_v1.views.admin.users
Extracted from api_v1/views_admin.py.
"""

from datetime import timedelta
from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.models import Q
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
from core.models import Subject
from core.notifications_service import notify_user
from dashboard_admin.models import AuditLog
from teachers.models import (
    TeacherProfile,
    SubscriptionPlan,
)
from api_v1.permissions import IsPlatformModerator
from api_v1.serializers import (
    UserDetailSerializer,
    SubscriptionPlanSerializer,
    SubjectSerializer,
)
from api_v1.security_engine import (
    enforce_security_ban,
    unban_user_and_devices,
)

from api_v1.views.admin.dashboard import _backfill_missing_user_profiles

User = get_user_model()


class AdminManageUsersAPIView(APIView):
    """عرض المستخدمين والبحث والفلترة وتنفيذ الإجراءات الإدارية الكاملة."""
    permission_classes = [IsAuthenticated, IsPlatformModerator]

    def get(self, request):
        _backfill_missing_user_profiles()
        query = request.query_params.get('q', '').strip()
        role_filter = request.query_params.get('role', '').strip()
        try:
            limit = min(max(int(request.query_params.get('limit') or 500), 1), 1000)
        except (TypeError, ValueError):
            limit = 500

        users = (
            User.objects
            .select_related(
                'student_profile',
                'teacher_profile',
                'teacher_profile__subject',
                'teacher_profile__current_plan',
                'assistant_profile',
                'admin_profile',
            )
            .all()
            .order_by('-id')
        )
        if role_filter == 'pending_teacher':
            users = users.filter(role='teacher', teacher_profile__is_approved=False)
        elif role_filter == 'approved_teacher':
            users = users.filter(role='teacher', teacher_profile__is_approved=True)
        elif role_filter == 'banned':
            users = users.filter(is_banned=True)
        elif role_filter:
            users = users.filter(role=role_filter)

        if query:
            users = users.filter(
                Q(first_name__icontains=query)
                | Q(last_name__icontains=query)
                | Q(username__icontains=query)
                | Q(email__icontains=query)
                | Q(phone__icontains=query)
                | Q(custom_id__icontains=query)
            )

        return Response({
            'total_count': users.count(),
            'pending_teachers_count': TeacherProfile.objects.filter(is_approved=False).count(),
            'users': UserDetailSerializer(users[:limit], many=True, context={'request': request}).data,
            'plans': SubscriptionPlanSerializer(SubscriptionPlan.objects.all(), many=True).data,
            'subjects': SubjectSerializer(Subject.objects.all(), many=True).data,
        })

    @transaction.atomic
    def post(self, request):
        """إجراءات على المستخدم: approve_teacher, unapprove_teacher, ban, unban, delete, renew_free, edit_user, change_password, generate_login_link."""
        user_id = request.data.get('user_id')
        action = request.data.get('action')
        target = get_object_or_404(User, id=user_id)

        if target.is_superuser and action in ('ban', 'delete'):
            return Response({'error': 'لا يمكن حظر أو حذف حساب المالك.'}, status=status.HTTP_400_BAD_REQUEST)

        requester_profile = getattr(request.user, 'admin_profile', None)
        can_delete = request.user.is_superuser or (requester_profile and requester_profile.can_delete_users)

        if action == 'approve_teacher':
            if target.role != 'teacher':
                return Response({'error': 'هذا المستخدم ليس معلماً.'}, status=status.HTTP_400_BAD_REQUEST)
            tp, _ = TeacherProfile.objects.get_or_create(user=target)
            tp.is_approved = True
            tp.approved_at = timezone.now()
            update_fields = ['is_approved', 'approved_at']
            # منح الباقة الافتراضية والتجربة 30 يوماً فور موافقة الإدارة لأول مرة
            if not tp.is_trial_used and not tp.subscription_end_date:
                default_plan = (
                    SubscriptionPlan.objects.filter(is_default=True).first()
                    or SubscriptionPlan.objects.order_by('price').first()
                )
                if default_plan:
                    tp.current_plan = default_plan
                    update_fields.append('current_plan')
                tp.subscription_end_date = timezone.now() + timedelta(days=30)
                tp.is_trial_used = True
                update_fields.extend(['subscription_end_date', 'is_trial_used'])
            tp.save(update_fields=update_fields)
            notify_user(
                target,
                'تمت الموافقة على اعتمادك كمعلم في منصة تعلّم',
                'وافقت إدارة المنصة على طلب انضمامك، وتم تفعيل لوحة المعلم والشهر التجريبي المجاني لتبدأ بإنشاء مجموعاتك وكورساتك.',
                link='/teacher/',
            )
            AuditLog.log(request, AuditLog.ACTION_EDIT_USER, target_label=f'اعتماد معلم: {target.get_full_name() or target.email}', target_id=target.id)
            return Response({
                'message': f'تم اعتماد المعلم {target.get_full_name() or target.email} وتفعيل حسابه.',
                'user': UserDetailSerializer(target, context={'request': request}).data,
            })

        if action == 'unapprove_teacher':
            if target.role != 'teacher':
                return Response({'error': 'هذا المستخدم ليس معلماً.'}, status=status.HTTP_400_BAD_REQUEST)
            tp, _ = TeacherProfile.objects.get_or_create(user=target)
            tp.is_approved = False
            tp.approved_at = None
            tp.save(update_fields=['is_approved', 'approved_at'])
            notify_user(
                target,
                'تم إيقاف ظهور ملفك التعليمي مؤقتاً',
                'تم سحب الاعتماد المؤقت لحسابك من الظهور العام للطلاب لحين المراجعة الإدارية.',
                link='/teacher/',
            )
            AuditLog.log(request, AuditLog.ACTION_EDIT_USER, target_label=f'إلغاء اعتماد معلم: {target.get_full_name() or target.email}', target_id=target.id)
            return Response({
                'message': f'تم إخفاء المعلم {target.get_full_name() or target.email} وإعادته لقائمة الانتظار.',
                'user': UserDetailSerializer(target, context={'request': request}).data,
            })

        if action == 'ban':
            ban_mode = str(request.data.get('ban_mode') or 'user_only').strip()
            reason = str(request.data.get('reason') or 'حظر من إدارة المستخدمين').strip()
            enforce_security_ban(
                user=target,
                mode=ban_mode,
                reason=reason,
                actor=request.user,
                request=request,
            )
            return Response({'message': f'تم تنفيذ الحظر ({ban_mode}) على {target.get_full_name() or target.email}.'})

        if action == 'unban':
            unban_mode = str(request.data.get('unban_mode') or 'both').strip()
            unban_user_and_devices(
                user=target,
                mode=unban_mode,
                actor=request.user,
                reason='رفع الحظر بواسطة الإدارة',
                request=request,
            )
            return Response({'message': f'تم رفع الحظر عن {target.get_full_name() or target.email}.'})

        if action == 'delete':
            if not can_delete:
                return Response({'error': 'ليس لديك صلاحية حذف المستخدمين.'}, status=status.HTTP_403_FORBIDDEN)
            name = target.get_full_name() or target.email
            AuditLog.log(request, AuditLog.ACTION_DELETE, target_label=name, target_id=target.id)
            target.delete()
            return Response({'message': f'تم حذف المستخدم {name} نهائياً.'})

        if action == 'renew_free':
            if not hasattr(target, 'teacher_profile'):
                return Response({'error': 'هذا المستخدم ليس معلماً.'}, status=status.HTTP_400_BAD_REQUEST)
            teacher = target.teacher_profile
            plan_id = request.data.get('plan_id')
            if plan_id:
                teacher.current_plan = get_object_or_404(SubscriptionPlan, id=plan_id)
            teacher.subscription_end_date = (
                teacher.subscription_end_date + timedelta(days=30)
                if teacher.has_active_subscription()
                else timezone.now() + timedelta(days=30)
            )
            teacher.save()
            notify_user(
                target,
                'تم تجديد اشتراكك من قِبل الإدارة',
                f"جددت إدارة المنصة اشتراكك لمدة 30 يوماً{f' على باقة {teacher.current_plan.name}' if teacher.current_plan else ''} حتى {teacher.subscription_end_date.strftime('%Y-%m-%d')}.",
                link='/teacher/subscription/',
            )
            AuditLog.log(request, AuditLog.ACTION_RENEW_SUB, target_label=target.get_full_name(), target_id=target.id)
            return Response({'message': f'تم تجديد اشتراك {target.get_full_name()} لمدة 30 يوماً.'})

        if action == 'change_password':
            new_password = str(request.data.get('new_password', '')).strip()
            if len(new_password) < 6:
                return Response({'error': 'كلمة المرور يجب أن تكون 6 أحرف على الأقل.'}, status=status.HTTP_400_BAD_REQUEST)
            target.set_password(new_password)
            target.save(update_fields=['password'])
            AuditLog.log(
                request,
                AuditLog.ACTION_EDIT_USER,
                target_label=f"تغيير كلمة مرور: {target.get_full_name() or target.email}",
                target_id=target.id,
            )
            return Response({'message': f'تم تغيير كلمة المرور للمستخدم {target.get_full_name() or target.email} بنجاح.'})

        if action == 'generate_login_link':
            expires = timezone.now() + timedelta(minutes=15)
            link = OneTimeLoginLink.objects.create(user=target, expires_at=expires)
            login_url = f"https://www.ta3alm.online/login/auto/{link.token}/"
            AuditLog.log(
                request,
                AuditLog.ACTION_EDIT_USER,
                target_label=f"توليد رابط دخول مؤقت: {target.get_full_name() or target.email}",
                target_id=target.id,
            )
            return Response({
                'message': 'تم توليد رابط/كود الدخول المؤقت (صالح لمدة 15 دقيقة ولمرة واحدة).',
                'token': str(link.token),
                'login_url': login_url,
                'expires_at': expires,
            })

        if action == 'edit_user':
            for field in ('first_name', 'last_name', 'email', 'phone', 'national_id', 'custom_id', 'role'):
                if field in request.data and request.data[field] is not None:
                    val = str(request.data[field]).strip()
                    if field in ('national_id', 'custom_id') and not val:
                        val = None
                    setattr(target, field, val)
            target.save()

            if target.role == 'teacher':
                tp, _ = TeacherProfile.objects.get_or_create(user=target)
                if 'bio' in request.data:
                    tp.bio = str(request.data['bio']).strip()
                if 'subject_id' in request.data and request.data['subject_id']:
                    tp.subject = Subject.objects.filter(id=request.data['subject_id']).first() or tp.subject
                if 'plan_id' in request.data:
                    tp.current_plan = SubscriptionPlan.objects.filter(id=request.data['plan_id']).first() if request.data['plan_id'] else None
                tp.save()
            elif target.role == 'student':
                sp, _ = StudentProfile.objects.get_or_create(user=target)
                if 'parent_phone' in request.data:
                    sp.parent_phone = str(request.data['parent_phone']).strip()
                sp.save()
            elif target.role == 'assistant':
                ap, _ = AssistantProfile.objects.get_or_create(user=target)
                if 'phone' in request.data:
                    ap.phone = str(request.data['phone']).strip()
                ap.save()

            AuditLog.log(
                request,
                AuditLog.ACTION_EDIT_USER,
                target_label=target.get_full_name() or target.email,
                target_id=target.id,
            )
            return Response({
                'message': f'تم حفظ تعديلات المستخدم {target.get_full_name() or target.email} بنجاح.',
                'user': UserDetailSerializer(target, context={'request': request}).data,
            })

        return Response({'error': 'إجراء غير صالح.'}, status=status.HTTP_400_BAD_REQUEST)
