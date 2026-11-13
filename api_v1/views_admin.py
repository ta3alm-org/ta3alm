"""
api_v1/views_admin.py
نقاط النهاية الخاصة بلوحة الإدارة ومالك المنصة (الإحصاءات، الصيانة، إدارة المستخدمين، المالية، الباقات، فريق الإدارة، وسجل الأحداث).
"""
from datetime import timedelta
from django.contrib.auth import get_user_model
from django.db.models import Q, Sum
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import StudentProfile
from assistants.models import AssistantProfile
from core.models import SiteSetting, ManualPayment
from dashboard_admin.models import AdminProfile, AdminRole, AuditLog
from students.models import PackageEnrollment
from teachers.models import TeacherProfile, SubscriptionPlan, PaymentTransaction, WithdrawRequest

from .permissions import (
    IsPlatformAdmin,
    IsPlatformOwner,
    IsPlatformFinance,
    IsPlatformModerator,
)
from .serializers import (
    UserDetailSerializer,
    SubscriptionPlanSerializer,
    WithdrawRequestSerializer,
    ManualPaymentSerializer,
    AdminProfileSerializer,
    AuditLogSerializer,
)

User = get_user_model()


class AdminDashboardAPIView(APIView):
    """لوحة إحصاءات الإدارة وحالة الصيانة وآخر الأحداث."""
    permission_classes = [IsAuthenticated, IsPlatformAdmin]

    def get(self, request):
        site_settings = SiteSetting.load()
        recent_logs = AuditLog.objects.select_related('admin').order_by('-created_at')[:15]

        return Response({
            'total_teachers': TeacherProfile.objects.count(),
            'active_teachers_count': TeacherProfile.objects.filter(subscription_end_date__gt=timezone.now()).count(),
            'total_students': StudentProfile.objects.count(),
            'total_assistants': AssistantProfile.objects.count(),
            'pending_manual_payments': ManualPayment.objects.filter(status='pending').count(),
            'pending_withdrawals': WithdrawRequest.objects.filter(is_paid=False).count(),
            'is_maintenance_mode': site_settings.is_maintenance_mode,
            'recent_logs': AuditLogSerializer(recent_logs, many=True).data,
        })


class AdminToggleMaintenanceAPIView(APIView):
    """تفعيل أو إلغاء وضع الصيانة."""
    permission_classes = [IsAuthenticated, IsPlatformOwner]

    def post(self, request):
        site_settings = SiteSetting.load()
        site_settings.is_maintenance_mode = not site_settings.is_maintenance_mode
        site_settings.save()
        AuditLog.log(
            request,
            AuditLog.ACTION_TOGGLE_MAINT,
            details={'maintenance': site_settings.is_maintenance_mode},
        )
        return Response({
            'message': 'تم تفعيل وضع الصيانة.' if site_settings.is_maintenance_mode else 'تم إلغاء وضع الصيانة.',
            'is_maintenance_mode': site_settings.is_maintenance_mode,
        })


class AdminManageUsersAPIView(APIView):
    """عرض المستخدمين والبحث والفلترة وتنفيذ الإجراءات الإدارية."""
    permission_classes = [IsAuthenticated, IsPlatformModerator]

    def get(self, request):
        query = request.query_params.get('q', '').strip()
        role_filter = request.query_params.get('role', '').strip()

        users = User.objects.all().order_by('-id')
        if role_filter:
            users = users.filter(role=role_filter)
        if query:
            users = users.filter(
                Q(first_name__icontains=query)
                | Q(last_name__icontains=query)
                | Q(email__icontains=query)
                | Q(phone__icontains=query)
                | Q(custom_id__icontains=query)
            )

        return Response({
            'users': UserDetailSerializer(users[:100], many=True, context={'request': request}).data,
            'plans': SubscriptionPlanSerializer(SubscriptionPlan.objects.all(), many=True).data,
        })

    def post(self, request):
        """إجراءات على المستخدم: ban, unban, delete, renew_free."""
        user_id = request.data.get('user_id')
        action = request.data.get('action')
        target = get_object_or_404(User, id=user_id)

        if target.is_superuser:
            return Response({'error': 'لا يمكن التأثير على حساب المالك.'}, status=status.HTTP_400_BAD_REQUEST)

        requester_profile = getattr(request.user, 'admin_profile', None)
        can_delete = request.user.is_superuser or (requester_profile and requester_profile.can_delete_users)

        if action == 'ban':
            target.is_banned = True
            target.save(update_fields=['is_banned'])
            AuditLog.log(request, AuditLog.ACTION_BAN, target_label=target.email, target_id=target.id)
            return Response({'message': f'تم حظر {target.get_full_name() or target.email}.'})

        if action == 'unban':
            target.is_banned = False
            target.save(update_fields=['is_banned'])
            AuditLog.log(request, AuditLog.ACTION_UNBAN, target_label=target.email, target_id=target.id)
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
            AuditLog.log(request, AuditLog.ACTION_RENEW_SUB, target_label=target.get_full_name(), target_id=target.id)
            return Response({'message': f'تم تجديد اشتراك {target.get_full_name()} لمدة 30 يوماً.'})

        return Response({'error': 'إجراء غير صالح.'}, status=status.HTTP_400_BAD_REQUEST)


class AdminFinanceAPIView(APIView):
    """التقارير المالية، طلبات السحب، وطلبات الدفع اليدوي."""
    permission_classes = [IsAuthenticated, IsPlatformFinance]

    def get(self, request):
        transactions = PaymentTransaction.objects.select_related('teacher__user').order_by('-date')[:100]
        total_sub_revenue = PaymentTransaction.objects.aggregate(t=Sum('amount'))['t'] or 0
        total_pkg_revenue = PackageEnrollment.objects.filter(is_paid=True).aggregate(t=Sum('package__price'))['t'] or 0
        withdraw_requests = WithdrawRequest.objects.select_related('wallet__teacher__user').order_by('-created_at')
        manual_payments = ManualPayment.objects.select_related('user').order_by('-created_at')

        return Response({
            'total_subscription_revenue': total_sub_revenue,
            'total_package_revenue': total_pkg_revenue,
            'withdraw_requests': WithdrawRequestSerializer(withdraw_requests, many=True).data,
            'manual_payments': ManualPaymentSerializer(manual_payments, many=True, context={'request': request}).data,
            'transactions': [
                {
                    'id': tr.id,
                    'teacher_name': f"{tr.teacher.user.first_name} {tr.teacher.user.last_name}".strip(),
                    'amount': tr.amount,
                    'date': tr.date,
                    'transaction_id': tr.transaction_id,
                }
                for tr in transactions
            ],
        })

    def post(self, request):
        """تسديد طلب سحب أو قبول/رفض طلب دفع يدوي."""
        item_type = request.data.get('item_type')  # 'withdrawal' | 'manual_payment'
        if item_type == 'withdrawal':
            req = get_object_or_404(WithdrawRequest, id=request.data.get('id'))
            req.is_paid = True
            req.save(update_fields=['is_paid'])
            AuditLog.log(request, AuditLog.ACTION_PAY_WITHDRAW, target_label=str(req), target_id=req.id)
            return Response({'message': f'تم تسجيل تحويل {req.amount} EGP.'})

        if item_type == 'manual_payment':
            payment = get_object_or_404(ManualPayment, id=request.data.get('id'))
            action = request.data.get('action')
            if action == 'approve':
                payment.status = 'approved'
                payment.save()
                AuditLog.log(request, AuditLog.ACTION_EDIT_USER, target_label=f'دفع يدوي {payment.id}', target_id=payment.id)
                return Response({'message': 'تم قبول طلب الدفع وتفعيل الاشتراك/الحزمة.'})
            if action == 'reject':
                payment.status = 'rejected'
                payment.save()
                return Response({'message': 'تم رفض طلب الدفع.'})

        return Response({'error': 'إجراء غير صالح.'}, status=status.HTTP_400_BAD_REQUEST)


class AdminPlansAndStaffAPIView(APIView):
    """إدارة الباقات وفريق الإدارة للمالك."""
    permission_classes = [IsAuthenticated, IsPlatformOwner]

    def get(self, request):
        plans = SubscriptionPlan.objects.all().order_by('price')
        staff = AdminProfile.objects.select_related('user', 'appointed_by').order_by('admin_role')
        return Response({
            'plans': SubscriptionPlanSerializer(plans, many=True).data,
            'staff': AdminProfileSerializer(staff, many=True).data,
            'admin_roles': [{'code': c, 'name': str(l)} for c, l in AdminRole.choices],
        })

    def post(self, request):
        action = request.data.get('action')
        if action == 'add_plan':
            plan = SubscriptionPlan.objects.create(
                name=str(request.data.get('name', '')).strip(),
                price=int(request.data.get('price', 0)),
                description=str(request.data.get('description', '')).strip(),
                student_limit=int(request.data.get('student_limit', 1000)),
                group_limit=int(request.data.get('group_limit', 5)),
                assistant_limit=int(request.data.get('assistant_limit', 2)),
                allow_online_packages=bool(request.data.get('allow_online_packages', False)),
                allow_question_images=bool(request.data.get('allow_question_images', False)),
                is_default=bool(request.data.get('is_default', False)),
            )
            AuditLog.log(request, AuditLog.ACTION_ADD_PLAN, target_label=plan.name, target_id=plan.id)
            return Response({'message': 'تم إضافة الباقة.', 'plan': SubscriptionPlanSerializer(plan).data}, status=status.HTTP_201_CREATED)

        if action == 'delete_plan':
            plan = get_object_or_404(SubscriptionPlan, id=request.data.get('plan_id'))
            plan.delete()
            return Response({'message': 'تم حذف الباقة.'})

        if action == 'appoint_staff':
            email = str(request.data.get('email', '')).strip()
            admin_role = str(request.data.get('admin_role', AdminRole.MODERATOR))
            notes = str(request.data.get('notes', '')).strip()
            target = get_object_or_404(User, email__iexact=email)
            if target.is_superuser:
                return Response({'error': 'المالك لا يحتاج لبروفايل إداري.'}, status=status.HTTP_400_BAD_REQUEST)
            target.role = 'admin'
            target.save(update_fields=['role'])
            prof, _ = AdminProfile.objects.update_or_create(
                user=target,
                defaults={
                    'admin_role': admin_role,
                    'notes': notes,
                    'is_active_admin': True,
                    'appointed_by': request.user,
                },
            )
            return Response({'message': 'تم تعيين المسؤول بنجاح.', 'staff': AdminProfileSerializer(prof).data})

        if action == 'remove_staff':
            prof = get_object_or_404(AdminProfile, id=request.data.get('profile_id'))
            prof.user.role = 'student'
            prof.user.save(update_fields=['role'])
            prof.delete()
            return Response({'message': 'تم إزالة المسؤول من الفريق الإداري.'})

        return Response({'error': 'إجراء غير صالح.'}, status=status.HTTP_400_BAD_REQUEST)

