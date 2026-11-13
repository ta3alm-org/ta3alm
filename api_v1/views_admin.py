"""
api_v1/views_admin.py
نقاط النهاية الخاصة بلوحة الإدارة ومالك المنصة (الإحصاءات، الصيانة، إدارة المستخدمين، المالية، الباقات، المناهج، فريق الإدارة، سجل الأحداث، وبريد الدعم Zoho).
"""
from datetime import timedelta
import random
import string
from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.models import Q, Sum
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import StudentProfile, OneTimeLoginLink
from assistants.models import AssistantProfile
from core.models import SiteSetting, ManualPayment, Subject, CurriculumUnit, CurriculumLesson
from dashboard_admin.models import AdminProfile, AdminRole, AuditLog, ZohoMailConfig
from services.zoho_mail_service import ZohoMailService
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
    PackageEnrollmentSerializer,
    AdminProfileSerializer,
    AuditLogSerializer,
    CurriculumUnitSerializer,
    SubjectSerializer,
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
    """عرض المستخدمين والبحث والفلترة وتنفيذ الإجراءات الإدارية الكاملة."""
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
            'subjects': SubjectSerializer(Subject.objects.all(), many=True).data,
        })

    @transaction.atomic
    def post(self, request):
        """إجراءات على المستخدم: ban, unban, delete, renew_free, edit_user, change_password, generate_login_link."""
        user_id = request.data.get('user_id')
        action = request.data.get('action')
        target = get_object_or_404(User, id=user_id)

        if target.is_superuser and action in ('ban', 'delete'):
            return Response({'error': 'لا يمكن حظر أو حذف حساب المالك.'}, status=status.HTTP_400_BAD_REQUEST)

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
            login_url = f"https://ta3alm.online/login/auto/{link.token}/"
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


class AdminFinanceAPIView(APIView):
    """التقارير المالية، طلبات السحب، مبيعات الحزم، وطلبات الدفع اليدوي."""
    permission_classes = [IsAuthenticated, IsPlatformFinance]

    def get(self, request):
        transactions = PaymentTransaction.objects.select_related('teacher__user').order_by('-date')[:100]
        total_sub_revenue = PaymentTransaction.objects.aggregate(t=Sum('amount'))['t'] or 0
        total_pkg_revenue = PackageEnrollment.objects.filter(is_paid=True).aggregate(t=Sum('package__price'))['t'] or 0
        withdraw_requests = WithdrawRequest.objects.select_related('wallet__teacher__user').order_by('-created_at')
        manual_payments = ManualPayment.objects.select_related('user').order_by('-created_at')
        student_payments = (
            PackageEnrollment.objects
            .filter(is_paid=True)
            .select_related('student__user', 'package__teacher__user', 'package__teacher__subject')
            .order_by('-joined_at')[:100]
        )

        return Response({
            'total_subscription_revenue': total_sub_revenue,
            'total_package_revenue': total_pkg_revenue,
            'withdraw_requests': WithdrawRequestSerializer(withdraw_requests, many=True).data,
            'manual_payments': ManualPaymentSerializer(manual_payments, many=True, context={'request': request}).data,
            'student_payments': PackageEnrollmentSerializer(student_payments, many=True, context={'request': request}).data,
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
    """إدارة الباقات، المناهج الدراسية، المواد، فريق الإدارة، وسجل الأحداث للمالك."""
    permission_classes = [IsAuthenticated, IsPlatformOwner]

    def get(self, request):
        plans = SubscriptionPlan.objects.all().order_by('price')
        staff = AdminProfile.objects.select_related('user', 'appointed_by').order_by('admin_role')
        action_filter = request.query_params.get('action_filter', '').strip()
        logs_qs = AuditLog.objects.select_related('admin').order_by('-created_at')
        if action_filter:
            logs_qs = logs_qs.filter(action=action_filter)
        units_qs = CurriculumUnit.objects.select_related('subject').prefetch_related('lessons').order_by('grade', 'subject', 'term', 'order')
        subjects = Subject.objects.all().order_by('name')

        return Response({
            'plans': SubscriptionPlanSerializer(plans, many=True).data,
            'staff': AdminProfileSerializer(staff, many=True).data,
            'admin_roles': [{'code': c, 'name': str(l)} for c, l in AdminRole.choices],
            'audit_logs': AuditLogSerializer(logs_qs[:100], many=True).data,
            'curriculum_units': CurriculumUnitSerializer(units_qs, many=True).data,
            'subjects': SubjectSerializer(subjects, many=True).data,
        })

    @transaction.atomic
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

        if action == 'edit_plan':
            plan = get_object_or_404(SubscriptionPlan, id=request.data.get('plan_id'))
            for f in ('name', 'description'):
                if f in request.data:
                    setattr(plan, f, str(request.data[f]).strip())
            for f in ('price', 'student_limit', 'group_limit', 'assistant_limit'):
                if f in request.data:
                    setattr(plan, f, int(request.data[f]))
            for f in ('allow_online_packages', 'allow_question_images', 'is_default'):
                if f in request.data:
                    setattr(plan, f, bool(request.data[f]))
            plan.save()
            AuditLog.log(request, AuditLog.ACTION_EDIT_PLAN, target_label=plan.name, target_id=plan.id)
            return Response({'message': 'تم تحديث الباقة بنجاح.', 'plan': SubscriptionPlanSerializer(plan).data})

        if action == 'delete_plan':
            plan = get_object_or_404(SubscriptionPlan, id=request.data.get('plan_id'))
            name = plan.name
            plan.delete()
            AuditLog.log(request, AuditLog.ACTION_DEL_PLAN, target_label=name)
            return Response({'message': 'تم حذف الباقة.'})

        if action == 'create_staff':
            first_name = str(request.data.get('first_name', '')).strip()
            last_name = str(request.data.get('last_name', '')).strip()
            email = str(request.data.get('email', '')).strip().lower()
            phone = str(request.data.get('phone', '')).strip()
            password = str(request.data.get('password', '')).strip()
            admin_role = str(request.data.get('admin_role', AdminRole.MODERATOR))
            notes = str(request.data.get('notes', '')).strip()

            if not all([first_name, email, phone, password]):
                return Response({'error': 'يرجى ملء جميع الحقول الأساسية.'}, status=status.HTTP_400_BAD_REQUEST)
            if User.objects.filter(email__iexact=email).exists():
                return Response({'error': 'البريد الإلكتروني مسجل مسبقاً.'}, status=status.HTTP_400_BAD_REQUEST)
            if User.objects.filter(phone=phone).exists():
                return Response({'error': 'رقم الهاتف مسجل مسبقاً.'}, status=status.HTTP_400_BAD_REQUEST)

            chars = string.ascii_uppercase + string.digits
            custom_id = 'M' + ''.join(random.choices(chars, k=6))
            new_user = User.objects.create_user(
                username=email,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                phone=phone,
                role='admin',
                custom_id=custom_id,
            )
            prof = AdminProfile.objects.create(
                user=new_user,
                admin_role=admin_role,
                notes=notes,
                is_active_admin=True,
                appointed_by=request.user,
            )
            return Response({'message': 'تم إنشاء حساب المسؤول بنجاح.', 'staff': AdminProfileSerializer(prof).data}, status=status.HTTP_201_CREATED)

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

        if action == 'add_curriculum_unit':
            title = str(request.data.get('title', '')).strip()
            subject_id = request.data.get('subject_id')
            grade = str(request.data.get('grade', '')).strip()
            term = str(request.data.get('term', '1')).strip()
            order = int(request.data.get('order', 1))
            lessons_raw = request.data.get('lessons', [])

            if not title or not subject_id or not grade:
                return Response({'error': 'عنوان الوحدة والمادة والصف الدراسي مطلوبة.'}, status=status.HTTP_400_BAD_REQUEST)

            unit = CurriculumUnit.objects.create(
                title=title,
                subject_id=subject_id,
                grade=grade,
                term=term,
                order=order,
            )
            for idx, item in enumerate(lessons_raw):
                l_title = str(item.get('title', '') if isinstance(item, dict) else item).strip()
                if l_title:
                    CurriculumLesson.objects.create(
                        unit=unit,
                        title=l_title,
                        order=int(item.get('order', idx + 1)) if isinstance(item, dict) else (idx + 1),
                    )
            return Response({
                'message': 'تم إضافة الوحدة الدراسية ودروسها بنجاح.',
                'unit': CurriculumUnitSerializer(unit).data,
            }, status=status.HTTP_201_CREATED)

        if action == 'edit_curriculum_unit':
            unit = get_object_or_404(CurriculumUnit, id=request.data.get('unit_id'))
            if 'title' in request.data:
                unit.title = str(request.data['title']).strip()
            if 'subject_id' in request.data and request.data['subject_id']:
                unit.subject_id = request.data['subject_id']
            if 'grade' in request.data:
                unit.grade = str(request.data['grade']).strip()
            if 'term' in request.data:
                unit.term = str(request.data['term']).strip()
            if 'order' in request.data:
                unit.order = int(request.data['order'])
            unit.save()

            if 'lessons' in request.data and isinstance(request.data['lessons'], list):
                unit.lessons.all().delete()
                for idx, item in enumerate(request.data['lessons']):
                    l_title = str(item.get('title', '') if isinstance(item, dict) else item).strip()
                    if l_title:
                        CurriculumLesson.objects.create(
                            unit=unit,
                            title=l_title,
                            order=int(item.get('order', idx + 1)) if isinstance(item, dict) else (idx + 1),
                        )
            return Response({
                'message': 'تم تحديث الوحدة الدراسية بنجاح.',
                'unit': CurriculumUnitSerializer(unit).data,
            })

        if action == 'delete_curriculum_unit':
            unit = get_object_or_404(CurriculumUnit, id=request.data.get('unit_id'))
            unit.delete()
            return Response({'message': 'تم حذف الوحدة الدراسية.'})

        if action == 'add_subject':
            name = str(request.data.get('name', '')).strip()
            if not name:
                return Response({'error': 'يرجى إدخال اسم المادة.'}, status=status.HTTP_400_BAD_REQUEST)
            sub, _ = Subject.objects.get_or_create(name=name)
            return Response({'message': 'تم إضافة المادة الدراسية.', 'subject': SubjectSerializer(sub).data}, status=status.HTTP_201_CREATED)

        if action == 'delete_subject':
            sub = get_object_or_404(Subject, id=request.data.get('subject_id'))
            sub.delete()
            return Response({'message': 'تم حذف المادة الدراسية.'})

        return Response({'error': 'إجراء غير صالح.'}, status=status.HTTP_400_BAD_REQUEST)


class AdminSupportInboxAPIView(APIView):
    """بريد الدعم الفني (Zoho Mail REST API) وإعدادات الربط."""
    permission_classes = [IsAuthenticated, IsPlatformModerator]

    def get(self, request):
        config = ZohoMailConfig.load()
        service = ZohoMailService(config=config)
        message_id = request.query_params.get('message_id', '').strip()
        folder_id = request.query_params.get('folder_id')

        if message_id and service.is_connected():
            try:
                content_data = service.get_message_content(message_id, folder_id=folder_id)
                return Response({'message_detail': content_data})
            except Exception as exc:
                return Response({'error': f'تعذر جلب محتوى الرسالة: {exc}'}, status=status.HTTP_400_BAD_REQUEST)

        messages_list = []
        error_message = None
        if service.is_connected():
            q = request.query_params.get('q', '').strip()
            try:
                res = service.list_messages(limit=25, search_key=q or None)
                raw = res.get('data', []) if isinstance(res, dict) else []
                for m in raw:
                    messages_list.append({
                        'messageId': str(m.get('messageId', '')),
                        'folderId': str(m.get('folderId', '')),
                        'fromAddress': m.get('fromAddress', ''),
                        'sender': m.get('sender', m.get('fromAddress', '')),
                        'subject': m.get('subject', '(بدون عنوان)'),
                        'summary': m.get('summary', ''),
                        'receivedTime': m.get('formatted_date', ''),
                        'isRead': m.get('isRead', m.get('status') == '1'),
                    })
            except Exception as exc:
                error_message = str(exc)

        return Response({
            'is_configured': service.is_configured(),
            'is_connected': service.is_connected(),
            'support_email': service.support_email,
            'account_id': config.get_effective_account_id(),
            'api_domain': config.zoho_api_url,
            'accounts_domain': config.zoho_accounts_url,
            'client_id': config.get_effective_client_id(),
            'messages': messages_list,
            'error_message': error_message,
        })

    def post(self, request):
        config = ZohoMailConfig.load()
        service = ZohoMailService(config=config)
        action = request.data.get('action')

        if action == 'save_settings':
            if not request.user.is_superuser:
                return Response({'error': 'إعدادات الربط متاحة للمالك فقط.'}, status=status.HTTP_403_FORBIDDEN)
            config.support_email = str(request.data.get('support_email', config.support_email)).strip() or 'support@ta3alm.online'
            api_url = request.data.get('zoho_api_url') or request.data.get('api_domain') or config.zoho_api_url
            accounts_url = request.data.get('zoho_accounts_url') or request.data.get('accounts_domain') or config.zoho_accounts_url
            config.zoho_api_url = str(api_url).strip() or 'https://mail.zoho.com/api'
            config.zoho_accounts_url = str(accounts_url).strip() or 'https://accounts.zoho.com'
            config.client_id = str(request.data.get('client_id', config.client_id)).strip()
            client_secret = str(request.data.get('client_secret', '')).strip()
            if client_secret:
                config.client_secret = client_secret
            refresh_token = str(request.data.get('refresh_token', '')).strip()
            if refresh_token:
                config.refresh_token = refresh_token
                config.access_token = ''
            account_id = str(request.data.get('account_id', '')).strip()
            if account_id:
                config.account_id = account_id
            config.save()
            return Response({'message': 'تم حفظ إعدادات بريد الدعم Zoho بنجاح.'})

        if not service.is_connected():
            return Response({'error': 'بريد الدعم Zoho غير مربوط حالياً.'}, status=status.HTTP_400_BAD_REQUEST)

        to_address = str(request.data.get('to_address', '')).strip()
        subject = str(request.data.get('subject', '')).strip()
        body_text = str(request.data.get('body', '')).strip()

        if not to_address or not body_text:
            return Response({'error': 'يرجى إدخال البريد المرسل إليه ونص الرسالة.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            body_html = f'<div dir="rtl" style="font-family:Cairo,Tahoma,sans-serif;font-size:15px;line-height:1.8;">{body_text.replace(chr(10), "<br>")}</div>'
            service.compose_new_message(
                to_email=to_address,
                subject=subject or 'رسالة من الدعم الفني - منصة تعلّم',
                content=body_html,
            )
            return Response({'message': f'تم إرسال الرسالة إلى {to_address} بنجاح.'})
        except Exception as exc:
            return Response({'error': f'فشل إرسال البريد: {exc}'}, status=status.HTTP_400_BAD_REQUEST)
