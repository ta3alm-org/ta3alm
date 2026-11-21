"""api_v1.views.admin.dashboard
Extracted from api_v1/views_admin.py.
"""

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db.models import Q
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from accounts.models import StudentProfile
from assistants.models import AssistantProfile
from core.models import (
    SiteSetting,
    ManualPayment,
)
from dashboard_admin.models import AuditLog
from teachers.models import (
    TeacherProfile,
    WithdrawRequest,
)
from api_v1.permissions import (
    IsPlatformAdmin,
    IsPlatformOwner,
)
from api_v1.serializers import AuditLogSerializer
from api_v1.models import UserSecurityProfile

User = get_user_model()


def _backfill_missing_user_profiles(*, force: bool = False) -> None:
    """ضمان وجود سجل Profile للحسابات المكتملة في قاعدة البيانات دون تفعيل حسابات المعلمين غير المستكملة."""
    if not force and not cache.add('ta3alm:admin:backfill_profiles_done', 1, timeout=300):
        return
    missing_teachers = list(
        User.objects.filter(role='teacher', teacher_profile__isnull=True).exclude(
            Q(custom_id__isnull=True) | Q(custom_id='')
        )
    )
    if missing_teachers:
        TeacherProfile.objects.bulk_create(
            [TeacherProfile(user=u, is_approved=False) for u in missing_teachers],
            ignore_conflicts=True,
        )
    missing_students = list(User.objects.filter(role='student', student_profile__isnull=True))
    if missing_students:
        StudentProfile.objects.bulk_create(
            [StudentProfile(user=u, parent_phone='') for u in missing_students],
            ignore_conflicts=True,
        )
    missing_assistants = list(User.objects.filter(role='assistant', assistant_profile__isnull=True))
    if missing_assistants:
        AssistantProfile.objects.bulk_create(
            [AssistantProfile(user=u, phone=u.phone or '') for u in missing_assistants],
            ignore_conflicts=True,
        )


class AdminDashboardAPIView(APIView):
    """لوحة إحصاءات الإدارة وحالة الصيانة وآخر الأحداث."""
    permission_classes = [IsAuthenticated, IsPlatformAdmin]

    def get(self, request):
        _backfill_missing_user_profiles()
        site_settings = SiteSetting.load()
        recent_logs = AuditLog.objects.select_related('admin').order_by('-created_at')[:15]

        return Response({
            'total_teachers': User.objects.filter(role='teacher').count(),
            'approved_teachers_count': TeacherProfile.objects.filter(is_approved=True, user__is_banned=False).count(),
            'pending_teachers_count': TeacherProfile.objects.filter(is_approved=False).count(),
            'active_teachers_count': TeacherProfile.objects.filter(subscription_end_date__gt=timezone.now()).count(),
            'total_students': User.objects.filter(role='student').count(),
            'total_assistants': User.objects.filter(role='assistant').count(),
            'high_risk_users_count': UserSecurityProfile.objects.filter(behavior_risk_level__in=('high', 'critical')).count(),
            'pending_manual_payments': ManualPayment.objects.filter(status='pending').count(),
            'pending_withdrawals': WithdrawRequest.objects.filter(status=WithdrawRequest.STATUS_PENDING).count(),
            'is_maintenance_mode': site_settings.is_maintenance_mode,
            'platform_commission_percentage': site_settings.platform_commission_percentage,
            'app_update': site_settings.build_app_update_payload(request=request),
            'app_release_admin': {
                'android_apk_url': (site_settings.android_apk_url or '').strip(),
                'has_uploaded_apk': bool(site_settings.android_apk_file),
                'uploaded_apk_name': site_settings.android_apk_file.name if site_settings.android_apk_file else '',
                'android_assetlinks_sha256': (site_settings.android_assetlinks_sha256 or '').strip(),
                'effective_assetlinks_fingerprints': site_settings.get_assetlinks_fingerprints(),
            },
            'recent_logs': AuditLogSerializer(recent_logs, many=True).data,
        })

    def post(self, request):
        """تحديث إعدادات المنصة الأساسية مثل نسبة عمولة المنصة أو إعدادات إصدار التطبيق."""
        profile = getattr(request.user, 'admin_profile', None)
        if not (request.user.is_superuser or (profile and profile.is_owner)):
            return Response({'error': 'هذا الإجراء متاح لمالك المنصة فقط.'}, status=status.HTTP_403_FORBIDDEN)

        site_settings = SiteSetting.load()
        updated_fields = []

        if 'platform_commission_percentage' in request.data:
            raw_commission = request.data.get('platform_commission_percentage')
            try:
                commission = int(raw_commission)
            except (TypeError, ValueError):
                return Response({'error': 'يرجى إدخال نسبة عمولة صحيحة بين 0 و 100.'}, status=status.HTTP_400_BAD_REQUEST)
            if commission < 0 or commission > 100:
                return Response({'error': 'يجب أن تكون نسبة العمولة بين 0 و 100%.'}, status=status.HTTP_400_BAD_REQUEST)
            site_settings.platform_commission_percentage = commission
            updated_fields.append('platform_commission_percentage')

        if 'android_latest_version_code' in request.data:
            try:
                site_settings.android_latest_version_code = max(1, int(request.data.get('android_latest_version_code')))
                updated_fields.append('android_latest_version_code')
            except (TypeError, ValueError):
                return Response({'error': 'رقم البناء الأحدث غير صالح.'}, status=status.HTTP_400_BAD_REQUEST)

        if 'android_min_required_version_code' in request.data:
            try:
                site_settings.android_min_required_version_code = max(1, int(request.data.get('android_min_required_version_code')))
                updated_fields.append('android_min_required_version_code')
            except (TypeError, ValueError):
                return Response({'error': 'أقل رقم بناء مسموح غير صالح.'}, status=status.HTTP_400_BAD_REQUEST)

        if 'android_latest_version_name' in request.data:
            site_settings.android_latest_version_name = str(request.data.get('android_latest_version_name', '1.0.0')).strip()[:32]
            updated_fields.append('android_latest_version_name')

        if 'android_apk_url' in request.data:
            site_settings.android_apk_url = str(request.data.get('android_apk_url', '')).strip()[:500]
            updated_fields.append('android_apk_url')

        if 'android_update_release_notes' in request.data:
            site_settings.android_update_release_notes = str(request.data.get('android_update_release_notes', '')).strip()
            updated_fields.append('android_update_release_notes')

        if 'android_apk_sha256' in request.data:
            raw_sha = str(request.data.get('android_apk_sha256', '')).strip()
            normalized_sha = SiteSetting.normalize_file_sha256(raw_sha) if raw_sha else ''
            if raw_sha and not normalized_sha:
                return Response(
                    {'error': 'بصمة SHA-256 لملف APK غير صالحة (يجب أن تكون 64 حرفاً Hex).'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            site_settings.android_apk_sha256 = normalized_sha
            updated_fields.append('android_apk_sha256')

        if 'android_force_update' in request.data:
            val = request.data.get('android_force_update')
            site_settings.android_force_update = str(val).lower() in ('1', 'true', 'yes', 'on') if not isinstance(val, bool) else val
            updated_fields.append('android_force_update')

        if 'android_assetlinks_sha256' in request.data:
            site_settings.android_assetlinks_sha256 = str(request.data.get('android_assetlinks_sha256', '')).strip()
            updated_fields.append('android_assetlinks_sha256')

        clear_uploaded = request.data.get('clear_uploaded_apk')
        if str(clear_uploaded).lower() in ('1', 'true', 'yes', 'on') or clear_uploaded is True:
            if site_settings.android_apk_file:
                try:
                    site_settings.android_apk_file.delete(save=False)
                except Exception:
                    pass
                site_settings.android_apk_file = None
                updated_fields.append('android_apk_file')

        if 'android_apk_file' in request.FILES:
            site_settings.android_apk_file = request.FILES['android_apk_file']
            updated_fields.append('android_apk_file')

        if not updated_fields:
            return Response({'error': 'لم يتم إرسال أي حقول للتحديث.'}, status=status.HTTP_400_BAD_REQUEST)

        site_settings.save()
        AuditLog.log(
            request,
            AuditLog.ACTION_EDIT_USER,
            target_label='تحديث إعدادات المنصة / إصدار التطبيق',
            details={'updated_fields': updated_fields},
        )
        return Response({
            'message': 'تم حفظ الإعدادات بنجاح.',
            'platform_commission_percentage': site_settings.platform_commission_percentage,
            'app_update': site_settings.build_app_update_payload(request=request),
            'app_release_admin': {
                'android_apk_url': (site_settings.android_apk_url or '').strip(),
                'has_uploaded_apk': bool(site_settings.android_apk_file),
                'uploaded_apk_name': site_settings.android_apk_file.name if site_settings.android_apk_file else '',
                'android_assetlinks_sha256': (site_settings.android_assetlinks_sha256 or '').strip(),
                'effective_assetlinks_fingerprints': site_settings.get_assetlinks_fingerprints(),
            },
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
