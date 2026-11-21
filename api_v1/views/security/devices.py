"""api_v1.views.security.devices
Extracted from api_v1/views_security.py.
"""
from __future__ import annotations

from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from api_v1.device_security_service import (
    get_user_device_limit,
    record_device_activity,
    record_security_event,
    register_or_update_device,
    revoke_user_device,
    serialize_device_summary,
)
from api_v1.models import (
    DeviceTrustStatus,
    RegisteredDevice,
)
from api_v1.permissions import IsNotBanned

from api_v1.views.security.helpers import (
    _extract_client_installation_id,
    _is_platform_admin,
)

User = get_user_model()


class SecurityDeviceRegisterAPIView(APIView):
    """تسجيل أو تحديث جهاز المستخدم وتوليد بصمة الخادم وجلسة الجهاز."""
    permission_classes = [IsAuthenticated, IsNotBanned]

    def post(self, request):
        installation_id = _extract_client_installation_id(request)
        raw_info = request.data.get('device_info')
        if not isinstance(raw_info, dict):
            raw_info = {
                k: request.data.get(k)
                for k in (
                    'device_name', 'manufacturer', 'model', 'os_name', 'android_version',
                    'api_level', 'cpu_arch', 'cpu_info', 'gpu_renderer', 'gpu_vendor',
                    'screen_resolution', 'app_version', 'app_build_number', 'package_name',
                    'signing_cert_sha256', 'apk_cert_sha256', 'installer_source',
                    'installer_package', 'integrity_signals',
                )
                if k in request.data
            }

        token_jti = ''
        if isinstance(request.auth, dict):
            token_jti = str(request.auth.get('jti') or '')

        outcome = register_or_update_device(
            request=request,
            user=request.user,
            installation_id=installation_id,
            device_info=raw_info,
            token_jti=token_jti,
        )
        clean_payload = {k: v for k, v in outcome.items() if k not in ('device_obj', 'session_obj')}
        http_status = status.HTTP_200_OK if clean_payload.get('allowed') else status.HTTP_403_FORBIDDEN
        return Response(clean_payload, status=http_status)


class SecurityDeviceListAPIView(APIView):
    """عرض الأجهزة الموثوقة للمستخدم الحالي (أو لمستخدم محدد عند الطلب من مسؤول)."""
    permission_classes = [IsAuthenticated, IsNotBanned]

    def get(self, request):
        target_user = request.user
        req_user_id = request.query_params.get('user_id')
        if req_user_id and str(req_user_id) != str(request.user.id):
            if not _is_platform_admin(request.user):
                return Response({'error': 'غير مصرح لك بعرض أجهزة مستخدم آخر.'}, status=status.HTTP_403_FORBIDDEN)
            target_user = get_object_or_404(User, id=req_user_id)

        current_inst_id = (
            request.META.get('HTTP_X_DEVICE_ID')
            or request.META.get('HTTP_X_INSTALLATION_ID')
            or ''
        ).strip()

        devices_qs = RegisteredDevice.objects.filter(user=target_user).order_by('-is_active', '-last_active_at')
        limit = get_user_device_limit(target_user)
        active_count = devices_qs.filter(is_active=True).exclude(
            trust_status__in=[DeviceTrustStatus.REVOKED, DeviceTrustStatus.BLOCKED]
        ).count()

        return Response({
            'device_limit': limit,
            'active_count': active_count,
            'current_installation_id': current_inst_id,
            'devices': [serialize_device_summary(d, current_inst_id) for d in devices_qs],
        })


class SecurityDeviceRevokeAPIView(APIView):
    """إلغاء جهاز أو تسجيل خروجه أو الإبلاغ عنه كجهاز غير معروف مع فحص صارم للملكية (Anti-IDOR)."""
    permission_classes = [IsAuthenticated, IsNotBanned]

    def post(self, request, device_id):
        device = get_object_or_404(RegisteredDevice, id=device_id)
        is_admin = _is_platform_admin(request.user)

        if device.user_id != request.user.id and not is_admin:
            record_security_event(
                event_type='cross_account_device_idor_attempt',
                severity='high',
                risk_score=80,
                user=request.user,
                device=device,
                installation_id=_extract_client_installation_id(request) or device.installation_id,
                request=request,
                action_taken='denied_idor',
                details={'target_device_id': device.id, 'target_owner_id': device.user_id},
            )
            return Response(
                {'error': 'غير مصرح لك بالتحكم في جهاز تابع لحساب آخر.', 'code': 'FORBIDDEN_DEVICE_OWNER'},
                status=status.HTTP_403_FORBIDDEN,
            )

        action = str(request.data.get('action') or 'revoke').strip().lower()
        if action not in ('revoke', 'logout', 'report_unfamiliar'):
            return Response(
                {'error': 'قيمة action غير صالحة. القيم المسموحة: revoke, logout, report_unfamiliar.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        reason = str(request.data.get('reason') or '').strip()
        updated = revoke_user_device(
            device=device,
            actor=request.user,
            request=request,
            mode=action,
            reason=reason,
        )
        current_inst_id = (request.META.get('HTTP_X_DEVICE_ID') or '').strip()
        return Response({
            'message': 'تم تنفيذ الإجراء على الجهاز بنجاح.',
            'action': action,
            'device': serialize_device_summary(updated, current_inst_id),
        })


class SecurityDeviceVerifyAPIView(APIView):
    """إعادة التحقق من الجهاز المقيّد/المعلّق واستعادة ثقته بعد تأكيد كلمة المرور أو موافقة المسؤول."""
    permission_classes = [IsAuthenticated, IsNotBanned]

    def post(self, request, device_id):
        device = get_object_or_404(RegisteredDevice, id=device_id)
        is_admin = _is_platform_admin(request.user)

        if device.user_id != request.user.id and not is_admin:
            return Response(
                {'error': 'غير مصرح لك بالتحقق من جهاز تابع لحساب آخر.'},
                status=status.HTTP_403_FORBIDDEN,
            )

        if device.trust_status == DeviceTrustStatus.BLOCKED and not is_admin:
            return Response(
                {'error': 'هذا الجهاز محظور إدارياً ولا يمكن تفعيله ذاتياً.', 'code': 'DEVICE_BLOCKED'},
                status=status.HTTP_403_FORBIDDEN,
            )

        if not is_admin:
            if request.user.has_usable_password():
                password = str(request.data.get('password') or '')
                if not password or not request.user.check_password(password):
                    return Response(
                        {'error': 'كلمة المرور غير صحيحة لإعادة توثيق الجهاز.', 'code': 'INVALID_PASSWORD'},
                        status=status.HTTP_403_FORBIDDEN,
                    )
            else:
                confirm_email = str(request.data.get('email') or '').strip().lower()
                if not confirm_email or confirm_email != (request.user.email or '').strip().lower():
                    return Response(
                        {'error': 'يرجى تأكيد البريد الإلكتروني لإعادة توثيق الجهاز.', 'code': 'EMAIL_CONFIRMATION_REQUIRED'},
                        status=status.HTTP_403_FORBIDDEN,
                    )

        device.trust_status = DeviceTrustStatus.TRUSTED
        device.is_verified = True
        device.is_active = True
        device.requires_reauth = False
        device.risk_score = 0
        device.risk_level = 'low'
        device.save(
            update_fields=['trust_status', 'is_verified', 'is_active', 'requires_reauth', 'risk_score', 'risk_level']
        )

        record_device_activity(
            request=request,
            user=device.user,
            device=device,
            activity_type='device_reverified',
            metadata={'verified_by_admin': is_admin},
        )
        record_security_event(
            event_type='device_reverified',
            severity='low',
            risk_score=0,
            user=device.user,
            device=device,
            request=request,
            action_taken='restored_trusted',
            details={'verified_by_admin': is_admin},
        )
        return Response({
            'message': 'تم التحقق من الجهاز واستعادة ثقته بنجاح.',
            'device': serialize_device_summary(device),
        })
