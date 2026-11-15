from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from django.db.models import Q
from .models import User


@api_view(['POST'])
@permission_classes([AllowAny])
def api_login(request):
    """نقطة دخول آمنة لحسابات التطبيق مع فحص الحظر والتحقق من البريد وحدود الأجهزة."""
    from api_v1.device_security_service import (
        record_failed_login,
        register_or_update_device,
        validate_installation_id,
    )

    identifier = (request.data.get('email') or request.data.get('username') or '').strip()
    password = request.data.get('password') or ''

    if not identifier or not password:
        return Response({'error': 'Missing credentials'}, status=400)

    user = authenticate(request, username=identifier, password=password)
    matched_user = None

    if not user:
        matched_user = User.objects.filter(
            Q(email__iexact=identifier) | Q(username__iexact=identifier)
        ).first()
        if matched_user and matched_user.check_password(password):
            user = matched_user

    if not user:
        record_failed_login(request, identifier, user=matched_user)
        return Response({'error': 'Invalid credentials'}, status=401)

    if not user.is_active or getattr(user, 'is_banned', False):
        return Response({'error': 'Account is disabled or banned'}, status=403)

    if hasattr(user, 'requires_email_verification') and user.requires_email_verification():
        return Response(
            {
                'error': 'Email verification required',
                'code': 'EMAIL_VERIFICATION_REQUIRED',
            },
            status=403,
        )

    installation_id = (
        request.data.get('installation_id')
        or request.META.get('HTTP_X_DEVICE_ID')
        or ''
    ).strip()

    if installation_id:
        ok, clean_id, err = validate_installation_id(installation_id)
        if not ok:
            return Response({'error': err or 'Invalid device identifier'}, status=400)
        device_info = request.data.get('device_info')
        reg = register_or_update_device(
            request=request,
            user=user,
            installation_id=clean_id,
            device_info=device_info if isinstance(device_info, dict) else {},
        )
        if not reg.get('allowed'):
            return Response(
                {
                    'error': reg.get('error') or 'Device not allowed',
                    'code': reg.get('code') or 'DEVICE_NOT_ALLOWED',
                },
                status=403,
            )

    token, _ = Token.objects.get_or_create(user=user)

    return Response({
        'token': token.key,
        'user_id': user.id,
        'first_name': user.first_name,
        'role': user.role,
        'image': '',
    })
