"""
api_v1/authentication.py
نظام مصادقة مزدوج يدعم:
1. JWT Authentication (Bearer <access_token>) مع Access + Refresh Tokens باستخدام PyJWT.
2. DRF TokenAuthentication (Token <key>) للتوافق الكامل مع أي عميل قديم.
"""
from datetime import datetime, timedelta, timezone as dt_timezone
import uuid
import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework import authentication, exceptions
from rest_framework.authtoken.models import Token

User = get_user_model()

ACCESS_TOKEN_LIFETIME = timedelta(hours=12)
REFRESH_TOKEN_LIFETIME = timedelta(days=30)
JWT_ALGORITHM = 'HS256'


def generate_jwt_pair(user) -> dict:
    """توليد زوج من Access Token و Refresh Token للمستخدم بالإضافة لـ DRF Token."""
    now = datetime.now(dt_timezone.utc)
    access_payload = {
        'token_type': 'access',
        'user_id': user.id,
        'role': user.role,
        'is_superuser': user.is_superuser,
        'jti': uuid.uuid4().hex,
        'iat': int(now.timestamp()),
        'exp': int((now + ACCESS_TOKEN_LIFETIME).timestamp()),
    }
    refresh_payload = {
        'token_type': 'refresh',
        'user_id': user.id,
        'jti': uuid.uuid4().hex,
        'iat': int(now.timestamp()),
        'exp': int((now + REFRESH_TOKEN_LIFETIME).timestamp()),
    }
    access_token = jwt.encode(access_payload, settings.SECRET_KEY, algorithm=JWT_ALGORITHM)
    refresh_token = jwt.encode(refresh_payload, settings.SECRET_KEY, algorithm=JWT_ALGORITHM)
    drf_token, _ = Token.objects.get_or_create(user=user)
    return {
        'access': access_token,
        'refresh': refresh_token,
        'token': drf_token.key,
        'expires_in': int(ACCESS_TOKEN_LIFETIME.total_seconds()),
    }


def decode_jwt_token(raw_token: str, expected_type: str = 'access') -> dict:
    """فك تشفير والتحقق من صلاحية ونوع الـ JWT Token."""
    try:
        payload = jwt.decode(raw_token, settings.SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise exceptions.AuthenticationFailed('انتهت صلاحية الجلسة (Token Expired). يرجى إعادة تسجيل الدخول أو تحديث التوكن.')
    except jwt.InvalidTokenError:
        raise exceptions.AuthenticationFailed('رمز المصادقة غير صالح (Invalid Token).')

    if payload.get('token_type') != expected_type:
        raise exceptions.AuthenticationFailed(f'نوع التوكن غير صالح، المطلوب: {expected_type}.')

    return payload


class JWTAndTokenAuthentication(authentication.BaseAuthentication):
    """
    يدعم:
    - Authorization: Bearer <jwt_access_token>
    - Authorization: Token <drf_token_key>
    """

    def authenticate(self, request):
        auth_header = authentication.get_authorization_header(request).decode('utf-8').strip()
        if not auth_header:
            return None

        parts = auth_header.split()
        if len(parts) != 2:
            return None

        scheme, raw_token = parts[0].lower(), parts[1].strip()

        if scheme == 'bearer':
            # محاولة فك JWT أولاً، ولو كان DRF Token مرسلاً كـ Bearer نقبله أيضاً للتسهيل
            if '.' in raw_token:
                payload = decode_jwt_token(raw_token, expected_type='access')
                user_id = payload.get('user_id')
                try:
                    user = User.objects.get(id=user_id, is_active=True)
                except User.DoesNotExist:
                    raise exceptions.AuthenticationFailed('المستخدم غير موجود أو غير مفعل.')
                if user.is_banned:
                    raise exceptions.PermissionDenied('تم حظر حسابك من قِبل إدارة المنصة.')
                return (user, payload)
            else:
                return self._authenticate_drf_token(raw_token)

        if scheme == 'token':
            return self._authenticate_drf_token(raw_token)

        return None

    def _authenticate_drf_token(self, key: str):
        try:
            token = Token.objects.select_related('user').get(key=key)
        except Token.DoesNotExist:
            raise exceptions.AuthenticationFailed('رمز الدخول غير صالح.')

        if not token.user.is_active:
            raise exceptions.AuthenticationFailed('هذا الحساب غير مفعل.')

        if token.user.is_banned:
            raise exceptions.PermissionDenied('تم حظر حسابك من قِبل إدارة المنصة.')

        return (token.user, token)

    def authenticate_header(self, request):
        return 'Bearer'

