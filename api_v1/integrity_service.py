"""
api_v1/integrity_service.py
التحقق من Google Play Integrity API من جهة الخادم + سياسة المخاطر المراعية للبيئة (Production / Testing / Dev).
لا يثق الخادم أبداً في قرار العميل وحده.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import timedelta
from typing import Any

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .models import DeviceIntegrityRecord, PlayIntegrityNonce
from .video_security import get_client_ip, log_security_event


NONCE_TTL_SECONDS = 300
MAX_TOKEN_AGE_SECONDS = 300


def get_expected_package_name() -> str:
    return os.environ.get('PLAY_INTEGRITY_PACKAGE_NAME', 'online.ta3alm.ta3alm_flutter').strip()


def get_integrity_policy_mode() -> str:
    """
    الأوضاع المدعومة:
    - strict: حظر أي بناء غير معترف به من Play أو جهاز يفشل Basic/Device Integrity.
    - balanced: حظر التلاعب المؤكد، والسماح مع المراقبة/تحقق إضافي لبعض حالات الاختبار المسموحة.
    - audit: تسجيل الحوادث والتنبيه فقط بدون حظر (لمراحل الطرح التدريجي).
    - dev_bypass: للتطوير المحلي واختبارات الوحدات عند غياب Play Store أو DEBUG=True.
    """
    default_mode = 'dev_bypass' if settings.DEBUG else 'balanced'
    return os.environ.get('PLAY_INTEGRITY_POLICY_MODE', default_mode).strip().lower()


def compute_request_hash(action: str, binding_data: str, nonce_id: str) -> str:
    raw = f"ta3alm|{action}|{binding_data}|{nonce_id}".encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


def issue_integrity_challenge(*, user=None, action: str = 'app_startup', binding_data: str = '') -> PlayIntegrityNonce:
    now = timezone.now()
    nonce = PlayIntegrityNonce.objects.create(
        user=user if getattr(user, 'is_authenticated', False) else None,
        action=action[:64],
        binding_data=binding_data[:255],
        expires_at=now + timedelta(seconds=NONCE_TTL_SECONDS),
    )
    nonce.expected_request_hash = compute_request_hash(nonce.action, nonce.binding_data, str(nonce.nonce_id))
    nonce.save(update_fields=['expected_request_hash'])
    return nonce


def decode_token_with_google_api(integrity_token: str, package_name: str) -> dict[str, Any]:
    """
    يفك تشفير التوكن عبر Google Play Integrity REST API باستخدام Service Account.
    يرفض الاستدعاء إذا لم تتوفر بيانات اعتماد Google في بيئة الإنتاج.
    """
    service_account_json = os.environ.get('PLAY_INTEGRITY_SERVICE_ACCOUNT_JSON', '').strip()
    credentials_file = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS', '').strip()

    from google.oauth2 import service_account
    from googleapiclient.discovery import build

    scopes = ['https://www.googleapis.com/auth/playintegrity']
    if service_account_json:
        info = json.loads(service_account_json)
        creds = service_account.Credentials.from_service_account_info(info, scopes=scopes)
    elif credentials_file and os.path.exists(credentials_file):
        creds = service_account.Credentials.from_service_account_file(credentials_file, scopes=scopes)
    else:
        raise RuntimeError('PLAY_INTEGRITY_CREDENTIALS_NOT_CONFIGURED')

    service = build('playintegrity', 'v1', credentials=creds, cache_discovery=False)
    response = (
        service.v1()
        .decodeIntegrityToken(
            packageName=package_name,
            body={'integrityToken': integrity_token},
        )
        .execute()
    )
    return response.get('tokenPayloadExternal', response)


def evaluate_integrity_payload(
    *,
    decoded_payload: dict[str, Any],
    nonce: PlayIntegrityNonce | None,
    expected_package: str,
    tamper_signals: dict[str, Any],
    policy_mode: str,
    is_debug_build: bool = False,
) -> dict[str, Any]:
    """
    يقيّم قرار Google Play Integrity وإشارات التلاعب لحساب مستوى المخاطرة والقرار الأمني.
    """
    req_details = decoded_payload.get('requestDetails', {}) or {}
    app_integrity = decoded_payload.get('appIntegrity', {}) or {}
    device_integrity = decoded_payload.get('deviceIntegrity', {}) or {}
    account_details = decoded_payload.get('accountDetails', {}) or {}

    pkg = str(req_details.get('requestPackageName') or app_integrity.get('packageName') or expected_package)
    token_request_hash = str(req_details.get('requestHash') or req_details.get('nonce') or '')
    timestamp_millis = int(req_details.get('timestampMillis') or 0)

    app_verdict = str(app_integrity.get('appRecognitionVerdict') or 'UNEVALUATED')
    device_verdicts = list(device_integrity.get('deviceRecognitionVerdict') or [])
    licensing_verdict = str(account_details.get('appLicensingVerdict') or 'UNEVALUATED')

    reasons = []
    if pkg and expected_package and pkg != expected_package:
        reasons.append('package_name_mismatch')

    if nonce and token_request_hash:
        if token_request_hash not in (nonce.expected_request_hash, str(nonce.nonce_id)):
            reasons.append('request_hash_mismatch')

    if timestamp_millis > 0:
        age_seconds = abs((timezone.now().timestamp() * 1000.0) - timestamp_millis) / 1000.0
        if age_seconds > MAX_TOKEN_AGE_SECONDS:
            reasons.append('stale_integrity_token')

    # تحليل مؤشرات التلاعب المرصودة (لا تمنع وحدها إلا عند تضافر الأدلة أو في strict)
    has_frida = bool(tamper_signals.get('frida_detected') or tamper_signals.get('hooking_detected'))
    has_debugger = bool(tamper_signals.get('debugger_attached'))
    is_rooted = bool(tamper_signals.get('root_detected'))
    sig_mismatch = bool(tamper_signals.get('signature_mismatch'))

    if has_frida:
        reasons.append('hooking_or_frida_detected')
    if sig_mismatch:
        reasons.append('apk_signature_mismatch')
    if has_debugger and not is_debug_build:
        reasons.append('debugger_attached_release')
    if is_rooted:
        reasons.append('root_indicators_present')

    # حساب مستوى الخطورة
    risk_level = 'low'
    if 'package_name_mismatch' in reasons or 'request_hash_mismatch' in reasons or has_frida or sig_mismatch:
        risk_level = 'critical'
    elif app_verdict == 'UNRECOGNIZED_VERSION' and not is_debug_build:
        risk_level = 'high'
        reasons.append('unrecognized_app_version')
    elif 'MEETS_STRONG_INTEGRITY' not in device_verdicts and 'MEETS_DEVICE_INTEGRITY' not in device_verdicts:
        if 'MEETS_BASIC_INTEGRITY' in device_verdicts:
            risk_level = 'medium'
            reasons.append('basic_integrity_only')
        else:
            risk_level = 'high'
            reasons.append('device_failed_integrity')

    if policy_mode == 'audit':
        decision = 'allow' if risk_level == 'low' else 'warn'
    elif policy_mode == 'dev_bypass' and (is_debug_build or settings.DEBUG):
        decision = 'block' if (has_frida or sig_mismatch) else 'allow'
    elif policy_mode == 'strict':
        decision = 'allow' if (
            risk_level == 'low'
            and app_verdict == 'PLAY_RECOGNIZED'
            and ('MEETS_DEVICE_INTEGRITY' in device_verdicts or 'MEETS_STRONG_INTEGRITY' in device_verdicts)
        ) else 'block'
    else:
        # balanced policy
        if risk_level == 'critical':
            decision = 'block'
        elif risk_level == 'high':
            decision = 'block' if (app_verdict == 'UNRECOGNIZED_VERSION' or not device_verdicts) else 'step_up'
        elif risk_level == 'medium':
            decision = 'warn'
        else:
            decision = 'allow'

    return {
        'package_name': pkg,
        'app_recognition_verdict': app_verdict,
        'device_recognition_verdict': device_verdicts,
        'licensing_verdict': licensing_verdict,
        'risk_level': risk_level,
        'policy_decision': decision,
        'reasons': reasons,
    }


@transaction.atomic
def verify_and_record_integrity(
    *,
    request,
    user,
    nonce_id: str | None,
    integrity_token: str | None,
    device_id: str,
    tamper_signals: dict[str, Any] | None = None,
    is_debug_build: bool = False,
    decoder_fn=None,
) -> tuple[DeviceIntegrityRecord, dict[str, Any]]:
    """
    يتحقق من صحة Nonce (لمنع Replay Attack)، ويفك توكن Play Integrity عبر خادم جوجل، ويطبّق سياسة المنصة.
    """
    signals = tamper_signals or {}
    expected_package = get_expected_package_name()
    policy_mode = get_integrity_policy_mode()

    nonce_obj = None
    if nonce_id:
        try:
            nonce_obj = PlayIntegrityNonce.objects.select_for_update().get(nonce_id=nonce_id)
        except PlayIntegrityNonce.DoesNotExist:
            nonce_obj = None

        if not nonce_obj:
            raise ValueError('INVALID_NONCE')
        if nonce_obj.is_used:
            log_security_event(
                event_type='token_replayed',
                user=user,
                severity='critical',
                request=request,
                device_id=device_id,
                details={'nonce_id': str(nonce_id)},
            )
            raise ValueError('NONCE_ALREADY_USED')
        if nonce_obj.expires_at <= timezone.now():
            raise ValueError('NONCE_EXPIRED')

        nonce_obj.is_used = True
        nonce_obj.save(update_fields=['is_used'])

    decoded_payload: dict[str, Any] = {}
    token_str = (integrity_token or '').strip()

    if token_str:
        decoder = decoder_fn or decode_token_with_google_api
        try:
            decoded_payload = decoder(token_str, expected_package)
        except RuntimeError as exc:
            if str(exc) == 'PLAY_INTEGRITY_CREDENTIALS_NOT_CONFIGURED' and policy_mode in ('dev_bypass', 'audit'):
                decoded_payload = {
                    'requestDetails': {
                        'requestPackageName': expected_package,
                        'requestHash': nonce_obj.expected_request_hash if nonce_obj else '',
                        'timestampMillis': int(timezone.now().timestamp() * 1000),
                    },
                    'appIntegrity': {'appRecognitionVerdict': 'UNEVALUATED'},
                    'deviceIntegrity': {'deviceRecognitionVerdict': ['MEETS_BASIC_INTEGRITY']},
                    'accountDetails': {'appLicensingVerdict': 'UNEVALUATED'},
                }
            else:
                raise
    else:
        if policy_mode == 'strict':
            decoded_payload = {
                'requestDetails': {'requestPackageName': expected_package},
                'appIntegrity': {'appRecognitionVerdict': 'UNEVALUATED'},
                'deviceIntegrity': {'deviceRecognitionVerdict': []},
                'accountDetails': {'appLicensingVerdict': 'UNEVALUATED'},
            }
        else:
            decoded_payload = {
                'requestDetails': {
                    'requestPackageName': expected_package,
                    'requestHash': nonce_obj.expected_request_hash if nonce_obj else '',
                    'timestampMillis': int(timezone.now().timestamp() * 1000),
                },
                'appIntegrity': {'appRecognitionVerdict': 'UNEVALUATED'},
                'deviceIntegrity': {'deviceRecognitionVerdict': ['MEETS_BASIC_INTEGRITY'] if (is_debug_build or settings.DEBUG) else []},
                'accountDetails': {'appLicensingVerdict': 'UNEVALUATED'},
            }

    # فحص توقيع APK المرجعي إن وُجد في متغيرات البيئة
    expected_sha256 = os.environ.get('ANDROID_RELEASE_CERT_SHA256', '').strip().lower().replace(':', '')
    client_sha256 = str(signals.get('apk_cert_sha256') or '').strip().lower().replace(':', '')
    enriched_signals = dict(signals)
    if expected_sha256 and client_sha256 and client_sha256 != expected_sha256 and not is_debug_build:
        enriched_signals['signature_mismatch'] = True

    verdict = evaluate_integrity_payload(
        decoded_payload=decoded_payload,
        nonce=nonce_obj,
        expected_package=expected_package,
        tamper_signals=enriched_signals,
        policy_mode=policy_mode,
        is_debug_build=is_debug_build,
    )

    record = DeviceIntegrityRecord.objects.create(
        user=user if getattr(user, 'is_authenticated', False) else None,
        device_id=device_id[:128],
        package_name=verdict['package_name'][:128],
        app_recognition_verdict=verdict['app_recognition_verdict'][:64],
        device_recognition_verdict=verdict['device_recognition_verdict'],
        licensing_verdict=verdict['licensing_verdict'][:64],
        risk_level=verdict['risk_level'],
        policy_decision=verdict['policy_decision'],
        tamper_signals=enriched_signals,
        ip_address=get_client_ip(request),
    )

    log_security_event(
        event_type='integrity_blocked' if verdict['policy_decision'] == 'block' else 'integrity_verified',
        user=user,
        severity='high' if verdict['policy_decision'] == 'block' else 'info',
        request=request,
        device_id=device_id,
        details=verdict,
    )
    return record, verdict

