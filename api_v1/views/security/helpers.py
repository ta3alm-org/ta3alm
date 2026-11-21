"""api_v1.views.security.helpers
Extracted from api_v1/views_security.py.
"""
from __future__ import annotations

from api_v1.models import (
    DeviceSecurityEvent,
    DeviceSession,
    SecurityPolicyConfig,
)
from api_v1.security_engine import get_effective_ai_config


ALLOWED_CLIENT_REPORT_EVENTS = {
    'screenshot_attempt': ('medium', 20),
    'screen_recording_detected': ('high', 35),
    'display_capture_detected': ('high', 35),
    'debugger_detected': ('critical', 75),
    'tamper_detected': ('critical', 80),
    'integrity_failure': ('high', 65),
    'unfamiliar_device_report': ('high', 40),
    'proxy_mitm_detected': ('critical', 95),
    'user_ca_mitm_detected': ('critical', 95),
    'request_tamper_detected': ('critical', 95),
    'vpn_detected': ('medium', 25),
}


def _is_platform_admin(user) -> bool:
    if not user or not getattr(user, 'is_authenticated', False):
        return False
    if getattr(user, 'is_superuser', False):
        return True
    profile = getattr(user, 'admin_profile', None)
    return bool(profile and profile.is_active_admin)


def _extract_client_installation_id(request) -> str:
    return str(
        request.data.get('installation_id')
        or request.data.get('device_id')
        or request.META.get('HTTP_X_DEVICE_ID')
        or request.META.get('HTTP_X_INSTALLATION_ID')
        or ''
    ).strip()


def _serialize_event(evt: DeviceSecurityEvent) -> dict:
    return {
        'id': evt.id,
        'event_uuid': str(evt.event_uuid),
        'user_id': evt.user_id,
        'username': evt.user.username if evt.user else None,
        'device_id': evt.device_id,
        'installation_id': evt.installation_id,
        'event_type': evt.event_type,
        'severity': evt.severity,
        'risk_score': evt.risk_score,
        'ip_address': evt.ip_address,
        'country_code': evt.country_code,
        'region_name': evt.region_name,
        'action_taken': evt.action_taken,
        'investigation_status': evt.investigation_status,
        'investigation_notes': evt.investigation_notes,
        'details': evt.details,
        'created_at': evt.created_at.isoformat() if evt.created_at else None,
    }


def _serialize_session(sess: DeviceSession, current_inst_id: str = '') -> dict:
    return {
        'id': sess.id,
        'session_uuid': str(sess.session_uuid),
        'user_id': sess.user_id,
        'device_id': sess.device_id,
        'device_name': sess.device.device_name if sess.device else '',
        'installation_id': sess.installation_id,
        'is_current_device': bool(current_inst_id and sess.installation_id == current_inst_id),
        'status': sess.status,
        'ip_address': sess.ip_address,
        'country_code': sess.country_code,
        'region_name': sess.region_name,
        'isp_name': sess.isp_name,
        'is_vpn_or_proxy': sess.is_vpn_or_proxy,
        'started_at': sess.started_at.isoformat() if sess.started_at else None,
        'last_seen_at': sess.last_seen_at.isoformat() if sess.last_seen_at else None,
        'expires_at': sess.expires_at.isoformat() if sess.expires_at else None,
        'revoked_reason': sess.revoked_reason,
    }


def _serialize_policy(policy: SecurityPolicyConfig) -> dict:
    ai_cfg = get_effective_ai_config(policy)
    return {
        'student_device_limit': policy.student_device_limit,
        'teacher_device_limit': policy.teacher_device_limit,
        'assistant_device_limit': policy.assistant_device_limit,
        'max_concurrent_sessions': policy.max_concurrent_sessions,
        'max_concurrent_playback': policy.max_concurrent_playback,
        'risk_threshold_medium': policy.risk_threshold_medium,
        'risk_threshold_high': policy.risk_threshold_high,
        'risk_threshold_critical': policy.risk_threshold_critical,
        'rapid_login_threshold_5m': policy.rapid_login_threshold_5m,
        'rapid_geo_kmh_threshold': policy.rapid_geo_kmh_threshold,
        'event_retention_days': policy.event_retention_days,
        'enforce_device_limits': policy.enforce_device_limits,
        'enforce_screen_capture_policy': policy.enforce_screen_capture_policy,
        'auto_block_on_proxy_mitm': policy.auto_block_on_proxy_mitm,
        'auto_ban_on_account_sharing': policy.auto_ban_on_account_sharing,
        'auto_ban_on_tamper': policy.auto_ban_on_tamper,
        'auto_enforcement_mode': policy.auto_enforcement_mode,
        'enforce_request_signatures': policy.enforce_request_signatures,
        'request_signature_max_skew_seconds': policy.request_signature_max_skew_seconds,
        'ai_security_enabled': policy.ai_security_enabled,
        'ai_provider': ai_cfg['provider'],
        'ai_provider_setting': policy.ai_provider,
        'ai_model_name': policy.ai_model_name,
        'ai_api_key_configured': ai_cfg['configured'],
        'ai_api_key_masked': ai_cfg['masked_key'],
        'ai_hourly_schedule_enabled': policy.ai_hourly_schedule_enabled,
        'ai_auto_enforce_bans': policy.ai_auto_enforce_bans,
        'block_vpn_connections': policy.block_vpn_connections,
        'block_developer_options': policy.block_developer_options,
        'block_abnormal_dns_or_ports': policy.block_abnormal_dns_or_ports,
        'maintenance_approved_devices': policy.maintenance_approved_devices,
        'last_ai_audit_at': policy.last_ai_audit_at.isoformat() if policy.last_ai_audit_at else None,
        'last_ai_audit_summary': policy.last_ai_audit_summary or {},
        'updated_at': policy.updated_at.isoformat() if policy.updated_at else None,
    }
