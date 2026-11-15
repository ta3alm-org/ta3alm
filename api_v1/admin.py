from django.contrib import admin
from .models import (
    DeviceActivity,
    DeviceBlock,
    DeviceFingerprint,
    DeviceIntegrityRecord,
    DeviceSecurityEvent,
    DeviceSession,
    PlaybackSession,
    PlayIntegrityNonce,
    RegisteredDevice,
    SecurityPolicyConfig,
    VideoAsset,
    VideoBookmark,
    VideoProgress,
    VideoSecurityAuditLog,
)


@admin.register(VideoAsset)
class VideoAssetAdmin(admin.ModelAdmin):
    list_display = ('lecture', 'source_type', 'provider', 'migration_status', 'drm_enabled', 'duration_seconds', 'updated_at')
    list_filter = ('source_type', 'provider', 'migration_status', 'drm_enabled')
    search_fields = ('lecture__title', 'provider_asset_id', 'legacy_youtube_id')


@admin.register(PlaybackSession)
class PlaybackSessionAdmin(admin.ModelAdmin):
    list_display = ('session_id', 'user', 'lecture', 'device_id', 'client_platform', 'status', 'integrity_verdict', 'last_heartbeat_at')
    list_filter = ('status', 'client_platform', 'integrity_verdict')
    search_fields = ('session_id', 'user__username', 'device_id')


@admin.register(VideoProgress)
class VideoProgressAdmin(admin.ModelAdmin):
    list_display = ('user', 'lecture', 'position_seconds', 'progress_percent', 'is_completed', 'preferred_speed', 'last_watched_at')
    list_filter = ('is_completed',)


@admin.register(VideoBookmark)
class VideoBookmarkAdmin(admin.ModelAdmin):
    list_display = ('user', 'lecture', 'timestamp_seconds', 'title', 'created_at')


@admin.register(PlayIntegrityNonce)
class PlayIntegrityNonceAdmin(admin.ModelAdmin):
    list_display = ('nonce_id', 'user', 'action', 'is_used', 'expires_at', 'created_at')
    list_filter = ('action', 'is_used')


@admin.register(DeviceIntegrityRecord)
class DeviceIntegrityRecordAdmin(admin.ModelAdmin):
    list_display = ('device_id', 'user', 'app_recognition_verdict', 'risk_level', 'policy_decision', 'verified_at')
    list_filter = ('risk_level', 'policy_decision', 'app_recognition_verdict')
    search_fields = ('device_id', 'user__username', 'package_name')


@admin.register(VideoSecurityAuditLog)
class VideoSecurityAuditLogAdmin(admin.ModelAdmin):
    list_display = ('created_at', 'event_type', 'severity', 'user', 'lecture', 'device_id', 'ip_address')
    list_filter = ('event_type', 'severity')
    search_fields = ('session_id', 'device_id', 'user__username')


@admin.register(SecurityPolicyConfig)
class SecurityPolicyConfigAdmin(admin.ModelAdmin):
    list_display = ('student_device_limit', 'teacher_device_limit', 'assistant_device_limit', 'max_concurrent_sessions', 'max_concurrent_playback', 'event_retention_days', 'updated_at')


@admin.register(RegisteredDevice)
class RegisteredDeviceAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'device_name', 'manufacturer', 'model', 'trust_status', 'risk_score', 'risk_level', 'is_active', 'last_active_at')
    list_filter = ('trust_status', 'risk_level', 'is_active', 'signing_cert_verified')
    search_fields = ('installation_id', 'user__email', 'user__username', 'manufacturer', 'model', 'last_ip')


@admin.register(DeviceFingerprint)
class DeviceFingerprintAdmin(admin.ModelAdmin):
    list_display = ('device', 'algorithm_version', 'drift_score', 'fingerprint_hash', 'created_at')
    list_filter = ('algorithm_version',)
    search_fields = ('fingerprint_hash', 'device__installation_id')


@admin.register(DeviceSession)
class DeviceSessionAdmin(admin.ModelAdmin):
    list_display = ('session_uuid', 'user', 'device', 'status', 'ip_address', 'country_code', 'is_vpn_or_proxy', 'last_seen_at')
    list_filter = ('status', 'is_vpn_or_proxy', 'country_code')
    search_fields = ('installation_id', 'user__email', 'ip_address', 'token_jti')


@admin.register(DeviceActivity)
class DeviceActivityAdmin(admin.ModelAdmin):
    list_display = ('activity_type', 'user', 'device', 'ip_address', 'country_code', 'is_vpn_or_proxy', 'created_at')
    list_filter = ('activity_type', 'is_vpn_or_proxy', 'country_code')
    search_fields = ('user__email', 'ip_address', 'endpoint')


@admin.register(DeviceSecurityEvent)
class DeviceSecurityEventAdmin(admin.ModelAdmin):
    list_display = ('event_type', 'severity', 'risk_score', 'user', 'device', 'action_taken', 'investigation_status', 'created_at')
    list_filter = ('severity', 'investigation_status', 'action_taken', 'event_type')
    search_fields = ('installation_id', 'user__email', 'ip_address')


@admin.register(DeviceBlock)
class DeviceBlockAdmin(admin.ModelAdmin):
    list_display = ('installation_id', 'block_type', 'is_active', 'user', 'reason', 'expires_at', 'created_at')
    list_filter = ('block_type', 'is_active')
    search_fields = ('installation_id', 'reason', 'user__email')


