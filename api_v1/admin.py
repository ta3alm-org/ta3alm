from django.contrib import admin
from .models import (
    DeviceIntegrityRecord,
    PlaybackSession,
    PlayIntegrityNonce,
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

