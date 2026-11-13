"""
api_v1/models.py
نماذج أمان الفيديو، تتبع التقدم، العلامات المرجعية، جلسات المشاهدة، والتحقق من سلامة التطبيق (Play Integrity).
"""
import uuid
from django.conf import settings
from django.db import models
from django.utils import timezone


class VideoAsset(models.Model):
    SOURCE_TYPES = (
        ('youtube_legacy', 'YouTube Legacy'),
        ('hls_protected', 'Protected HLS (.m3u8)'),
        ('dash_protected', 'Protected DASH (.mpd)'),
        ('mp4_private', 'Private Signed MP4'),
        ('cloudflare_stream', 'Cloudflare Stream'),
        ('bunny_stream', 'Bunny Stream'),
        ('s3_cloudfront', 'AWS S3 + CloudFront'),
    )
    PROVIDERS = (
        ('internal', 'Internal Private Origin'),
        ('cloudflare_stream', 'Cloudflare Stream'),
        ('bunny_stream', 'Bunny Stream'),
        ('aws_cloudfront', 'AWS CloudFront'),
        ('youtube', 'YouTube'),
    )
    DRM_SCHEMES = (
        ('none', 'None'),
        ('widevine', 'Widevine'),
        ('fairplay', 'FairPlay'),
    )
    MIGRATION_STATUSES = (
        ('legacy_youtube', 'Legacy YouTube (Needs Migration)'),
        ('queued', 'Queued for Migration'),
        ('transcoding', 'Transcoding'),
        ('migrated', 'Migrated'),
        ('verified', 'Verified in Native Player'),
    )

    lecture = models.OneToOneField(
        'teachers.Lecture',
        on_delete=models.CASCADE,
        related_name='video_asset',
    )
    source_type = models.CharField(
        max_length=32,
        choices=SOURCE_TYPES,
        default='youtube_legacy',
    )
    provider = models.CharField(
        max_length=32,
        choices=PROVIDERS,
        default='youtube',
    )
    provider_asset_id = models.CharField(max_length=255, blank=True)
    manifest_url = models.URLField(max_length=1000, blank=True)
    quality_variants = models.JSONField(default=list, blank=True)
    subtitle_tracks = models.JSONField(default=list, blank=True)

    drm_enabled = models.BooleanField(default=False)
    drm_scheme = models.CharField(max_length=20, choices=DRM_SCHEMES, default='none')
    drm_license_url = models.URLField(max_length=1000, blank=True)

    duration_seconds = models.PositiveIntegerField(default=0)
    intro_start_seconds = models.PositiveIntegerField(default=0)
    intro_end_seconds = models.PositiveIntegerField(default=0)

    migration_status = models.CharField(
        max_length=32,
        choices=MIGRATION_STATUSES,
        default='legacy_youtube',
    )
    legacy_youtube_id = models.CharField(max_length=32, blank=True)
    migrated_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-updated_at']

    def __str__(self):
        return f"VideoAsset(lecture={self.lecture_id}, type={self.source_type})"

    @property
    def is_native_protected(self) -> bool:
        return self.source_type != 'youtube_legacy' and bool(
            self.manifest_url or self.provider_asset_id
        )


class PlaybackSession(models.Model):
    STATUS_CHOICES = (
        ('active', 'Active'),
        ('ended', 'Ended'),
        ('revoked', 'Revoked'),
        ('expired', 'Expired'),
    )

    session_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='playback_sessions',
    )
    lecture = models.ForeignKey(
        'teachers.Lecture',
        on_delete=models.CASCADE,
        related_name='playback_sessions',
    )
    course_package = models.ForeignKey(
        'teachers.CoursePackage',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='playback_sessions',
    )
    device_id = models.CharField(max_length=128)
    device_fingerprint = models.CharField(max_length=128, blank=True)
    client_platform = models.CharField(max_length=24, default='android')
    app_version = models.CharField(max_length=32, blank=True)
    integrity_verdict = models.CharField(max_length=32, default='unverified')
    token_jti = models.CharField(max_length=64, unique=True)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default='active')
    revoked_reason = models.CharField(max_length=120, blank=True)
    last_heartbeat_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['user', 'status'], name='pb_user_status_idx'),
            models.Index(fields=['lecture', 'status'], name='pb_lec_status_idx'),
        ]

    def __str__(self):
        return f"PlaybackSession({self.session_id}, user={self.user_id}, {self.status})"


class VideoProgress(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='video_progress',
    )
    lecture = models.ForeignKey(
        'teachers.Lecture',
        on_delete=models.CASCADE,
        related_name='student_progress',
    )
    position_seconds = models.PositiveIntegerField(default=0)
    duration_seconds = models.PositiveIntegerField(default=0)
    watched_seconds = models.PositiveIntegerField(default=0)
    progress_percent = models.FloatField(default=0.0)
    is_completed = models.BooleanField(default=False)
    preferred_speed = models.FloatField(default=1.0)
    last_watched_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('user', 'lecture')
        ordering = ['-last_watched_at']

    def __str__(self):
        return f"VideoProgress(user={self.user_id}, lecture={self.lecture_id}, {self.progress_percent:.0f}%)"


class VideoBookmark(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='video_bookmarks',
    )
    lecture = models.ForeignKey(
        'teachers.Lecture',
        on_delete=models.CASCADE,
        related_name='bookmarks',
    )
    timestamp_seconds = models.PositiveIntegerField()
    title = models.CharField(max_length=120)
    note = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['timestamp_seconds', 'id']

    def __str__(self):
        return f"Bookmark({self.lecture_id} @ {self.timestamp_seconds}s: {self.title})"


class PlayIntegrityNonce(models.Model):
    nonce_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='integrity_nonces',
    )
    action = models.CharField(max_length=64, default='app_startup')
    binding_data = models.CharField(max_length=255, blank=True)
    expected_request_hash = models.CharField(max_length=128, blank=True)
    is_used = models.BooleanField(default=False)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"PlayIntegrityNonce({self.nonce_id}, action={self.action}, used={self.is_used})"


class DeviceIntegrityRecord(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='integrity_records',
    )
    device_id = models.CharField(max_length=128, db_index=True)
    package_name = models.CharField(max_length=128, blank=True)
    app_recognition_verdict = models.CharField(max_length=64, blank=True)
    device_recognition_verdict = models.JSONField(default=list, blank=True)
    licensing_verdict = models.CharField(max_length=64, blank=True)
    risk_level = models.CharField(max_length=16, default='low')
    policy_decision = models.CharField(max_length=32, default='allow')
    tamper_signals = models.JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    verified_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-verified_at']

    def __str__(self):
        return f"DeviceIntegrity({self.device_id}, {self.risk_level}, {self.policy_decision})"


class VideoSecurityAuditLog(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='video_security_logs',
    )
    lecture = models.ForeignKey(
        'teachers.Lecture',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='security_logs',
    )
    session_id = models.CharField(max_length=64, blank=True)
    event_type = models.CharField(max_length=64, db_index=True)
    severity = models.CharField(max_length=16, default='info')
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    device_id = models.CharField(max_length=128, blank=True)
    details = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"AuditLog({self.event_type}, severity={self.severity}, user={self.user_id})"

