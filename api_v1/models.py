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
    view_window_expires_at = models.DateTimeField(null=True, blank=True)
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


class DeviceTrustStatus(models.TextChoices):
    TRUSTED = 'trusted', 'Trusted'
    PENDING = 'pending', 'Pending Verification'
    SUSPICIOUS = 'suspicious', 'Suspicious'
    RESTRICTED = 'restricted', 'Temporarily Restricted'
    REVOKED = 'revoked', 'Revoked'
    BLOCKED = 'blocked', 'Blocked'


class SecurityPolicyConfig(models.Model):
    """إعدادات حدود الأجهزة وسياسات المخاطر وحماية الشاشة والاحتفاظ بالسجلات (Singleton pk=1)."""
    student_device_limit = models.PositiveIntegerField(default=2)
    teacher_device_limit = models.PositiveIntegerField(default=5)
    assistant_device_limit = models.PositiveIntegerField(default=3)
    max_concurrent_sessions = models.PositiveIntegerField(default=2)
    max_concurrent_playback = models.PositiveIntegerField(default=1)

    risk_threshold_medium = models.PositiveIntegerField(default=30)
    risk_threshold_high = models.PositiveIntegerField(default=60)
    risk_threshold_critical = models.PositiveIntegerField(default=85)

    rapid_login_threshold_5m = models.PositiveIntegerField(default=8)
    rapid_geo_kmh_threshold = models.PositiveIntegerField(default=800)
    event_retention_days = models.PositiveIntegerField(default=90)

    enforce_device_limits = models.BooleanField(default=True)
    enforce_screen_capture_policy = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Security Policy Config'
        verbose_name_plural = 'Security Policy Config'

    def save(self, *args, **kwargs):
        self.pk = 1
        super().save(*args, **kwargs)

    @classmethod
    def load(cls) -> 'SecurityPolicyConfig':
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj

    def __str__(self):
        return (
            f"SecurityPolicy(student_limit={self.student_device_limit}, "
            f"thresholds={self.risk_threshold_medium}/{self.risk_threshold_high}/{self.risk_threshold_critical})"
        )


class RegisteredDevice(models.Model):
    """الأجهزة المسجّلة والموثوقة لكل مستخدم عبر هوية التثبيت وبصمة الجهاز المتعددة الطبقات."""
    device_uuid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='registered_devices',
    )
    installation_id = models.CharField(max_length=128, db_index=True)

    device_name = models.CharField(max_length=150, blank=True)
    manufacturer = models.CharField(max_length=100, blank=True)
    model = models.CharField(max_length=100, blank=True)
    os_name = models.CharField(max_length=32, default='Android')
    android_version = models.CharField(max_length=32, blank=True)
    api_level = models.PositiveIntegerField(default=0)
    cpu_arch = models.CharField(max_length=64, blank=True)
    cpu_info = models.CharField(max_length=255, blank=True)
    gpu_renderer = models.CharField(max_length=255, blank=True)
    gpu_vendor = models.CharField(max_length=255, blank=True)
    screen_resolution = models.CharField(max_length=64, blank=True)

    app_version = models.CharField(max_length=32, blank=True)
    app_build_number = models.CharField(max_length=32, blank=True)
    package_name = models.CharField(max_length=128, blank=True)
    signing_cert_sha256 = models.CharField(max_length=128, blank=True)
    signing_cert_verified = models.BooleanField(default=True)
    installer_source = models.CharField(max_length=128, blank=True)

    current_fingerprint = models.CharField(max_length=128, blank=True, db_index=True)
    fingerprint_version = models.CharField(max_length=16, default='fp_v1')

    trust_status = models.CharField(
        max_length=20,
        choices=DeviceTrustStatus.choices,
        default=DeviceTrustStatus.TRUSTED,
        db_index=True,
    )
    is_active = models.BooleanField(default=True, db_index=True)
    is_verified = models.BooleanField(default=True)
    requires_reauth = models.BooleanField(default=False)
    risk_score = models.PositiveIntegerField(default=0, db_index=True)
    risk_level = models.CharField(max_length=16, default='low')

    last_ip = models.GenericIPAddressField(null=True, blank=True)
    last_country = models.CharField(max_length=64, blank=True)
    last_region = models.CharField(max_length=128, blank=True)
    last_isp = models.CharField(max_length=128, blank=True)
    ip_history = models.JSONField(default=list, blank=True)
    integrity_signals = models.JSONField(default=dict, blank=True)
    unfamiliar_reported = models.BooleanField(default=False)

    first_registered_at = models.DateTimeField(auto_now_add=True, db_index=True)
    last_active_at = models.DateTimeField(default=timezone.now, db_index=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_reason = models.CharField(max_length=255, blank=True)

    class Meta:
        unique_together = ('user', 'installation_id')
        ordering = ['-last_active_at']
        indexes = [
            models.Index(fields=['user', 'is_active', 'trust_status'], name='regdev_user_active_trust_idx'),
            models.Index(fields=['installation_id', 'is_active'], name='regdev_inst_active_idx'),
            models.Index(fields=['risk_score', '-last_active_at'], name='regdev_risk_active_idx'),
        ]

    def __str__(self):
        return f"RegisteredDevice(id={self.id}, user={self.user_id}, {self.manufacturer} {self.model}, {self.trust_status})"


class DeviceFingerprint(models.Model):
    """سجل إصدارات البصمات المشفّرة للجهاز وتتبع التغيّرات (Fingerprint Drift History)."""
    device = models.ForeignKey(
        RegisteredDevice,
        on_delete=models.CASCADE,
        related_name='fingerprints',
    )
    fingerprint_hash = models.CharField(max_length=128, db_index=True)
    algorithm_version = models.CharField(max_length=16, default='fp_v1')
    core_hash = models.CharField(max_length=128, blank=True)
    supporting_hash = models.CharField(max_length=128, blank=True)
    normalized_traits = models.JSONField(default=dict, blank=True)
    drift_score = models.PositiveIntegerField(default=0)
    changed_fields = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['device', '-created_at'], name='devfp_device_time_idx'),
        ]

    def __str__(self):
        return f"DeviceFingerprint(device={self.device_id}, {self.algorithm_version}, drift={self.drift_score})"


class DeviceSession(models.Model):
    """جلسات المصادقة المرتبطة بالأجهزة وعنوان الشبكة المرصود من الخادم."""
    STATUS_CHOICES = (
        ('active', 'Active'),
        ('logged_out', 'Logged Out'),
        ('revoked', 'Revoked'),
        ('expired', 'Expired'),
    )

    session_uuid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='device_sessions',
    )
    device = models.ForeignKey(
        RegisteredDevice,
        on_delete=models.CASCADE,
        related_name='sessions',
        null=True,
        blank=True,
    )
    installation_id = models.CharField(max_length=128, db_index=True)
    token_jti = models.CharField(max_length=64, blank=True, db_index=True)
    refresh_jti = models.CharField(max_length=64, blank=True, db_index=True)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default='active', db_index=True)

    ip_address = models.GenericIPAddressField(null=True, blank=True)
    country_code = models.CharField(max_length=16, blank=True)
    region_name = models.CharField(max_length=128, blank=True)
    isp_name = models.CharField(max_length=128, blank=True)
    is_vpn_or_proxy = models.BooleanField(default=False)
    user_agent = models.CharField(max_length=255, blank=True)

    started_at = models.DateTimeField(auto_now_add=True, db_index=True)
    last_seen_at = models.DateTimeField(default=timezone.now, db_index=True)
    expires_at = models.DateTimeField(db_index=True)
    ended_at = models.DateTimeField(null=True, blank=True)
    revoked_reason = models.CharField(max_length=160, blank=True)

    class Meta:
        ordering = ['-last_seen_at']
        indexes = [
            models.Index(fields=['user', 'status', '-last_seen_at'], name='devsess_user_status_idx'),
            models.Index(fields=['device', 'status'], name='devsess_dev_status_idx'),
            models.Index(fields=['token_jti'], name='devsess_token_jti_idx'),
        ]

    def __str__(self):
        return f"DeviceSession({self.session_uuid}, user={self.user_id}, {self.status})"


class DeviceActivity(models.Model):
    """سجل الأنشطة التاريخية للأجهزة ومحاولات الدخول والشبكة (مع سياسة احتفاظ زمنية)."""
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='device_activities',
        null=True,
        blank=True,
    )
    device = models.ForeignKey(
        RegisteredDevice,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='activities',
    )
    session = models.ForeignKey(
        DeviceSession,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='activities',
    )
    activity_type = models.CharField(max_length=64, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    country_code = models.CharField(max_length=16, blank=True)
    region_name = models.CharField(max_length=128, blank=True)
    isp_name = models.CharField(max_length=128, blank=True)
    is_vpn_or_proxy = models.BooleanField(default=False)
    endpoint = models.CharField(max_length=255, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'activity_type', '-created_at'], name='devact_user_type_time_idx'),
            models.Index(fields=['ip_address', '-created_at'], name='devact_ip_time_idx'),
        ]

    def __str__(self):
        return f"DeviceActivity({self.activity_type}, user={self.user_id}, ip={self.ip_address})"


class DeviceSecurityEvent(models.Model):
    """أحداث الأمان والتهديدات وتقييم المخاطر وتقارير التقاط الشاشة والتلاعب."""
    SEVERITY_CHOICES = (
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    )
    INVESTIGATION_CHOICES = (
        ('open', 'Open'),
        ('investigating', 'Investigating'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive'),
    )

    event_uuid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='device_security_events',
    )
    device = models.ForeignKey(
        RegisteredDevice,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='security_events',
    )
    installation_id = models.CharField(max_length=128, blank=True, db_index=True)
    event_type = models.CharField(max_length=64, db_index=True)
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default='low', db_index=True)
    risk_score = models.PositiveIntegerField(default=0, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    country_code = models.CharField(max_length=16, blank=True)
    region_name = models.CharField(max_length=128, blank=True)
    action_taken = models.CharField(max_length=64, default='logged')
    investigation_status = models.CharField(
        max_length=20,
        choices=INVESTIGATION_CHOICES,
        default='open',
        db_index=True,
    )
    investigation_notes = models.TextField(blank=True)
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='reviewed_security_events',
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    details = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['severity', '-created_at'], name='devsec_sev_time_idx'),
            models.Index(fields=['investigation_status', '-created_at'], name='devsec_inv_time_idx'),
            models.Index(fields=['user', '-created_at'], name='devsec_user_time_idx'),
        ]

    def __str__(self):
        return f"DeviceSecurityEvent({self.event_type}, {self.severity}, risk={self.risk_score})"


class DeviceBlock(models.Model):
    """سجل حظر الأجهزة المؤقت والدائم على مستوى الخادم."""
    BLOCK_TYPES = (
        ('temporary', 'Temporary'),
        ('permanent', 'Permanent'),
    )

    device = models.ForeignKey(
        RegisteredDevice,
        on_delete=models.CASCADE,
        related_name='blocks',
        null=True,
        blank=True,
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='device_blocks',
    )
    installation_id = models.CharField(max_length=128, db_index=True)
    fingerprint_hash = models.CharField(max_length=128, blank=True, db_index=True)
    block_type = models.CharField(max_length=16, choices=BLOCK_TYPES, default='temporary')
    reason = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True, db_index=True)
    blocked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='issued_device_blocks',
    )
    expires_at = models.DateTimeField(null=True, blank=True, db_index=True)
    unblocked_at = models.DateTimeField(null=True, blank=True)
    unblocked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='lifted_device_blocks',
    )
    unblock_reason = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['installation_id', 'is_active'], name='devblock_inst_active_idx'),
        ]

    def __str__(self):
        return f"DeviceBlock({self.installation_id}, {self.block_type}, active={self.is_active})"


