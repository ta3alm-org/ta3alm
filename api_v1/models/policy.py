"""api_v1.models.policy
Extracted from api_v1/models.py.
"""

from django.conf import settings
from django.db import models


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
    auto_block_on_proxy_mitm = models.BooleanField(default=True)
    auto_ban_on_account_sharing = models.BooleanField(default=False)
    auto_ban_on_tamper = models.BooleanField(default=True)
    auto_enforcement_mode = models.CharField(max_length=24, default='device_and_user')
    enforce_request_signatures = models.BooleanField(default=True)
    request_signature_max_skew_seconds = models.PositiveIntegerField(default=300)
    ai_security_enabled = models.BooleanField(default=True)
    ai_provider = models.CharField(max_length=24, default='auto')
    ai_model_name = models.CharField(max_length=64, default='gemini-2.5-flash')
    ai_api_key_override = models.CharField(max_length=255, blank=True, default='')
    ai_hourly_schedule_enabled = models.BooleanField(default=True)
    ai_auto_enforce_bans = models.BooleanField(default=True)
    last_ai_audit_at = models.DateTimeField(null=True, blank=True)
    last_ai_audit_summary = models.JSONField(default=dict, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Security Policy Config'
        verbose_name_plural = 'Security Policy Config'

    CACHE_KEY = 'ta3alm:singleton:security_policy_v1'

    def save(self, *args, **kwargs):
        from django.core.cache import cache
        self.pk = 1
        super().save(*args, **kwargs)
        cache.set(self.CACHE_KEY, self, timeout=60)

    @classmethod
    def load(cls) -> 'SecurityPolicyConfig':
        from django.core.cache import cache
        cached = cache.get(cls.CACHE_KEY)
        if cached is not None:
            return cached
        obj, _ = cls.objects.get_or_create(pk=1)
        cache.set(cls.CACHE_KEY, obj, timeout=60)
        return obj

    def _boot_guard_flags(self) -> dict:
        raw = self.last_ai_audit_summary if isinstance(self.last_ai_audit_summary, dict) else {}
        flags = raw.get('boot_guard_flags')
        return flags if isinstance(flags, dict) else {}

    @property
    def block_vpn_connections(self) -> bool:
        val = self._boot_guard_flags().get('block_vpn_connections')
        return True if val is None else bool(val)

    @property
    def block_developer_options(self) -> bool:
        val = self._boot_guard_flags().get('block_developer_options')
        return True if val is None else bool(val)

    @property
    def block_abnormal_dns_or_ports(self) -> bool:
        val = self._boot_guard_flags().get('block_abnormal_dns_or_ports')
        return True if val is None else bool(val)

    @property
    def maintenance_approved_devices(self) -> list[str]:
        raw_list = self._boot_guard_flags().get('maintenance_approved_devices')
        if not isinstance(raw_list, list):
            return []
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in raw_list:
            tok = str(item or '').strip()
            if tok and tok not in seen:
                seen.add(tok)
                cleaned.append(tok)
        return cleaned

    def is_device_maintenance_approved(self, *identifiers: str) -> bool:
        approved_set = {x.upper() for x in self.maintenance_approved_devices}
        if not approved_set:
            return False
        for ident in identifiers:
            tok = str(ident or '').strip().upper()
            if tok and tok in approved_set:
                return True
        return False

    def set_device_maintenance_approval(self, identifier: str, approved: bool = True) -> list[str]:
        tok = str(identifier or '').strip()
        if not tok:
            return self.maintenance_approved_devices
        raw = dict(self.last_ai_audit_summary) if isinstance(self.last_ai_audit_summary, dict) else {}
        flags = dict(raw.get('boot_guard_flags')) if isinstance(raw.get('boot_guard_flags'), dict) else {}
        current = self.maintenance_approved_devices
        tok_upper = tok.upper()
        if approved:
            if not any(x.upper() == tok_upper for x in current):
                current.append(tok_upper if tok_upper.startswith('DEV-') else tok)
        else:
            current = [x for x in current if x.upper() != tok_upper]
        flags['maintenance_approved_devices'] = current
        raw['boot_guard_flags'] = flags
        self.last_ai_audit_summary = raw
        return current

    def set_boot_guard_flags(
        self,
        *,
        block_vpn=None,
        block_dev_options=None,
        block_abnormal_net=None,
    ) -> None:
        raw = dict(self.last_ai_audit_summary) if isinstance(self.last_ai_audit_summary, dict) else {}
        flags = dict(raw.get('boot_guard_flags')) if isinstance(raw.get('boot_guard_flags'), dict) else {}
        if block_vpn is not None:
            flags['block_vpn_connections'] = bool(block_vpn)
        if block_dev_options is not None:
            flags['block_developer_options'] = bool(block_dev_options)
        if block_abnormal_net is not None:
            flags['block_abnormal_dns_or_ports'] = bool(block_abnormal_net)
        raw['boot_guard_flags'] = flags
        self.last_ai_audit_summary = raw

    def __str__(self):
        return (
            f"SecurityPolicy(student_limit={self.student_device_limit}, "
            f"thresholds={self.risk_threshold_medium}/{self.risk_threshold_high}/{self.risk_threshold_critical})"
        )


class UserSecurityProfile(models.Model):
    """ملف التحليل السلوكي والمخاطر التراكمية للمستخدم وإجراءات الحظر الانتقائي أو المشترك."""
    ENFORCEMENT_MODES = (
        ('none', 'None'),
        ('warn', 'Warning'),
        ('device_only', 'Device Only'),
        ('user_only', 'Account Only'),
        ('device_and_user', 'Account & Device'),
    )

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='security_profile',
    )
    behavior_risk_score = models.PositiveIntegerField(default=0, db_index=True)
    behavior_risk_level = models.CharField(max_length=16, default='low', db_index=True)
    total_actions_count = models.PositiveIntegerField(default=0)
    total_failed_logins = models.PositiveIntegerField(default=0)
    proxy_tamper_strikes = models.PositiveIntegerField(default=0)
    sharing_strikes = models.PositiveIntegerField(default=0)
    last_action_type = models.CharField(max_length=64, blank=True)
    last_action_endpoint = models.CharField(max_length=255, blank=True)
    last_action_at = models.DateTimeField(null=True, blank=True)
    last_ip = models.GenericIPAddressField(null=True, blank=True)
    last_country = models.CharField(max_length=16, blank=True)
    last_signals = models.JSONField(default=dict, blank=True)
    auto_ban_mode = models.CharField(max_length=24, choices=ENFORCEMENT_MODES, default='none')
    ban_reason = models.CharField(max_length=255, blank=True)
    ai_risk_score = models.PositiveIntegerField(default=0)
    ai_recommended_action = models.CharField(max_length=24, default='none')
    ai_analysis_summary = models.TextField(blank=True, default='')
    ai_last_analyzed_at = models.DateTimeField(null=True, blank=True)
    analyzed_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-behavior_risk_score', '-analyzed_at']
        indexes = [
            models.Index(fields=['behavior_risk_level', '-behavior_risk_score'], name='usec_level_score_idx'),
        ]

    def __str__(self):
        return f"UserSecurityProfile(user={self.user_id}, score={self.behavior_risk_score}, level={self.behavior_risk_level})"
