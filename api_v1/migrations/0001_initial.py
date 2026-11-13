from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('teachers', '__latest__'),
    ]

    operations = [
        migrations.CreateModel(
            name='VideoAsset',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('source_type', models.CharField(choices=[('youtube_legacy', 'YouTube Legacy'), ('hls_protected', 'Protected HLS (.m3u8)'), ('dash_protected', 'Protected DASH (.mpd)'), ('mp4_private', 'Private Signed MP4'), ('cloudflare_stream', 'Cloudflare Stream'), ('bunny_stream', 'Bunny Stream'), ('s3_cloudfront', 'AWS S3 + CloudFront')], default='youtube_legacy', max_length=32)),
                ('provider', models.CharField(choices=[('internal', 'Internal Private Origin'), ('cloudflare_stream', 'Cloudflare Stream'), ('bunny_stream', 'Bunny Stream'), ('aws_cloudfront', 'AWS CloudFront'), ('youtube', 'YouTube')], default='youtube', max_length=32)),
                ('provider_asset_id', models.CharField(blank=True, max_length=255)),
                ('manifest_url', models.URLField(blank=True, max_length=1000)),
                ('quality_variants', models.JSONField(blank=True, default=list)),
                ('subtitle_tracks', models.JSONField(blank=True, default=list)),
                ('drm_enabled', models.BooleanField(default=False)),
                ('drm_scheme', models.CharField(choices=[('none', 'None'), ('widevine', 'Widevine'), ('fairplay', 'FairPlay')], default='none', max_length=20)),
                ('drm_license_url', models.URLField(blank=True, max_length=1000)),
                ('duration_seconds', models.PositiveIntegerField(default=0)),
                ('intro_start_seconds', models.PositiveIntegerField(default=0)),
                ('intro_end_seconds', models.PositiveIntegerField(default=0)),
                ('migration_status', models.CharField(choices=[('legacy_youtube', 'Legacy YouTube (Needs Migration)'), ('queued', 'Queued for Migration'), ('transcoding', 'Transcoding'), ('migrated', 'Migrated'), ('verified', 'Verified in Native Player')], default='legacy_youtube', max_length=32)),
                ('legacy_youtube_id', models.CharField(blank=True, max_length=32)),
                ('migrated_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('lecture', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='video_asset', to='teachers.lecture')),
            ],
            options={'ordering': ['-updated_at']},
        ),
        migrations.CreateModel(
            name='PlayIntegrityNonce',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('nonce_id', models.UUIDField(default=uuid.uuid4, editable=False, unique=True)),
                ('action', models.CharField(default='app_startup', max_length=64)),
                ('binding_data', models.CharField(blank=True, max_length=255)),
                ('expected_request_hash', models.CharField(blank=True, max_length=128)),
                ('is_used', models.BooleanField(default=False)),
                ('expires_at', models.DateTimeField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='integrity_nonces', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='DeviceIntegrityRecord',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('device_id', models.CharField(db_index=True, max_length=128)),
                ('package_name', models.CharField(blank=True, max_length=128)),
                ('app_recognition_verdict', models.CharField(blank=True, max_length=64)),
                ('device_recognition_verdict', models.JSONField(blank=True, default=list)),
                ('licensing_verdict', models.CharField(blank=True, max_length=64)),
                ('risk_level', models.CharField(default='low', max_length=16)),
                ('policy_decision', models.CharField(default='allow', max_length=32)),
                ('tamper_signals', models.JSONField(blank=True, default=dict)),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('verified_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='integrity_records', to=settings.AUTH_USER_MODEL)),
            ],
            options={'ordering': ['-verified_at']},
        ),
        migrations.CreateModel(
            name='VideoSecurityAuditLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('session_id', models.CharField(blank=True, max_length=64)),
                ('event_type', models.CharField(db_index=True, max_length=64)),
                ('severity', models.CharField(default='info', max_length=16)),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('device_id', models.CharField(blank=True, max_length=128)),
                ('details', models.JSONField(blank=True, default=dict)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('lecture', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='security_logs', to='teachers.lecture')),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='video_security_logs', to=settings.AUTH_USER_MODEL)),
            ],
            options={'ordering': ['-created_at']},
        ),
        migrations.CreateModel(
            name='VideoBookmark',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp_seconds', models.PositiveIntegerField()),
                ('title', models.CharField(max_length=120)),
                ('note', models.TextField(blank=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('lecture', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='bookmarks', to='teachers.lecture')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='video_bookmarks', to=settings.AUTH_USER_MODEL)),
            ],
            options={'ordering': ['timestamp_seconds', 'id']},
        ),
        migrations.CreateModel(
            name='PlaybackSession',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('session_id', models.UUIDField(default=uuid.uuid4, editable=False, unique=True)),
                ('device_id', models.CharField(max_length=128)),
                ('device_fingerprint', models.CharField(blank=True, max_length=128)),
                ('client_platform', models.CharField(default='android', max_length=24)),
                ('app_version', models.CharField(blank=True, max_length=32)),
                ('integrity_verdict', models.CharField(default='unverified', max_length=32)),
                ('token_jti', models.CharField(max_length=64, unique=True)),
                ('status', models.CharField(choices=[('active', 'Active'), ('ended', 'Ended'), ('revoked', 'Revoked'), ('expired', 'Expired')], default='active', max_length=16)),
                ('revoked_reason', models.CharField(blank=True, max_length=120)),
                ('last_heartbeat_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('expires_at', models.DateTimeField()),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('user_agent', models.CharField(blank=True, max_length=255)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('course_package', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='playback_sessions', to='teachers.coursepackage')),
                ('lecture', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='playback_sessions', to='teachers.lecture')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='playback_sessions', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'indexes': [
                    models.Index(fields=['user', 'status'], name='pb_user_status_idx'),
                    models.Index(fields=['lecture', 'status'], name='pb_lec_status_idx'),
                ],
            },
        ),
        migrations.CreateModel(
            name='VideoProgress',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('position_seconds', models.PositiveIntegerField(default=0)),
                ('duration_seconds', models.PositiveIntegerField(default=0)),
                ('watched_seconds', models.PositiveIntegerField(default=0)),
                ('progress_percent', models.FloatField(default=0.0)),
                ('is_completed', models.BooleanField(default=False)),
                ('preferred_speed', models.FloatField(default=1.0)),
                ('last_watched_at', models.DateTimeField(auto_now=True)),
                ('lecture', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='student_progress', to='teachers.lecture')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='video_progress', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-last_watched_at'],
                'unique_together': {('user', 'lecture')},
            },
        ),
    ]

