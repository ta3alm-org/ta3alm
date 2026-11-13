"""
Management command to inventory legacy YouTube lectures vs migrated native VideoAssets.
Usage: python manage.py audit_video_migration [--create-placeholders]
"""
from django.core.management.base import BaseCommand
from teachers.models import Lecture
from api_v1.models import VideoAsset


class Command(BaseCommand):
    help = 'يستعرض حالة ترحيل المحاضرات من روابط YouTube القديمة إلى أصول البث المحمي (VideoAsset).'

    def add_arguments(self, parser):
        parser.add_argument(
            '--create-placeholders',
            action='store_true',
            help='إنشاء سجلات VideoAsset بحالة legacy_youtube للمحاضرات غير المسجلة.',
        )

    def handle(self, *args, **options):
        create_placeholders = options['create_placeholders']
        total = 0
        migrated = 0
        legacy_yt = 0
        untracked = 0
        created_count = 0

        for lec in Lecture.objects.select_related('group').all():
            total += 1
            asset = getattr(lec, 'video_asset', None)
            yt_id = lec.get_video_id()
            if asset and asset.is_native_protected:
                migrated += 1
            elif asset:
                legacy_yt += 1
            else:
                untracked += 1
                if create_placeholders:
                    VideoAsset.objects.create(
                        lecture=lec,
                        source_type='youtube_legacy',
                        provider='youtube' if yt_id else 'internal',
                        migration_status='legacy_youtube',
                        legacy_youtube_id=yt_id or '',
                    )
                    created_count += 1

        self.stdout.write(self.style.SUCCESS(
            f'Total lectures: {total} | Protected native: {migrated} | Tracked legacy: {legacy_yt} | Untracked: {untracked} | Placeholders created: {created_count}'
        ))

