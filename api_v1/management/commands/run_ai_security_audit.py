import time
from django.core.management.base import BaseCommand
from api_v1.security_engine import run_hourly_ai_behavioral_audit


class Command(BaseCommand):
    help = 'تشغيل تحليل الذكاء الاصطناعي الأمني لسلوك جميع المستخدمين النشطين اليوم (يدعم العمل كخدمة دورية كل ساعة).'

    def add_arguments(self, parser):
        parser.add_argument(
            '--loop',
            action='store_true',
            help='الاستمرار في التشغيل التلقائي المتكرر كل ساعة.',
        )
        parser.add_argument(
            '--interval',
            type=int,
            default=3600,
            help='الفاصل الزمني بالثواني عند استخدام --loop (الافتراضي 3600 ثانية = ساعة).',
        )

    def handle(self, *args, **options):
        loop = bool(options.get('loop'))
        interval = max(int(options.get('interval') or 3600), 60)

        while True:
            self.stdout.write(self.style.NOTICE('بدء دورة تحليل الذكاء الاصطناعي لسلوك المستخدمين النشطين اليوم...'))
            summary = run_hourly_ai_behavioral_audit(force=True)
            self.stdout.write(
                self.style.SUCCESS(
                    f"تم تحليل {summary.get('analyzed_users', 0)} مستخدم | "
                    f"عالي الخطورة: {summary.get('flagged_high_risk', 0)} | "
                    f"حظر آلي (حسابات: {summary.get('banned_users', 0)}, أجهزة: {summary.get('banned_devices', 0)}) | "
                    f"AI Key مفعّل: {summary.get('ai_key_configured', False)}"
                )
            )
            if not loop:
                break
            time.sleep(interval)
