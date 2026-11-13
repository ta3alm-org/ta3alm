from django.apps import AppConfig


class CoreConfig(AppConfig):
    name = 'core'
    verbose_name = 'الإعدادات الأساسية والمناهج'

    def ready(self):
        from .mo_compiler import ensure_mo_compiled
        ensure_mo_compiled()

