"""
URL configuration for ta3alm_project project.
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.conf.urls.i18n import i18n_patterns
from django.contrib.sitemaps.views import sitemap
from django.views.generic.base import TemplateView
from accounts import views as account_views
from core.sitemaps import StaticViewSitemap, TeacherSitemap, PackageSitemap

# ==========================================================
# Sitemaps
# ==========================================================
sitemaps = {
    'static':   StaticViewSitemap,
    'teachers': TeacherSitemap,
    'packages': PackageSitemap,
}

# ==========================================================
# الروابط العامة (بدون i18n prefix)
# ==========================================================
urlpatterns = [
    path(
        'sitemap.xml',
        sitemap,
        {'sitemaps': sitemaps},
        name='django.contrib.sitemaps.views.sitemap',
    ),
    path(
        'robots.txt',
        TemplateView.as_view(template_name='robots.txt', content_type='text/plain'),
    ),
    path('i18n/', include('django.conf.urls.i18n')),

    # API endpoints (بدون i18n)
    path('api/v1/',  include('api_v1.urls')),
    path('api/auth/', include('accounts.api_urls')),
    path('api/bot/', include('bot_api.urls')),
]

# ملفات الوسائط في بيئة التطوير فقط
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.BASE_DIR / 'media')

# ==========================================================
# الروابط مع دعم اللغات (i18n)
# ==========================================================
urlpatterns += i18n_patterns(
    path('admin/',          admin.site.urls),
    path('accounts/',       include('allauth.urls')),
    path('complete-profile/', account_views.complete_profile, name='complete_profile'),
    path('manual-signup/',  account_views.manual_signup, name='manual_signup'),


    # ✅ لوحة الإدارة المستقلة — تحت /admin-panel/
    path('admin-panel/',    include('dashboard_admin.urls')),

    # تطبيقات المنصة
    path('student/',        include('students.urls')),
    path('teacher/',        include('teachers.urls')),
    path('exams/',          include('exams.urls')),
    path('assistants/',     include('assistants.urls')),

    # الصفحات العامة (core) — يجب أن تكون آخراً (catch-all)
    path('',                include('core.urls')),
)
