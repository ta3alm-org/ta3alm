from django.contrib.sitemaps import Sitemap
from django.urls import reverse
from teachers.models import TeacherProfile, CoursePackage

class StaticViewSitemap(Sitemap):
    priority = 0.8
    changefreq = 'daily'

    def items(self):
        # تأكد أن هذه الأسماء موجودة في urls.py لديك
        return ['home', 'privacy_policy', 'terms_of_service', 'platform_guide']

    def location(self, item):
        return reverse(item)

class TeacherSitemap(Sitemap):
    changefreq = "weekly"
    priority = 0.9

    def items(self):
        return TeacherProfile.objects.all()

    # هذه الدالة كانت تسبب مشكلة لو لم تعرف كيف تبني الرابط
    def location(self, obj):
        # بناء الرابط يدوياً للبحث
        return f"/student/search/?q={obj.user.first_name}"

class PackageSitemap(Sitemap):
    changefreq = "weekly"
    priority = 1.0

    def items(self):
        return CoursePackage.objects.filter(is_active=True)

    # تستخدم get_absolute_url لو موجودة في الموديل، أو نحددها هنا
    def location(self, obj):
        return reverse('package_detail', args=[obj.id])