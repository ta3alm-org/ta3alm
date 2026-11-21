"""ta3alm_project.middleware.routing
Extracted from ta3alm_project/middleware.py.
"""


class SubdomainAdminMiddleware:
    """
    يعترض الطلبات القادمة على النطاق الفرعي admin.* ويُعيد
    توجيهها لـ dashboard_admin URLs دون أي تغيير في الرابط الظاهر.

    محلياً  : admin.localhost:8000  أو  admin.127.0.0.1
    إنتاج   : admin.ta3alm.online
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def _is_admin_subdomain(self, host):
        """True إذا كان الـ host يبدأ بـ admin."""
        # أزِل رقم المنفذ لو موجود  (admin.localhost:8000 → admin.localhost)
        hostname = host.split(':')[0].lower()
        return hostname.startswith('admin.')

    def __call__(self, request):
        host = request.META.get('HTTP_HOST', '')

        if self._is_admin_subdomain(host):
            # أعِد كتابة المسار ليصل لـ dashboard_admin عبر prefix /admin-panel/
            original_path = request.path_info

            # تجنُّب إعادة الكتابة لو المسار أصلاً يحمل الـ prefix
            if not original_path.startswith('/admin-panel/'):
                # الصفحة الجذر → لوحة التحكم مباشرة
                if original_path in ('/', ''):
                    new_path = '/admin-panel/'
                else:
                    new_path = '/admin-panel' + original_path

                request.path_info = new_path
                request.path = new_path
                request.META['PATH_INFO'] = new_path

        return self.get_response(request)
