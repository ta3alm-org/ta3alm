"""
اختبارات شاملة للوحة الإدارة المعاد بناؤها (الصفحات، AJAX JSON، التصفية الحية، الصلاحيات، CSRF، والتوافق العكسي).
"""
from decimal import Decimal

from django.conf import settings
from django.core.cache import cache
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from accounts.models import StudentProfile
from api_v1.models import DeviceBlock, RegisteredDevice, SecurityPolicyConfig
from assistants.models import AssistantProfile
from core.models import CurriculumUnit, ManualPayment, SiteSetting, Subject
from dashboard_admin.models import AdminProfile, AdminRole, AuditLog, ZohoMailConfig
from teachers.models import (
    PaymentTransaction,
    SubscriptionPlan,
    TeacherProfile,
    Wallet,
    WithdrawRequest,
)

User = get_user_model()

AJAX_HEADERS = {'HTTP_X_REQUESTED_WITH': 'XMLHttpRequest'}


class AdminPanelRebuildTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        assert settings.DATABASES['default']['ENGINE'] == 'django.db.backends.sqlite3'

        cls.subject = Subject.objects.create(name='الرياضيات')
        cls.plan = SubscriptionPlan.objects.create(
            name='الباقة الأساسية',
            price=250,
            description='وصف اختبار',
            student_limit=500,
            group_limit=10,
            assistant_limit=2,
            allow_online_packages=True,
            allow_question_images=True,
            is_default=True,
        )

        # 1. Owner / Superuser
        cls.owner = User.objects.create_user(
            username='owner@example.com',
            email='owner@example.com',
            password='Password123!',
            first_name='أحمد',
            last_name='المالك',
            role='admin',
            is_staff=True,
            is_superuser=True,
        )
        AdminProfile.objects.create(
            user=cls.owner,
            admin_role=AdminRole.OWNER,
            is_active_admin=True,
        )

        # 2. Moderator
        cls.moderator = User.objects.create_user(
            username='mod@example.com',
            email='mod@example.com',
            password='Password123!',
            first_name='سارة',
            last_name='مشرفة',
            role='admin',
            is_staff=True,
        )
        AdminProfile.objects.create(
            user=cls.moderator,
            admin_role=AdminRole.MODERATOR,
            is_active_admin=True,
            appointed_by=cls.owner,
        )

        # 3. Finance admin
        cls.finance_admin = User.objects.create_user(
            username='fin@example.com',
            email='fin@example.com',
            password='Password123!',
            first_name='كريم',
            last_name='مالي',
            role='admin',
            is_staff=True,
        )
        AdminProfile.objects.create(
            user=cls.finance_admin,
            admin_role=AdminRole.FINANCE,
            is_active_admin=True,
            appointed_by=cls.owner,
        )

        # 4. Support admin
        cls.support_admin = User.objects.create_user(
            username='sup@example.com',
            email='sup@example.com',
            password='Password123!',
            first_name='ندى',
            last_name='دعم',
            role='admin',
            is_staff=True,
        )
        AdminProfile.objects.create(
            user=cls.support_admin,
            admin_role=AdminRole.SUPPORT,
            is_active_admin=True,
            appointed_by=cls.owner,
        )

        # 5. Teacher, Student, Assistant
        cls.teacher_user = User.objects.create_user(
            username='teacher1@example.com',
            email='teacher1@example.com',
            password='Password123!',
            first_name='محمود',
            last_name='المعلم',
            role='teacher',
            phone='01000000010',
        )
        cls.teacher_profile = TeacherProfile.objects.create(
            user=cls.teacher_user,
            subject=cls.subject,
            current_plan=cls.plan,
            is_approved=False,
        )
        cls.wallet = Wallet.objects.create(
            teacher=cls.teacher_profile,
            balance=Decimal('1000.00'),
            total_earnings=Decimal('1500.00'),
        )
        cls.withdraw_req = WithdrawRequest.objects.create(
            wallet=cls.wallet,
            amount=Decimal('200.00'),
            method='vodafone_cash',
            details='01012345678',
            status=WithdrawRequest.STATUS_PENDING,
        )
        cls.transaction = PaymentTransaction.objects.create(
            teacher=cls.teacher_profile,
            amount=250,
            transaction_id='TX-UNIT-1001',
        )

        cls.student_user = User.objects.create_user(
            username='student1@example.com',
            email='student1@example.com',
            password='Password123!',
            first_name='يوسف',
            last_name='الطالب',
            role='student',
            phone='01000000020',
            custom_id='STU-001',
        )
        cls.student_profile = StudentProfile.objects.create(
            user=cls.student_user,
            parent_phone='01000000021',
        )

        cls.assistant_user = User.objects.create_user(
            username='assistant1@example.com',
            email='assistant1@example.com',
            password='Password123!',
            first_name='عمر',
            last_name='المساعد',
            role='assistant',
            phone='01000000030',
        )
        cls.assistant_profile = AssistantProfile.objects.create(
            user=cls.assistant_user,
            phone='01000000030',
        )

        cls.manual_payment = ManualPayment.objects.create(
            user=cls.teacher_user,
            amount=250,
            payment_type='teacher_subscription',
            target_id=cls.plan.id,
            phone_number='01099998888',
            status='pending',
        )

        cls.unit = CurriculumUnit.objects.create(
            title='الجبر الأساسي',
            subject=cls.subject,
            grade='1_sec',
            term='1',
            order=1,
        )

        cls.device = RegisteredDevice.objects.create(
            user=cls.student_user,
            installation_id='inst_test_admin_ui_1234567890abcdef',
            device_name='Samsung Galaxy A54',
            manufacturer='Samsung',
            model='SM-A546E',
            os_name='Android',
            android_version='14',
            api_level=34,
        )

    def setUp(self):
        cache.clear()

    def _ajax_post(self, url, data=None, client=None):
        c = client or self.client
        return c.post(url, data or {}, **AJAX_HEADERS)

    def _ajax_get(self, url, data=None, client=None):
        c = client or self.client
        return c.get(url, data or {}, **AJAX_HEADERS)

    # ── 1. التحقق من عرض جميع القوالب الجديدة ─────────────────────
    def test_all_admin_pages_render_200_for_owner(self):
        self.client.force_login(self.owner)
        routes = [
            ('admin_panel:dashboard', []),
            ('admin_panel:app_release_settings', []),
            ('admin_panel:manage_users', []),
            ('admin_panel:edit_user', [self.teacher_user.id]),
            ('admin_panel:send_notifications', []),
            ('admin_panel:finance_report', []),
            ('admin_panel:withdrawals', []),
            ('admin_panel:student_payments', []),
            ('admin_panel:manual_payments', []),
            ('admin_panel:manage_plans', []),
            ('admin_panel:audit_log', []),
            ('admin_panel:manage_staff', []),
            ('admin_panel:manage_curriculum', []),
            ('admin_panel:curriculum_unit_create', []),
            ('admin_panel:curriculum_unit_edit', [self.unit.id]),
            ('admin_panel:support_inbox', []),
            ('admin_panel:support_settings', []),
            ('admin_panel:security_dashboard', []),
            ('admin_panel:security_device_detail', [self.device.id]),
        ]
        for name, args in routes:
            url = reverse(name, args=args)
            resp = self.client.get(url)
            self.assertEqual(resp.status_code, 200, f"Route {name} returned {resp.status_code}")
            html = resp.content.decode('utf-8')
            self.assertIn('admin_panel/css/tokens.css', html)
            self.assertIn('admin_panel/js/app.js', html)

    # ── 2. اختبار الصلاحيات والوصول (HTML 302 مقابل AJAX 401/403) ──
    def test_permissions_matrix_ajax_and_html(self):
        # مستخدم غير مسجل دخول
        anon = Client()
        html_anon = anon.get(reverse('admin_panel:dashboard'))
        self.assertEqual(html_anon.status_code, 302)
        ajax_anon = self._ajax_get(reverse('admin_panel:dashboard'), client=anon)
        self.assertEqual(ajax_anon.status_code, 401)
        self.assertFalse(ajax_anon.json()['success'])

        # طالب عادي ممنوع من كل صفحات الإدارة
        stud = Client()
        stud.force_login(self.student_user)
        self.assertEqual(stud.get(reverse('admin_panel:dashboard')).status_code, 302)
        ajax_stud = self._ajax_get(reverse('admin_panel:dashboard'), client=stud)
        self.assertEqual(ajax_stud.status_code, 403)
        self.assertFalse(ajax_stud.json()['success'])

        # مسؤول مالي: مسموح في المالية وممنوع في المستخدمين والخطط والإعدادات
        fin = Client()
        fin.force_login(self.finance_admin)
        self.assertEqual(fin.get(reverse('admin_panel:finance_report')).status_code, 200)
        self.assertEqual(self._ajax_get(reverse('admin_panel:manage_users'), client=fin).status_code, 403)
        self.assertEqual(self._ajax_post(reverse('admin_panel:manage_plans'), {'action': 'add', 'name': 'X'}, client=fin).status_code, 403)

        # مشرف: مسموح في المستخدمين والأمان والإشعارات والدعم، ممنوع في المالية والمالك
        mod = Client()
        mod.force_login(self.moderator)
        self.assertEqual(mod.get(reverse('admin_panel:manage_users')).status_code, 200)
        self.assertEqual(self._ajax_get(reverse('admin_panel:finance_report'), client=mod).status_code, 403)
        self.assertEqual(self._ajax_get(reverse('admin_panel:manage_staff'), client=mod).status_code, 403)

        # دعم فني: مسموح في صندوق الدعم وممنوع في إعدادات Zoho والمستخدمين والمالية
        sup = Client()
        sup.force_login(self.support_admin)
        self.assertEqual(sup.get(reverse('admin_panel:support_inbox')).status_code, 200)
        self.assertEqual(self._ajax_get(reverse('admin_panel:support_settings'), client=sup).status_code, 403)
        self.assertEqual(self._ajax_post(reverse('admin_panel:support_compose'), {'to_email': 'a@b.com'}, client=sup).status_code, 200 if False else 400)

    # ── 3. فرض التحقق من CSRF على طلبات AJAX POST ───────────────
    def test_csrf_enforced_on_ajax_posts(self):
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.owner)

        url = reverse('admin_panel:toggle_maintenance')
        # بدون X-CSRFToken يُرفض الطلب بـ 403
        blocked = csrf_client.post(url, {}, **AJAX_HEADERS)
        self.assertEqual(blocked.status_code, 403)

        # جلب الكوكي من صفحة لوحة القيادة ثم إرسال X-CSRFToken يمر بـ 200
        csrf_client.get(reverse('admin_panel:dashboard'))
        token = csrf_client.cookies['csrftoken'].value
        allowed = csrf_client.post(
            url,
            {},
            HTTP_X_CSRFTOKEN=token,
            **AJAX_HEADERS,
        )
        self.assertEqual(allowed.status_code, 200)
        self.assertTrue(allowed.json()['success'])

    # ── 4. AJAX الرئيسية والعمولة وإصدارات التطبيق ────────────────
    def test_home_and_app_release_ajax_endpoints(self):
        self.client.force_login(self.owner)

        # تبديل الصيانة عبر AJAX
        r1 = self._ajax_post(reverse('admin_panel:toggle_maintenance'))
        self.assertEqual(r1.status_code, 200)
        d1 = r1.json()
        self.assertTrue(d1['success'])
        self.assertTrue(d1['data']['is_maintenance_mode'])

        # تبديل غير AJAX يرجع 302 (توافق عكسي)
        r_fallback = self.client.post(reverse('admin_panel:toggle_maintenance'))
        self.assertEqual(r_fallback.status_code, 302)
        self.assertFalse(SiteSetting.load().is_maintenance_mode)

        # تحديث العمولة: صحيح ثم قيمة خاطئة
        rc_ok = self._ajax_post(reverse('admin_panel:update_platform_commission'), {'platform_commission_percentage': '15'})
        self.assertEqual(rc_ok.status_code, 200)
        self.assertEqual(rc_ok.json()['data']['platform_commission_percentage'], 15)

        rc_bad = self._ajax_post(reverse('admin_panel:update_platform_commission'), {'platform_commission_percentage': '150'})
        self.assertEqual(rc_bad.status_code, 400)
        self.assertFalse(rc_bad.json()['success'])
        self.assertIn('platform_commission_percentage', rc_bad.json()['errors'])

        # تحديث APK عبر AJAX
        r_apk = self._ajax_post(
            reverse('admin_panel:app_release_settings'),
            {
                'android_apk_url': 'https://github.com/org/app/releases/download/v2.0.0/app-release.apk',
                'android_latest_version_code': '12',
                'android_min_required_version_code': '10',
                'android_latest_version_name': '2.0.0',
                'android_force_update': '1',
                'android_apk_sha256': 'ab12' * 16,
            },
        )
        self.assertEqual(r_apk.status_code, 200)
        apk_json = r_apk.json()
        self.assertTrue(apk_json['success'])
        self.assertEqual(apk_json['data']['latest_version_code'], 12)
        self.assertIn('assetlinks_preview', apk_json['data'])

        r_apk_bad = self._ajax_post(
            reverse('admin_panel:update_app_release_settings'),
            {
                'android_apk_url': 'ftp://invalid.example.com/app.apk',
                'android_latest_version_code': '12',
                'android_min_required_version_code': '10',
                'android_latest_version_name': '2.0.0',
            },
        )
        self.assertEqual(r_apk_bad.status_code, 400)
        self.assertFalse(r_apk_bad.json()['success'])

    # ── 5. AJAX المستخدمون وتعديل المستخدم ───────────────────────
    def test_users_and_edit_user_ajax(self):
        self.client.force_login(self.moderator)

        # بحث جزئي عبر ?partial=1
        part = self._ajax_get(reverse('admin_panel:manage_users'), {'q': 'محمود', 'partial': '1', 'tab': 'teachers'})
        self.assertEqual(part.status_code, 200)
        pdata = part.json()
        self.assertTrue(pdata['success'])
        self.assertIn('محمود', pdata['data']['html'])
        self.assertEqual(pdata['data']['counts']['teachers'], 1)

        # اعتماد وتجديد وحظر وفك حظر المعلم عبر AJAX
        act_url = reverse('admin_panel:user_action')
        res_app = self._ajax_post(act_url, {'user_id': self.teacher_user.id, 'action': 'approve_teacher'})
        self.assertEqual(res_app.status_code, 200)
        self.assertTrue(res_app.json()['data']['is_approved'])

        res_ren = self._ajax_post(act_url, {'user_id': self.teacher_user.id, 'action': 'renew_free', 'plan_id': self.plan.id})
        self.assertEqual(res_ren.status_code, 200)
        self.assertTrue(res_ren.json()['data']['subscription_active'])

        res_ban = self._ajax_post(act_url, {'user_id': self.student_user.id, 'action': 'ban'})
        self.assertEqual(res_ban.status_code, 200)
        self.assertTrue(res_ban.json()['data']['is_banned'])

        res_unban = self._ajax_post(act_url, {'user_id': self.student_user.id, 'action': 'unban'})
        self.assertEqual(res_unban.status_code, 200)
        self.assertFalse(res_unban.json()['data']['is_banned'])

        # حماية المالك
        res_owner = self._ajax_post(act_url, {'user_id': self.owner.id, 'action': 'ban'})
        self.assertEqual(res_owner.status_code, 403)

        # المشرف لا يحذف المستخدمين -> 403
        res_del_mod = self._ajax_post(act_url, {'user_id': self.assistant_user.id, 'action': 'delete'})
        self.assertEqual(res_del_mod.status_code, 403)

        # edit_user AJAX: رابط مباشر وتغيير كلمة المرور وتحديث البيانات
        edit_url = reverse('admin_panel:edit_user', args=[self.student_user.id])
        r_magic = self._ajax_post(edit_url, {'generate_login_link': '1'})
        self.assertEqual(r_magic.status_code, 200)
        self.assertIn('/login/auto/', r_magic.json()['data']['magic_link'])

        r_pw = self._ajax_post(edit_url, {'change_password': '1', 'new_password': 'NewPass456!'})
        self.assertEqual(r_pw.status_code, 200)
        self.assertTrue(r_pw.json()['success'])

        r_prof = self._ajax_post(
            edit_url,
            {
                'first_name': 'يوسف',
                'last_name': 'المحدث',
                'email': self.student_user.email,
                'phone': '01000000020',
                'national_id': '',
                'custom_id': 'STU-001',
                'parent_phone': '01000000099',
            },
        )
        self.assertEqual(r_prof.status_code, 200)
        self.assertTrue(r_prof.json()['success'])

    # ── 6. AJAX المالية والسحب والدفع اليدوي ─────────────────────
    def test_finance_withdrawals_and_manual_payments_ajax(self):
        self.client.force_login(self.finance_admin)

        # التقرير المالي الجزئي
        r_fin = self._ajax_get(reverse('admin_panel:finance_report'), {'q': 'TX-UNIT-1001', 'partial': '1'})
        self.assertEqual(r_fin.status_code, 200)
        self.assertEqual(r_fin.json()['data']['count'], 1)

        # رفض طلب السحب وإرجاع الرصيد للمحفظة عبر AJAX
        r_rej = self._ajax_post(
            reverse('admin_panel:withdrawals'),
            {
                'req_id': self.withdraw_req.id,
                'action': 'reject',
                'rejection_reason': 'رقم محفظة غير صحيح',
            },
        )
        self.assertEqual(r_rej.status_code, 200)
        self.assertEqual(r_rej.json()['data']['status'], WithdrawRequest.STATUS_REJECTED)
        self.wallet.refresh_from_db()
        self.assertEqual(self.wallet.balance, Decimal('1200.00'))

        # منع المعالجة المزدوجة
        r_dup = self._ajax_post(reverse('admin_panel:withdrawals'), {'req_id': self.withdraw_req.id, 'action': 'approve'})
        self.assertEqual(r_dup.status_code, 409)

        # قبول الدفع اليدوي عبر AJAX
        r_mp = self._ajax_post(reverse('admin_panel:manual_payments'), {'payment_id': self.manual_payment.id, 'action': 'approve'})
        self.assertEqual(r_mp.status_code, 200)
        self.assertEqual(r_mp.json()['data']['status'], 'approved')

    # ── 7. AJAX الباقات وفريق الإدارة والمناهج والسجل ────────────
    def test_plans_staff_curriculum_and_audit_ajax(self):
        self.client.force_login(self.owner)

        # الباقات: إضافة ثم تعديل ثم حذف
        plans_url = reverse('admin_panel:manage_plans')
        r_add = self._ajax_post(
            plans_url,
            {
                'action': 'add',
                'name': 'الباقة الاحترافية',
                'price': '499',
                'desc': 'باقة اختبار',
                'student_limit': '2000',
                'group_limit': '20',
                'assistant_limit': '5',
                'allow_online': 'on',
            },
        )
        self.assertEqual(r_add.status_code, 200)
        self.assertIn('الباقة الاحترافية', r_add.json()['data']['grid_html'])

        new_plan = SubscriptionPlan.objects.get(name='الباقة الاحترافية')
        r_edit = self._ajax_post(
            plans_url,
            {
                'action': 'edit',
                'plan_id': new_plan.id,
                'name': 'الباقة المعدلة',
                'price': '550',
                'student_limit': '2500',
                'group_limit': '25',
                'assistant_limit': '5',
            },
        )
        self.assertEqual(r_edit.status_code, 200)
        self.assertIn('الباقة المعدلة', r_edit.json()['data']['grid_html'])

        r_del = self._ajax_post(plans_url, {'action': 'delete', 'plan_id': new_plan.id})
        self.assertEqual(r_del.status_code, 200)
        self.assertFalse(SubscriptionPlan.objects.filter(id=new_plan.id).exists())

        # فريق الإدارة: ترقية وإزالة
        staff_url = reverse('admin_panel:manage_staff')
        r_app = self._ajax_post(
            staff_url,
            {
                'action': 'appoint',
                'user_email': self.assistant_user.email,
                'admin_role': AdminRole.SUPPORT,
                'notes': 'ترقية اختبارية',
            },
        )
        self.assertEqual(r_app.status_code, 200)
        self.assertIn(self.assistant_user.email, r_app.json()['data']['table_html'])

        created_profile = AdminProfile.objects.get(user=self.assistant_user)
        r_rem = self._ajax_post(staff_url, {'action': 'remove', 'profile_id': created_profile.id})
        self.assertEqual(r_rem.status_code, 200)
        self.assertFalse(AdminProfile.objects.filter(id=created_profile.id).exists())

        # المناهج: إضافة وتعديل وحذف عبر AJAX
        r_cur_add = self._ajax_post(
            reverse('admin_panel:curriculum_unit_create'),
            {
                'title': 'الوحدة الثانية',
                'subject': self.subject.id,
                'grade': '1_sec',
                'term': '1',
                'order': '2',
                'lessons-TOTAL_FORMS': '1',
                'lessons-INITIAL_FORMS': '0',
                'lessons-MIN_NUM_FORMS': '0',
                'lessons-MAX_NUM_FORMS': '1000',
                'lessons-0-title': 'الدرس الأول',
                'lessons-0-order': '1',
            },
        )
        self.assertEqual(r_cur_add.status_code, 200)
        created_unit_id = r_cur_add.json()['data']['unit_id']

        r_cur_del = self._ajax_post(reverse('admin_panel:curriculum_unit_delete', args=[created_unit_id]))
        self.assertEqual(r_cur_del.status_code, 200)
        self.assertTrue(r_cur_del.json()['data']['deleted'])

        # سجل الأحداث الجزئي
        r_aud = self._ajax_get(reverse('admin_panel:audit_log'), {'action': AuditLog.ACTION_ADD_PLAN, 'partial': '1'})
        self.assertEqual(r_aud.status_code, 200)
        self.assertGreaterEqual(r_aud.json()['data']['count'], 1)

    # ── 8. AJAX الدعم والأمان والإشعارات ─────────────────────────
    def test_support_security_and_notifications_ajax(self):
        self.client.force_login(self.owner)

        # إعدادات Zoho: حفظ وفصل الاتصال عبر AJAX
        r_zsave = self._ajax_post(
            reverse('admin_panel:support_settings'),
            {
                'action': 'save_keys',
                'support_email': 'support@ta3alm.online',
                'client_id': '1000.TESTCLIENT',
                'client_secret': 'secret123',
            },
        )
        self.assertEqual(r_zsave.status_code, 200)
        self.assertTrue(r_zsave.json()['data']['is_configured'])

        r_zdisc = self._ajax_post(reverse('admin_panel:support_settings'), {'action': 'disconnect'})
        self.assertEqual(r_zdisc.status_code, 200)
        self.assertFalse(r_zdisc.json()['data']['is_connected'])

        # الأمان: تحديث السياسة، فحص AI، حظر وفك حظر، تصفية جزئية
        sec_part = self._ajax_get(reverse('admin_panel:security_dashboard'), {'partial': '1'})
        self.assertEqual(sec_part.status_code, 200)
        self.assertIn('stats', sec_part.json()['data'])

        sec_action_url = reverse('admin_panel:security_admin_action')
        r_pol = self._ajax_post(
            sec_action_url,
            {
                'action': 'update_policy',
                'student_device_limit': '2',
                'teacher_device_limit': '3',
                'max_concurrent_sessions': '2',
                'max_concurrent_playback': '1',
                'risk_threshold_high': '75',
                'event_retention_days': '45',
                'enforce_device_limits': 'on',
            },
        )
        self.assertEqual(r_pol.status_code, 200)
        self.assertEqual(SecurityPolicyConfig.load().student_device_limit, 2)

        r_blk = self._ajax_post(
            sec_action_url,
            {
                'action': 'block_device',
                'device_id': self.device.id,
                'block_type': 'permanent',
                'reason': 'اختبار AJAX',
            },
        )
        self.assertEqual(r_blk.status_code, 200)
        self.assertTrue(r_blk.json()['data']['is_blocked'])
        self.assertTrue(DeviceBlock.objects.filter(installation_id=self.device.installation_id, is_active=True).exists())

        r_unblk = self._ajax_post(
            sec_action_url,
            {'action': 'unblock_device', 'device_id': self.device.id},
        )
        self.assertEqual(r_unblk.status_code, 200)
        self.assertFalse(r_unblk.json()['data']['is_blocked'])

        # الإشعارات المخصصة عبر AJAX
        r_notif = self._ajax_post(
            reverse('admin_panel:send_notifications'),
            {
                'target_mode': 'users',
                'user_ids': [str(self.student_user.id)],
                'exclude_banned': '1',
                'title': 'إشعار AJAX تجريبي',
                'message': 'محتوى الاختبار من لوحة الإدارة.',
                'link': '/notifications/all/',
            },
        )
        self.assertEqual(r_notif.status_code, 200)
        nj = r_notif.json()
        self.assertTrue(nj['success'])
        self.assertEqual(nj['data']['recipient_count'], 1)
        self.assertIn('إشعار AJAX تجريبي', nj['data']['dispatches_html'])
