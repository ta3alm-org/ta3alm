"""
dashboard_admin/urls.py
روابط لوحة الإدارة — prefix: /admin-panel/
"""
from django.urls import path
from . import views

app_name = 'admin_panel'

urlpatterns = [
    # الرئيسية
    path('',                    views.dashboard,          name='dashboard'),
    path('maintenance/toggle/', views.toggle_maintenance, name='toggle_maintenance'),
    path('commission/update/',  views.update_platform_commission, name='update_platform_commission'),
    path('app-release/update/', views.update_app_release_settings, name='update_app_release_settings'),

    # إدارة المستخدمين
    path('users/',              views.manage_users,       name='manage_users'),
    path('users/action/',       views.user_action,        name='user_action'),
    path('users/edit/<int:user_id>/', views.edit_user,   name='edit_user'),

    # المالية
    path('finance/',            views.finance_report,     name='finance_report'),
    path('finance/withdrawals/',views.withdrawals,        name='withdrawals'),
    path('finance/student-payments/', views.student_payments, name='student_payments'),
    path('finance/manual-payments/', views.manual_payments, name='manual_payments'),

    # الباقات
    path('plans/',              views.manage_plans,       name='manage_plans'),

    # سجل الأحداث
    path('audit-log/',          views.audit_log,          name='audit_log'),

    # فريق الإدارة
    path('staff/',              views.manage_staff,       name='manage_staff'),

    # المناهج الدراسية
    path('curriculum/',         views.manage_curriculum,  name='manage_curriculum'),
    path('curriculum/add/',     views.curriculum_unit_create, name='curriculum_unit_create'),
    path('curriculum/edit/<int:unit_id>/', views.curriculum_unit_edit, name='curriculum_unit_edit'),
    path('curriculum/delete/<int:unit_id>/', views.curriculum_unit_delete, name='curriculum_unit_delete'),

    # خدمة العملاء وبريد الدعم (Zoho Mail REST API)
    path('support-inbox/',                 views.support_inbox,          name='support_inbox'),
    path('support-inbox/message/<str:message_id>/', views.support_message_detail, name='support_message_detail'),
    path('support-inbox/reply/',           views.support_send_reply,     name='support_send_reply'),
    path('support-inbox/compose/',         views.support_compose,        name='support_compose'),
    path('support-inbox/settings/',        views.support_settings,       name='support_settings'),
    path('support-inbox/oauth-connect/',   views.support_oauth_connect,  name='support_oauth_connect'),
    path('support-inbox/oauth2callback/',  views.support_oauth_callback, name='support_oauth_callback'),

    # مركز أمان الأجهزة ومكافحة مشاركة الحسابات
    path('security/',                         views.security_dashboard,     name='security_dashboard'),
    path('security/devices/<int:device_id>/', views.security_device_detail, name='security_device_detail'),
    path('security/action/',                  views.security_admin_action,  name='security_admin_action'),
]
