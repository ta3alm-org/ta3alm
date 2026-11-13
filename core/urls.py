"""
core/urls.py — الروابط العامة للمنصة
(روابط الإدارة انتقلت إلى dashboard_admin/urls.py)
"""
from django.urls import path
from . import views

urlpatterns = [
    path('',                                    views.home,                  name='home'),
    path('signup/<str:role>/',                  views.signup_redirect,       name='signup_redirect'),
    path('redirect/',                           views.custom_login_redirect, name='custom_login_redirect'),
    path('banned/',                             views.banned_page,           name='banned_page'),
    path('notifications/read/<int:notif_id>/', views.read_notification,     name='read_notification'),
    path('notifications/all/',                  views.all_notifications,     name='all_notifications'),
    path('guide/',                              views.platform_guide,        name='platform_guide'),
    path('checkout/manual/',                    views.manual_checkout_view,  name='manual_checkout'),
    path('ajax/get_lessons/',                   views.ajax_get_lessons,      name='ajax_get_lessons'),
    path('plans/',                               views.public_plans,          name='public_plans'),
]