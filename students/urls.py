from django.urls import path
from . import views
from . import api_views

urlpatterns = [
    path('dashboard/', views.student_dashboard, name='student_dashboard'),
    path('settings/', views.student_settings, name='student_settings'),
    path('search/', views.search_groups, name='search_groups'),
    path('join/<int:group_id>/', views.join_group, name='join_group'),
    path('group/<int:group_id>/', views.student_group_content, name='student_group_content'),
    path('group/<int:group_id>/exams/', views.student_group_exams, name='student_group_exams'),
    path('group/<int:group_id>/marks/', views.student_group_marks, name='student_group_marks'),
    path('group/<int:group_id>/ranking/', views.student_group_ranking, name='student_group_ranking'),
    path('lecture/<int:lecture_id>/watch/', views.student_watch_lecture, name='student_watch_lecture'),
    path('lecture/<int:lecture_id>/heartbeat/', views.web_lecture_heartbeat, name='web_lecture_heartbeat'),
    path('lecture/<int:lecture_id>/end/', views.web_lecture_end, name='web_lecture_end'),
    path('exam/<int:exam_id>/take/', views.student_take_exam, name='student_take_exam'),
    path('group/<int:group_id>/contact/', views.student_group_contact, name='student_group_contact'),
    path('package/<int:package_id>/checkout/', views.paymob_package_checkout, name='paymob_package_checkout'),
    path('packages/', views.list_packages, name='list_packages'),
    path('package/<int:package_id>/', views.package_detail, name='package_detail'),
    path('package/<int:package_id>/content/', views.my_package_content, name='my_package_content'),
    path('package/<int:package_id>/lecture/<int:lecture_id>/', views.watch_package_lecture, name='watch_package_lecture'),
    path('package/<int:package_id>/exam/<int:exam_id>/take/', views.student_take_package_exam, name='student_take_package_exam'),
    path('package/<int:package_id>/marks/', views.my_package_marks, name='my_package_marks'),
    path('package/<int:package_id>/ranking/', views.package_leaderboard, name='package_leaderboard'),
    path('group/<int:group_id>/files/', views.student_group_files, name='student_group_files'),
    path('package/<int:package_id>/files/', views.student_package_files, name='student_package_files'),
    path('api/my-groups/', api_views.my_groups_api),
    path('api/my-packages/', api_views.my_packages_api),
    path('api/group/<int:group_id>/content/', api_views.group_content_api),
]