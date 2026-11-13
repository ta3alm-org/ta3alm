"""
api_v1/schema.py
توليد مخطط OpenAPI 3.0 JSON وواجهة Swagger UI التفاعلية لتوثيق الـ API بالكامل.
"""
from django.http import HttpResponse
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView


OPENAPI_SPEC = {
    'openapi': '3.0.3',
    'info': {
        'title': 'Ta3alm Educational Platform REST API',
        'version': '1.0.0',
        'description': 'Complete REST API v1 for the Ta3alm Native Flutter Application (Students, Teachers, Assistants, and Platform Admins).',
    },
    'servers': [
        {'url': '/api/v1', 'description': 'API v1'},
    ],
    'components': {
        'securitySchemes': {
            'BearerAuth': {
                'type': 'http',
                'scheme': 'bearer',
                'bearerFormat': 'JWT',
            },
            'TokenAuth': {
                'type': 'apiKey',
                'in': 'header',
                'name': 'Authorization',
                'description': 'Token <key>',
            },
        },
    },
    'paths': {
        '/auth/login/': {'post': {'summary': 'Multi-field Login (Email / Phone / Username / Custom ID) -> JWT + DRF Token', 'tags': ['Auth']}},
        '/auth/register/': {'post': {'summary': 'Role-based Registration (student, teacher, assistant)', 'tags': ['Auth']}},
        '/auth/complete-profile/': {'post': {'summary': 'Complete User Profile & Activate Teacher Trial', 'tags': ['Auth']}},
        '/auth/refresh/': {'post': {'summary': 'Refresh JWT Access Token', 'tags': ['Auth']}},
        '/auth/logout/': {'post': {'summary': 'Logout & Revoke Token', 'tags': ['Auth']}},
        '/auth/me/': {
            'get': {'summary': 'Get Current User Profile & Role Status', 'tags': ['Auth']},
            'patch': {'summary': 'Update Current User & Role Profile', 'tags': ['Auth']},
            'delete': {'summary': 'Delete Account', 'tags': ['Auth']},
        },
        '/auth/change-password/': {'post': {'summary': 'Change Password', 'tags': ['Auth']}},
        '/auth/reset-password-nid/': {'post': {'summary': 'Reset Password via Phone + 14-digit National ID', 'tags': ['Auth']}},
        '/public/home/': {'get': {'summary': 'Home Page Featured Teachers, Packages, Subjects & Filters', 'tags': ['Public']}},
        '/public/metadata/': {'get': {'summary': 'Subjects, Grades, Terms, Roles & Payment Wallets Metadata', 'tags': ['Public']}},
        '/public/plans/': {'get': {'summary': 'Teacher Subscription Plans', 'tags': ['Public']}},
        '/public/guide/': {'get': {'summary': 'Platform User Guide', 'tags': ['Public']}},
        '/curriculum/lessons/': {'get': {'summary': 'Curriculum Units & Lessons Filter', 'tags': ['Public']}},
        '/notifications/': {'get': {'summary': 'User Notifications & Unread Count', 'tags': ['Notifications']}},
        '/notifications/read-all/': {'post': {'summary': 'Mark All Notifications Read', 'tags': ['Notifications']}},
        '/payments/manual-checkout/': {
            'get': {'summary': 'List My Manual Payment Requests', 'tags': ['Payments']},
            'post': {'summary': 'Submit Manual Payment Receipt (Vodafone Cash / InstaPay)', 'tags': ['Payments']},
        },
        '/student/dashboard/': {'get': {'summary': 'Student Dashboard (Active/Locked/Pending Groups & Paid Packages)', 'tags': ['Student']}},
        '/student/groups/search/': {'get': {'summary': 'Search & Filter Study Groups', 'tags': ['Student']}},
        '/student/groups/{group_id}/join/': {'post': {'summary': 'Send Group Join Request', 'tags': ['Student']}},
        '/student/groups/{group_id}/content/': {'get': {'summary': 'Student Group Content (Lectures, Exams, PDFs)', 'tags': ['Student']}},
        '/student/lectures/{lecture_id}/watch/': {
            'get': {'summary': 'Watch Group Lecture & Increment View Counter', 'tags': ['Student']},
            'post': {'summary': 'Activate Video Code for Lecture', 'tags': ['Student']},
        },
        '/student/exams/{exam_id}/take/': {
            'get': {'summary': 'Get Group Exam Questions (without correct_answer)', 'tags': ['Student']},
            'post': {'summary': 'Submit Group Exam Answers & Auto-Grade', 'tags': ['Student']},
        },
        '/student/groups/{group_id}/marks/': {'get': {'summary': 'Student Group Performance Logs & Exam Results', 'tags': ['Student']}},
        '/student/groups/{group_id}/ranking/': {'get': {'summary': 'Student Group Leaderboard & Rank', 'tags': ['Student']}},
        '/student/groups/{group_id}/contact/': {'get': {'summary': 'Student Group Teacher & Assistants Contact', 'tags': ['Student']}},
        '/student/packages/': {'get': {'summary': 'Browse Online Course Packages Store', 'tags': ['Student']}},
        '/student/packages/{package_id}/': {'get': {'summary': 'Course Package Detail & Enrollment Check', 'tags': ['Student']}},
        '/student/packages/{package_id}/content/': {'get': {'summary': 'Enrolled Package Content & Video Progress', 'tags': ['Student']}},
        '/student/packages/{package_id}/lectures/{lecture_id}/watch/': {'post': {'summary': 'Watch Package Lecture & Award 10 Points', 'tags': ['Student']}},
        '/student/packages/{package_id}/exams/{exam_id}/take/': {
            'get': {'summary': 'Get Package Exam Questions', 'tags': ['Student']},
            'post': {'summary': 'Submit Package Exam Answers', 'tags': ['Student']},
        },
        '/student/packages/{package_id}/marks/': {'get': {'summary': 'Package Marks, Video Points & Leaderboard', 'tags': ['Student']}},
        '/teacher/dashboard/': {
            'get': {'summary': 'Teacher Dashboard, Subscription Status & Groups', 'tags': ['Teacher']},
            'post': {'summary': 'Create New Study Group', 'tags': ['Teacher']},
        },
        '/teacher/groups/{group_id}/': {
            'get': {'summary': 'Group Full Detail for Teacher/Assistant', 'tags': ['Teacher']},
            'patch': {'summary': 'Update Group', 'tags': ['Teacher']},
            'delete': {'summary': 'Delete Group', 'tags': ['Teacher']},
        },
        '/teacher/groups/{group_id}/lectures/': {
            'get': {'summary': 'List Group Lectures', 'tags': ['Teacher']},
            'post': {'summary': 'Create Lecture & Notify Enrolled Students', 'tags': ['Teacher']},
        },
        '/teacher/lectures/{lecture_id}/': {
            'post': {'summary': 'Toggle Lecture Active Status', 'tags': ['Teacher']},
            'delete': {'summary': 'Delete Lecture', 'tags': ['Teacher']},
        },
        '/teacher/lectures/{lecture_id}/codes/': {
            'get': {'summary': 'List Lecture Video Codes', 'tags': ['Teacher']},
            'post': {'summary': 'Generate Batch of Video Codes with View Limit', 'tags': ['Teacher']},
        },
        '/teacher/groups/{group_id}/exams/': {
            'get': {'summary': 'List Group Exams', 'tags': ['Teacher']},
            'post': {'summary': 'Create Group Exam', 'tags': ['Teacher']},
        },
        '/teacher/exams/{exam_id}/': {
            'get': {'summary': 'Exam Manage Detail (Questions + Student Results)', 'tags': ['Teacher']},
            'post': {'summary': 'Add Question or Toggle Exam Status', 'tags': ['Teacher']},
            'delete': {'summary': 'Delete Exam', 'tags': ['Teacher']},
        },
        '/teacher/questions/{question_id}/': {
            'patch': {'summary': 'Edit Question', 'tags': ['Teacher']},
            'delete': {'summary': 'Delete Question', 'tags': ['Teacher']},
        },
        '/teacher/groups/{group_id}/students/': {
            'get': {'summary': 'List Active Students & Pending Join Requests', 'tags': ['Teacher']},
            'post': {'summary': 'Log Individual Performance or Accept/Reject Join Request', 'tags': ['Teacher']},
        },
        '/teacher/groups/{group_id}/students/{student_id}/logs/': {
            'get': {'summary': 'Full Performance Log for Student', 'tags': ['Teacher']},
            'delete': {'summary': 'Delete Log Entry or Remove Student from Group', 'tags': ['Teacher']},
        },
        '/teacher/groups/{group_id}/bulk-log/': {'post': {'summary': 'Bulk Attendance & Grades Logging', 'tags': ['Teacher']}},
        '/teacher/groups/{group_id}/ranking/': {
            'get': {'summary': 'Group Leaderboard', 'tags': ['Teacher']},
            'post': {'summary': 'Import Lectures & Exams from Other Groups', 'tags': ['Teacher']},
        },
        '/teacher/packages/': {
            'get': {'summary': 'List Teacher Course Packages', 'tags': ['Teacher']},
            'post': {'summary': 'Create Online Course Package', 'tags': ['Teacher']},
        },
        '/teacher/packages/{package_id}/': {
            'get': {'summary': 'Teacher Package Content, Enrolled Students, Revenue & Ranking', 'tags': ['Teacher']},
            'post': {'summary': 'Add/Remove/Import Content in Package', 'tags': ['Teacher']},
            'patch': {'summary': 'Update Package', 'tags': ['Teacher']},
            'delete': {'summary': 'Delete Package', 'tags': ['Teacher']},
        },
        '/teacher/wallet/': {
            'get': {'summary': 'Teacher Wallet Balance & Withdrawal History', 'tags': ['Teacher']},
            'post': {'summary': 'Submit Withdrawal Request', 'tags': ['Teacher']},
        },
        '/teacher/assistants/': {
            'get': {'summary': 'List Active & Pending Assistants', 'tags': ['Teacher']},
            'post': {'summary': 'Accept, Reject, or Update Assistant Permissions', 'tags': ['Teacher']},
        },
        '/assistant/dashboard/': {
            'get': {'summary': 'Assistant Active & Pending Jobs', 'tags': ['Assistant']},
            'post': {'summary': 'Apply to Work with a Teacher', 'tags': ['Assistant']},
        },
        '/assistant/teachers/{teacher_id}/groups/': {
            'get': {'summary': 'View Teacher Groups as Assistant', 'tags': ['Assistant']},
            'post': {'summary': 'Create Group for Teacher as Assistant', 'tags': ['Assistant']},
        },
        '/admin/dashboard/': {'get': {'summary': 'Platform Admin Statistics & Audit Logs', 'tags': ['Admin']}},
        '/admin/maintenance/toggle/': {'post': {'summary': 'Toggle Platform Maintenance Mode', 'tags': ['Admin']}},
        '/admin/users/': {
            'get': {'summary': 'Search & Filter All Users', 'tags': ['Admin']},
            'post': {'summary': 'Ban, Unban, Delete, or Renew Teacher Subscription', 'tags': ['Admin']},
        },
        '/admin/finance/': {
            'get': {'summary': 'Finance Reports, Withdrawals & Manual Payments', 'tags': ['Admin']},
            'post': {'summary': 'Approve/Reject Manual Payment or Mark Withdrawal Paid', 'tags': ['Admin']},
        },
        '/admin/plans-staff/': {
            'get': {'summary': 'Subscription Plans & Admin Staff List', 'tags': ['Admin']},
            'post': {'summary': 'Manage Plans & Appoint/Remove Admin Staff', 'tags': ['Admin']},
        },
    },
}


class OpenAPISchemaView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        return Response(OPENAPI_SPEC)


class SwaggerUIView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Ta3alm API v1 Documentation</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>
window.onload = () => {
    window.ui = SwaggerUIBundle({
        url: '/api/v1/schema/',
        dom_id: '#swagger-ui',
    });
};
</script>
</body>
</html>"""
        return HttpResponse(html, content_type='text/html')

