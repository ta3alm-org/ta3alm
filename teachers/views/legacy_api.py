"""teachers.views.legacy_api
Extracted from teachers/views.py.
"""

from teachers.models import TeacherProfile
from teachers.models import CoursePackage
from rest_framework.decorators import (
    api_view,
    permission_classes,
)
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from teachers.serializers import (
    TeacherSerializer,
    PackageSerializer,
)


# 1. API لجلب كل المدرسين (للصفحة الرئيسية في التطبيق)
@api_view(['GET'])
@permission_classes([AllowAny]) # مسموح لأي حد (حتى لو مش مسجل)
def api_all_teachers(request):
    teachers = TeacherProfile.objects.all().order_by('-id')
    serializer = TeacherSerializer(teachers, many=True)
    return Response(serializer.data)


# 2. API لجلب الحزم
@api_view(['GET'])
@permission_classes([AllowAny])
def api_all_packages(request):
    packages = CoursePackage.objects.filter(is_active=True)
    serializer = PackageSerializer(packages, many=True)
    return Response(serializer.data)
