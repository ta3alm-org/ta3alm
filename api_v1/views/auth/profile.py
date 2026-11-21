"""api_v1.views.auth.profile
Extracted from api_v1/views_auth.py.
"""

import re
from django.contrib.auth import get_user_model
from django.db import transaction
from rest_framework import status
from rest_framework.permissions import (
    AllowAny,
    IsAuthenticated,
)
from rest_framework.response import Response
from rest_framework.views import APIView
from api_v1.serializers import UserDetailSerializer
from api_v1.security_engine import record_behavioral_activity

from api_v1.services.auth_service import (
    _extract_installation_id,
    _resolve_subject_input,
)

User = get_user_model()


class MeProfileAPIView(APIView):
    """جلب أو تحديث أو حذف حساب المستخدم الحالي."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(UserDetailSerializer(request.user, context={'request': request}).data)

    def post(self, request):
        return self.patch(request)

    @transaction.atomic
    def patch(self, request):
        user = request.user
        if 'first_name' in request.data:
            user.first_name = str(request.data['first_name']).strip()
        if 'last_name' in request.data:
            user.last_name = str(request.data['last_name']).strip()
        if 'phone' in request.data:
            new_phone = str(request.data['phone']).strip()
            if new_phone and User.objects.filter(phone=new_phone).exclude(pk=user.pk).exists():
                return Response({'error': 'رقم الهاتف مستخدم بالفعل.'}, status=status.HTTP_400_BAD_REQUEST)
            user.phone = new_phone
        user.save()

        if user.role == 'teacher' and hasattr(user, 'teacher_profile'):
            tp = user.teacher_profile
            if 'bio' in request.data:
                tp.bio = str(request.data['bio']).strip()
            if 'subject_id' in request.data or 'subject' in request.data:
                sid = request.data.get('subject_id')
                if sid in (None, ''):
                    sid = request.data.get('subject')
                if sid:
                    tp.subject = _resolve_subject_input(sid) or tp.subject
            uploaded_img = request.FILES.get('image') or request.FILES.get('avatar')
            if uploaded_img is not None:
                tp.image = uploaded_img
            elif str(request.data.get('remove_image', '')).lower() in ('1', 'true', 'yes'):
                tp.image = None
            tp.save()
        elif user.role == 'student' and hasattr(user, 'student_profile'):
            sp = user.student_profile
            if 'parent_phone' in request.data:
                sp.parent_phone = str(request.data['parent_phone']).strip()
                sp.save()
        elif user.role == 'assistant' and hasattr(user, 'assistant_profile'):
            ap = user.assistant_profile
            if 'phone' in request.data:
                ap.phone = str(request.data['phone']).strip()
                ap.save()

        record_behavioral_activity(
            request=request,
            user=user,
            installation_id=_extract_installation_id(request),
            activity_type='profile_updated',
            metadata={'role': user.role},
        )
        return Response({
            'message': 'تم تحديث البيانات بنجاح.',
            'user': UserDetailSerializer(user, context={'request': request}).data,
        })

    def delete(self, request):
        user = request.user
        if user.is_superuser:
            return Response({'error': 'لا يمكن حذف حساب المالك.'}, status=status.HTTP_400_BAD_REQUEST)
        record_behavioral_activity(
            request=request,
            user=user,
            installation_id=_extract_installation_id(request),
            activity_type='account_deleted',
            metadata={'email': user.email, 'role': user.role},
        )
        user.delete()
        return Response({'message': 'تم حذف الحساب نهائياً.'}, status=status.HTTP_200_OK)


class ChangePasswordAPIView(APIView):
    """تغيير كلمة المرور للمستخدم المسجل."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        old_password = request.data.get('old_password', '')
        new_password = request.data.get('new_password', '')
        if not old_password or not new_password:
            return Response({'error': 'يرجى إدخال كلمة المرور الحالية والجديدة.'}, status=status.HTTP_400_BAD_REQUEST)
        if not request.user.check_password(old_password):
            return Response({'error': 'كلمة المرور الحالية غير صحيحة.'}, status=status.HTTP_400_BAD_REQUEST)
        if len(new_password) < 6:
            return Response({'error': 'كلمة المرور الجديدة يجب ألا تقل عن 6 أحرف.'}, status=status.HTTP_400_BAD_REQUEST)
        request.user.set_password(new_password)
        request.user.save(update_fields=['password'])
        record_behavioral_activity(
            request=request,
            user=request.user,
            installation_id=_extract_installation_id(request),
            activity_type='password_changed',
        )
        return Response({'message': 'تم تغيير كلمة المرور بنجاح.'})


class ResetPasswordByNationalIdAPIView(APIView):
    """استعادة كلمة المرور عبر التحقق من رقم الهاتف + الرقم القومي (14 رقماً)."""
    permission_classes = [AllowAny]

    def post(self, request):
        phone = str(request.data.get('phone', '')).strip()
        national_id = re.sub(r'\D', '', str(request.data.get('national_id', '')))
        new_password = str(request.data.get('new_password', ''))

        if not phone or not national_id or not new_password:
            return Response({'error': 'يرجى إدخال رقم الهاتف والرقم القومي وكلمة المرور الجديدة.'}, status=status.HTTP_400_BAD_REQUEST)

        if len(new_password) < 6:
            return Response({'error': 'كلمة المرور الجديدة يجب ألا تقل عن 6 أحرف.'}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(phone=phone).first()
        if not user or not user.national_id or str(user.national_id) != national_id:
            return Response({'error': 'بيانات التحقق (رقم الهاتف أو الرقم القومي) غير صحيحة.'}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save(update_fields=['password'])
        record_behavioral_activity(
            request=request,
            user=user,
            installation_id=_extract_installation_id(request),
            activity_type='password_reset_nid',
        )
        return Response({'message': 'تمت إعادة تعيين كلمة المرور بنجاح. يمكنك تسجيل الدخول الآن.'})
