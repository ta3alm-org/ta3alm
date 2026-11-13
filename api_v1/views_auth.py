"""
api_v1/views_auth.py
نقاط النهاية الخاصة بالمصادقة، التسجيل، استكمال الملف الشخصي، وتحديث التوكنات.
"""
from datetime import timedelta
import random
import re
import string

from django.contrib.auth import authenticate, get_user_model
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import StudentProfile
from assistants.models import AssistantProfile
from core.models import Subject
from teachers.models import TeacherProfile, SubscriptionPlan

from .authentication import generate_jwt_pair, decode_jwt_token
from .permissions import IsNotBanned
from .serializers import UserDetailSerializer

User = get_user_model()


class LoginAPIView(APIView):
    """
    تسجيل الدخول عبر البريد الإلكتروني أو رقم الهاتف أو اسم المستخدم أو الكود التعريفي (custom_id).
    يُعيد JWT (access + refresh) + DRF Token + بيانات المستخدم الكاملة.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        identifier = (
            request.data.get('identifier')
            or request.data.get('email')
            or request.data.get('username')
            or request.data.get('phone')
            or ''
        ).strip()
        password = request.data.get('password', '')

        if not identifier or not password:
            return Response(
                {'error': 'يرجى إدخال البريد الإلكتروني/الهاتف/الكود وكلمة المرور.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = authenticate(request, username=identifier, password=password)
        if not user:
            candidate = User.objects.filter(
                Q(email__iexact=identifier)
                | Q(phone=identifier)
                | Q(username__iexact=identifier)
                | Q(custom_id__iexact=identifier)
            ).order_by('id').first()
            if candidate and candidate.check_password(password) and candidate.is_active:
                user = candidate

        if not user:
            return Response(
                {'error': 'بيانات الدخول غير صحيحة. تأكد من البريد/الهاتف وكلمة المرور.'},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        if user.is_banned:
            return Response(
                {
                    'error': 'حسابك محظور من قِبل إدارة المنصة.',
                    'is_banned': True,
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        tokens = generate_jwt_pair(user)
        user_data = UserDetailSerializer(user, context={'request': request}).data
        return Response({
            **tokens,
            'user': user_data,
        }, status=status.HTTP_200_OK)


class RegisterAPIView(APIView):
    """
    إنشاء حساب جديد (طالب، معلم، مساعد) وإصدار التوكن مباشرة.
    """
    permission_classes = [AllowAny]

    @transaction.atomic
    def post(self, request):
        full_name = str(request.data.get('full_name', '')).strip()
        email = str(request.data.get('email', '')).strip().lower()
        phone = str(request.data.get('phone', '')).strip()
        password = str(request.data.get('password', ''))
        confirm_password = str(request.data.get('confirm_password', password))
        role = str(request.data.get('role', 'student')).strip().lower()

        if role not in ('student', 'teacher', 'assistant'):
            return Response({'error': 'نوع الحساب غير صالح.'}, status=status.HTTP_400_BAD_REQUEST)

        if not full_name or not email or not phone or not password:
            return Response({'error': 'جميع الحقول الأساسية مطلوبة.'}, status=status.HTTP_400_BAD_REQUEST)

        if password != confirm_password:
            return Response({'error': 'كلمتا المرور غير متطابقتين.'}, status=status.HTTP_400_BAD_REQUEST)

        if len(password) < 6:
            return Response({'error': 'كلمة المرور يجب ألا تقل عن 6 أحرف.'}, status=status.HTTP_400_BAD_REQUEST)

        if not phone.isdigit() or len(phone) < 11:
            return Response({'error': 'رقم الهاتف يجب أن يتكون من 11 رقماً على الأقل.'}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email__iexact=email).exists():
            return Response({'error': 'هذا البريد الإلكتروني مستخدم بالفعل.'}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(phone=phone).exists():
            return Response({'error': 'رقم الهاتف هذا مستخدم بالفعل.'}, status=status.HTTP_400_BAD_REQUEST)

        parts = full_name.split(' ', 1)
        first_name = parts[0]
        last_name = parts[1] if len(parts) > 1 else ''

        user = User.objects.create_user(
            username=email,
            email=email,
            password=password,
            phone=phone,
            role=role,
            first_name=first_name,
            last_name=last_name,
        )

        tokens = generate_jwt_pair(user)
        user_data = UserDetailSerializer(user, context={'request': request}).data
        return Response({
            'message': 'تم إنشاء الحساب بنجاح! يرجى استكمال بيانات الملف الشخصي.',
            **tokens,
            'user': user_data,
        }, status=status.HTTP_201_CREATED)


class CompleteProfileAPIView(APIView):
    """
    استكمال بيانات الملف الشخصي للطالب أو المعلم أو المساعد (مطابق تماماً لـ accounts.views.complete_profile).
    """
    permission_classes = [IsAuthenticated, IsNotBanned]

    @transaction.atomic
    def post(self, request):
        user = request.user
        full_name = str(request.data.get('full_name', '')).strip()
        national_id = str(request.data.get('national_id', user.national_id or '')).strip()
        phone = str(request.data.get('phone', user.phone or '')).strip()
        password = str(request.data.get('password', '')).strip()

        if not national_id or len(national_id) != 14 or not national_id.isdigit():
            return Response({'error': 'الرقم القومي يجب أن يكون 14 رقماً صحيحاً.'}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(national_id=national_id).exclude(pk=user.pk).exists():
            return Response({'error': 'الرقم القومي مسجل لمستخدم آخر بالفعل.'}, status=status.HTTP_400_BAD_REQUEST)

        if not phone or not phone.isdigit() or len(phone) < 11:
            return Response({'error': 'رقم الهاتف يجب أن يتكون من 11 رقماً على الأقل.'}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(phone=phone).exclude(pk=user.pk).exists():
            return Response({'error': 'رقم الهاتف مسجل لمستخدم آخر بالفعل.'}, status=status.HTTP_400_BAD_REQUEST)

        if full_name:
            parts = full_name.split(' ', 1)
            user.first_name = parts[0]
            user.last_name = parts[1] if len(parts) > 1 else ''

        user.national_id = national_id
        user.phone = phone

        if not user.custom_id:
            chars = string.ascii_uppercase + string.digits
            prefix = {'assistant': 'A', 'teacher': 'T', 'student': 'S'}.get(user.role, 'U')
            user.custom_id = prefix + ''.join(random.choices(chars, k=6))

        if password:
            if len(password) < 6:
                return Response({'error': 'كلمة المرور يجب ألا تقل عن 6 أحرف.'}, status=status.HTTP_400_BAD_REQUEST)
            user.set_password(password)

        user.save()

        if user.role == 'student':
            parent_phone = str(request.data.get('parent_phone', '')).strip()
            if not parent_phone or not parent_phone.isdigit() or len(parent_phone) < 11:
                return Response({'error': 'رقم هاتف ولي الأمر مطلوب ويجب أن يتكون من 11 رقماً.'}, status=status.HTTP_400_BAD_REQUEST)
            StudentProfile.objects.update_or_create(
                user=user,
                defaults={'parent_phone': parent_phone},
            )

        elif user.role == 'teacher':
            subject_id = request.data.get('subject_id') or request.data.get('subject')
            bio = str(request.data.get('bio', '')).strip()
            if not subject_id:
                return Response({'error': 'يرجى اختيار المادة التي تدرسها.'}, status=status.HTTP_400_BAD_REQUEST)
            try:
                subject = Subject.objects.get(id=subject_id)
            except Subject.DoesNotExist:
                return Response({'error': 'المادة المختارة غير موجودة.'}, status=status.HTTP_404_NOT_FOUND)

            default_plan = (
                SubscriptionPlan.objects.filter(is_default=True).first()
                or SubscriptionPlan.objects.order_by('price').first()
            )
            TeacherProfile.objects.update_or_create(
                user=user,
                defaults={
                    'bio': bio,
                    'subject': subject,
                    'subscription_end_date': timezone.now() + timedelta(days=30),
                    'is_trial_used': True,
                    'current_plan': default_plan,
                },
            )

        elif user.role == 'assistant':
            AssistantProfile.objects.update_or_create(
                user=user,
                defaults={'phone': phone},
            )

        return Response({
            'message': f'تم استكمال البيانات بنجاح! أهلاً بك يا {user.first_name}',
            'user': UserDetailSerializer(user, context={'request': request}).data,
        }, status=status.HTTP_200_OK)


class TokenRefreshAPIView(APIView):
    """تحديث Access Token باستخدام Refresh Token."""
    permission_classes = [AllowAny]

    def post(self, request):
        refresh_token = request.data.get('refresh', '')
        if not refresh_token:
            return Response({'error': 'حقل refresh مطلوب.'}, status=status.HTTP_400_BAD_REQUEST)

        payload = decode_jwt_token(refresh_token, expected_type='refresh')
        try:
            user = User.objects.get(id=payload.get('user_id'), is_active=True)
        except User.DoesNotExist:
            return Response({'error': 'المستخدم غير موجود.'}, status=status.HTTP_401_UNAUTHORIZED)

        if user.is_banned:
            return Response({'error': 'الحساب محظور.'}, status=status.HTTP_403_FORBIDDEN)

        tokens = generate_jwt_pair(user)
        return Response(tokens, status=status.HTTP_200_OK)


class LogoutAPIView(APIView):
    """تسجيل الخروج وإلغاء DRF Token."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        Token.objects.filter(user=request.user).delete()
        return Response({'message': 'تم تسجيل الخروج بنجاح.'}, status=status.HTTP_200_OK)


class MeProfileAPIView(APIView):
    """جلب أو تحديث أو حذف حساب المستخدم الحالي."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(UserDetailSerializer(request.user, context={'request': request}).data)

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
                sid = request.data.get('subject_id') or request.data.get('subject')
                if sid:
                    tp.subject = Subject.objects.filter(id=sid).first() or tp.subject
            if 'image' in request.FILES:
                tp.image = request.FILES['image']
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

        return Response({
            'message': 'تم تحديث البيانات بنجاح.',
            'user': UserDetailSerializer(user, context={'request': request}).data,
        })

    def delete(self, request):
        user = request.user
        if user.is_superuser:
            return Response({'error': 'لا يمكن حذف حساب المالك.'}, status=status.HTTP_400_BAD_REQUEST)
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
        return Response({'message': 'تمت إعادة تعيين كلمة المرور بنجاح. يمكنك تسجيل الدخول الآن.'})

