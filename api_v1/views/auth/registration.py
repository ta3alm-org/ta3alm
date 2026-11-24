"""api_v1.views.auth.registration
Extracted from api_v1/views_auth.py.
"""

import random
import string
from django.contrib.auth import get_user_model
from django.db import transaction
from rest_framework import status
from rest_framework.permissions import (
    AllowAny,
    IsAuthenticated,
)
from rest_framework.response import Response
from rest_framework.views import APIView
from accounts.models import StudentProfile
from assistants.models import AssistantProfile
from teachers.models import TeacherProfile
from api_v1.authentication import generate_jwt_pair
from api_v1.permissions import IsNotBanned
from api_v1.serializers import UserDetailSerializer
from api_v1.security_engine import record_behavioral_activity

from api_v1.services.auth_service import (
    _ensure_verification_otp_sent,
    _extract_installation_id,
    _handle_auth_device_registration,
    _notify_admins_teacher_pending,
    _resolve_subject_input,
    ensure_user_role_profile,
)

User = get_user_model()


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
        gender = str(request.data.get('gender', '')).strip().lower()
        password = str(request.data.get('password', ''))
        confirm_password = str(request.data.get('confirm_password', password))
        role = str(request.data.get('role', 'student')).strip().lower()

        if role not in ('student', 'teacher', 'assistant'):
            return Response({'error': 'نوع الحساب غير صالح.'}, status=status.HTTP_400_BAD_REQUEST)

        if gender not in ('male', 'female'):
            return Response({'error': 'يرجى اختيار النوع (ذكر أو أنثى).'}, status=status.HTTP_400_BAD_REQUEST)

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
            gender=gender,
            first_name=first_name,
            last_name=last_name,
        )
        ensure_user_role_profile(user)

        tokens = generate_jwt_pair(user)
        dev_allowed, dev_outcome = _handle_auth_device_registration(request, user, tokens)
        if not dev_allowed:
            err_status = 426 if (dev_outcome or {}).get('code') == 'APP_UPDATE_REQUIRED' else status.HTTP_403_FORBIDDEN
            return Response(dev_outcome, status=err_status)

        requires_verification, otp_sent, otp_err = _ensure_verification_otp_sent(
            request,
            user,
            force_new=True,
        )
        record_behavioral_activity(
            request=request,
            user=user,
            installation_id=_extract_installation_id(request),
            activity_type='register_account',
            metadata={'role': user.role},
        )
        user_data = UserDetailSerializer(user, context={'request': request}).data
        payload = {
            'message': 'تم إنشاء الحساب بنجاح! يرجى إدخال كود التحقق (OTP) المرسل إلى بريدك الإلكتروني لتفعيل الحساب.',
            **tokens,
            'requires_verification': requires_verification,
            'otp_sent': otp_sent,
            'user': user_data,
        }
        if otp_err:
            payload['otp_warning'] = otp_err
        if dev_outcome is not None:
            payload['device_security'] = dev_outcome
        return Response(payload, status=status.HTTP_201_CREATED)


class CompleteProfileAPIView(APIView):
    """
    استكمال بيانات الملف الشخصي للطالب أو المعلم أو المساعد (مطابق تماماً لـ accounts.views.complete_profile).
    """
    permission_classes = [IsAuthenticated, IsNotBanned]

    @transaction.atomic
    def post(self, request):
        user = request.user
        if hasattr(user, 'requires_email_verification') and user.requires_email_verification():
            return Response(
                {
                    'error': 'يرجى تأكيد حسابك برمز التحقق (OTP) أولاً.',
                    'code': 'EMAIL_VERIFICATION_REQUIRED',
                    'requires_verification': True,
                },
                status=status.HTTP_403_FORBIDDEN,
            )
        full_name = str(request.data.get('full_name') or user.get_full_name() or '').strip()
        raw_nid = request.data.get('national_id')
        national_id = str(raw_nid if raw_nid not in (None, '') else (user.national_id or '')).strip()
        raw_phone = request.data.get('phone') if 'phone' in request.data else request.data.get('phone_number')
        phone = str(raw_phone if raw_phone not in (None, '') else (user.phone or '')).strip()
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

        req_role = str(request.data.get('role', '')).strip().lower()
        if req_role in ('student', 'teacher', 'assistant') and not user.custom_id and not user.is_superuser and user.role != 'admin':
            user.role = req_role

        user.national_id = national_id
        user.phone = phone

        if 'gender' in request.data and request.data.get('gender') not in (None, ''):
            raw_gender = str(request.data.get('gender')).strip().lower()
            if raw_gender not in ('male', 'female'):
                return Response({'error': 'يرجى اختيار النوع (ذكر أو أنثى).'}, status=status.HTTP_400_BAD_REQUEST)
            user.gender = raw_gender
        elif not user.is_superuser and user.role != 'admin' and user.gender not in ('male', 'female'):
            return Response({'error': 'يرجى اختيار النوع (ذكر أو أنثى).'}, status=status.HTTP_400_BAD_REQUEST)

        if not user.custom_id:
            chars = string.ascii_uppercase + string.digits
            prefix = {'assistant': 'A', 'teacher': 'T', 'student': 'S'}.get(user.role, 'U')
            user.custom_id = prefix + ''.join(random.choices(chars, k=6))

        if password:
            if len(password) < 6:
                return Response({'error': 'كلمة المرور يجب ألا تقل عن 6 أحرف.'}, status=status.HTTP_400_BAD_REQUEST)
            user.set_password(password)

        user.save()

        pending_teacher_review = False
        if user.role == 'student':
            parent_phone = str(request.data.get('parent_phone', '')).strip()
            if not parent_phone or not parent_phone.isdigit() or len(parent_phone) < 11:
                return Response({'error': 'رقم هاتف ولي الأمر مطلوب ويجب أن يتكون من 11 رقماً.'}, status=status.HTTP_400_BAD_REQUEST)
            StudentProfile.objects.update_or_create(
                user=user,
                defaults={'parent_phone': parent_phone},
            )

        elif user.role == 'teacher':
            raw_subject = request.data.get('subject_id')
            if raw_subject in (None, ''):
                raw_subject = request.data.get('subject')
            bio = str(request.data.get('bio', '')).strip()
            if not raw_subject:
                if hasattr(user, 'teacher_profile') and user.teacher_profile.subject_id:
                    subject = user.teacher_profile.subject
                else:
                    return Response({'error': 'يرجى اختيار المادة التي تدرسها.'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                subject = _resolve_subject_input(raw_subject)
                if subject is None:
                    return Response({'error': 'المادة المختارة غير موجودة.'}, status=status.HTTP_404_NOT_FOUND)

            uploaded_image = request.FILES.get('image') or request.FILES.get('avatar')
            has_existing_image = hasattr(user, 'teacher_profile') and bool(user.teacher_profile.image)
            if uploaded_image is None and not has_existing_image:
                return Response(
                    {
                        'error': 'يرجى رفع الصورة الشخصية للمعلم (الصورة الشخصية ورقم الهاتف إجباريان لجميع المعلمين).',
                        'code': 'TEACHER_IMAGE_REQUIRED',
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # لا يُمنح المعلم باقة أو ظهوراً مباشراً عند التسجيل؛ يظل قيد المراجعة حتى موافقة الإدارة
            defaults = {
                'bio': bio,
                'subject': subject,
                'is_approved': False,
                'subscription_end_date': None,
                'is_trial_used': False,
                'current_plan': None,
            }
            if uploaded_image is not None:
                defaults['image'] = uploaded_image

            tp, created = TeacherProfile.objects.get_or_create(
                user=user,
                defaults=defaults,
            )
            if not created:
                tp.bio = bio or tp.bio
                tp.subject = subject
                update_fields = ['bio', 'subject']
                if uploaded_image is not None:
                    tp.image = uploaded_image
                    update_fields.append('image')
                tp.save(update_fields=update_fields)
            if created or not tp.is_approved:
                pending_teacher_review = True
                _notify_admins_teacher_pending(tp)

        elif user.role == 'assistant':
            AssistantProfile.objects.update_or_create(
                user=user,
                defaults={'phone': phone},
            )

        record_behavioral_activity(
            request=request,
            user=user,
            installation_id=_extract_installation_id(request),
            activity_type='complete_profile',
            metadata={'role': user.role, 'pending_teacher_review': pending_teacher_review},
        )
        msg = (
            'تم إرسال طلب انضمامك كمعلم بنجاح! حسابك الآن قيد المراجعة من قِبل الإدارة وسيتم تفعيله وإشعارك فور الموافقة.'
            if pending_teacher_review
            else f'تم استكمال البيانات بنجاح! أهلاً بك يا {user.first_name}'
        )
        return Response({
            'message': msg,
            'pending_teacher_review': pending_teacher_review,
            'user': UserDetailSerializer(user, context={'request': request}).data,
        }, status=status.HTTP_200_OK)
