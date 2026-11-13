"""
api_v1/views_public.py
نقاط النهاية العامة (الصفحة الرئيسية، الباقات، الدليل، المناهج، الإشعارات، الدفع اليدوي).
"""
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from core.constants import GRADE_CHOICES, ROLE_CHOICES
from core.models import (
    SiteSetting,
    Subject,
    Notification,
    ManualPayment,
    CurriculumUnit,
    TERM_CHOICES,
)
from teachers.models import TeacherProfile, SubscriptionPlan, CoursePackage

from .permissions import IsNotBanned
from .serializers import (
    SubjectSerializer,
    TeacherCardSerializer,
    SubscriptionPlanSerializer,
    CoursePackageSerializer,
    NotificationSerializer,
    ManualPaymentSerializer,
    CurriculumUnitSerializer,
)


class PublicHomeAPIView(APIView):
    """بيانات الصفحة الرئيسية مع فلترة المدرسين حسب الصف والمادة."""
    permission_classes = [AllowAny]

    def get(self, request):
        teachers = (
            TeacherProfile.objects
            .select_related('user', 'subject', 'current_plan')
            .filter(user__is_banned=False)
            .order_by('-id')
        )
        q_grade = request.query_params.get('grade', '').strip()
        q_subject = request.query_params.get('subject', '').strip()
        q_search = request.query_params.get('q', '').strip()

        if q_subject:
            teachers = teachers.filter(subject_id=q_subject)
        if q_grade:
            teachers = teachers.filter(groups__grade=q_grade).distinct()
        if q_search:
            teachers = teachers.filter(
                user__first_name__icontains=q_search
            ) | teachers.filter(user__last_name__icontains=q_search)

        subjects = Subject.objects.all()
        featured_packages = (
            CoursePackage.objects
            .select_related('teacher__user', 'teacher__subject')
            .filter(is_active=True, teacher__current_plan__allow_online_packages=True)
            .order_by('-created_at')[:6]
        )
        site_settings = SiteSetting.load()

        return Response({
            'is_maintenance_mode': site_settings.is_maintenance_mode,
            'teachers': TeacherCardSerializer(teachers[:12], many=True, context={'request': request}).data,
            'featured_packages': CoursePackageSerializer(featured_packages, many=True, context={'request': request}).data,
            'subjects': SubjectSerializer(subjects, many=True).data,
            'grades': [{'code': code, 'name': str(label)} for code, label in GRADE_CHOICES],
        })


class PublicMetadataAPIView(APIView):
    """قوائم الصفوف الدراسية والمواد والأدوار والترمات وطرق التحويل."""
    permission_classes = [AllowAny]

    def get(self, request):
        subjects = Subject.objects.all()
        return Response({
            'subjects': SubjectSerializer(subjects, many=True).data,
            'grades': [{'code': code, 'name': str(label)} for code, label in GRADE_CHOICES],
            'terms': [{'code': code, 'name': str(label)} for code, label in TERM_CHOICES],
            'roles': [{'code': code, 'name': str(label)} for code, label in ROLE_CHOICES],
            'payment_wallets': [
                {'type': 'Vodafone / E-Wallet', 'holder': 'عبدالرحمن طارق', 'number': '01275192105'},
                {'type': 'Vodafone / E-Wallet', 'holder': 'عبدالرحمن طارق', 'number': '01094724932'},
                {'type': 'InstaPay', 'holder': 'عبدالرحمن طارق', 'number': '01275192105'},
            ],
            'support_whatsapp': '+201507200894',
            'support_email': 'support@ta3alm.online',
        })


class PublicPlansAPIView(APIView):
    """باقات اشتراك المعلمين."""
    permission_classes = [AllowAny]

    def get(self, request):
        plans = SubscriptionPlan.objects.all().order_by('price')
        return Response(SubscriptionPlanSerializer(plans, many=True).data)


class PlatformGuideAPIView(APIView):
    """دليل استخدام المنصة الكامل لجميع الأدوار."""
    permission_classes = [AllowAny]

    def get(self, request):
        return Response({
            'title': 'الدليل الشامل لاستخدام منصة تعلّم',
            'subtitle': 'كل ما تحتاج معرفته عن الأزرار والوظائف والخصائص',
            'sections': [
                {
                    'role': 'teacher',
                    'title': 'دليل المعلم',
                    'items': [
                        {'label': 'إضافة مجموعة', 'description': 'لإنشاء فصل جديد وتحديد الصف الدراسي.'},
                        {'label': 'إضافة محاضرة وأكواد', 'description': 'نشر فيديوهات محمية وتوليد أكواد مشاهدة بعدد مرات محدد.'},
                        {'label': 'الامتحانات الإلكترونية', 'description': 'إنشاء اختبارات بمؤقت زمني وتصحيح تلقائي فوري.'},
                        {'label': 'الرصد الجماعي والغياب', 'description': 'تسجيل درجات الواجب والحصة والتسميع والامتحان الشامل لكل الطلاب دفعة واحدة.'},
                        {'label': 'الحزم والمحفظة', 'description': 'تجميع المحاضرات والامتحانات في كورسات أونلاين وسحب الأرباح عبر فودافون كاش أو إنستا باي.'},
                    ],
                },
                {
                    'role': 'student',
                    'title': 'دليل الطالب',
                    'items': [
                        {'label': 'البحث والانضمام', 'description': 'ابحث عن مدرسك بالصف أو المادة وأرسل طلب انضمام للمجموعة أو اشترك في حزمة أونلاين.'},
                        {'label': 'مشاهدة الدروس', 'description': 'افتح المحاضرة بكود السنتر أو من داخل الحزمة المشترك بها.'},
                        {'label': 'أداء الامتحانات', 'description': 'امتحن أونلاين واعرف درجتك وترتيبك على المجموعة أو الحزمة فوراً.'},
                        {'label': 'متابعة الدرجات', 'description': 'استعرض سجل حضورك ودرجاتك الشهرية الكاملة.'},
                    ],
                },
                {
                    'role': 'assistant',
                    'title': 'دليل المساعد',
                    'items': [
                        {'label': 'البحث عن عمل', 'description': 'ابحث عن المعلم بالاسم أو الكود وأرسل له طلب انضمام كمساعد.'},
                        {'label': 'إدارة المجموعات والحزم', 'description': 'رصد الغياب والدرجات ورفع الفيديوهات والامتحانات حسب الصلاحيات الممنوحة لك.'},
                    ],
                },
            ],
        })


class CurriculumLookupAPIView(APIView):
    """جلب الوحدات والدروس حسب الصف والمادة والترم."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        grade = request.query_params.get('grade')
        subject_id = request.query_params.get('subject')
        term = request.query_params.get('term')

        qs = CurriculumUnit.objects.select_related('subject').prefetch_related('lessons').order_by('order')
        if grade:
            qs = qs.filter(grade=grade)
        if subject_id:
            qs = qs.filter(subject_id=subject_id)
        if term:
            qs = qs.filter(term=term)

        return Response({'units': CurriculumUnitSerializer(qs, many=True).data})


class NotificationsAPIView(APIView):
    """جلب الإشعارات وعدد غير المقروء."""
    permission_classes = [IsAuthenticated, IsNotBanned]

    def get(self, request):
        notifs = Notification.objects.filter(recipient=request.user).order_by('-created_at')
        unread_count = notifs.filter(is_read=False).count()
        return Response({
            'unread_count': unread_count,
            'notifications': NotificationSerializer(notifs[:100], many=True).data,
        })


class MarkNotificationReadAPIView(APIView):
    """تحديد إشعار واحد أو كل الإشعارات كمقروءة."""
    permission_classes = [IsAuthenticated, IsNotBanned]

    def post(self, request, notif_id=None):
        if notif_id:
            notif = get_object_or_404(Notification, id=notif_id, recipient=request.user)
            notif.is_read = True
            notif.save(update_fields=['is_read'])
        else:
            Notification.objects.filter(recipient=request.user, is_read=False).update(is_read=True)

        unread_count = Notification.objects.filter(recipient=request.user, is_read=False).count()
        return Response({'message': 'تم تحديث حالة الإشعارات.', 'unread_count': unread_count})


class ManualCheckoutAPIView(APIView):
    """إرسال طلب دفع يدوي (اشتراك معلم أو شراء حزمة طالب) وعرض طلبات المستخدم السابقة."""
    permission_classes = [IsAuthenticated, IsNotBanned]

    def get(self, request):
        payments = ManualPayment.objects.filter(user=request.user).order_by('-created_at')
        return Response(ManualPaymentSerializer(payments, many=True, context={'request': request}).data)

    def post(self, request):
        payment_type = request.data.get('payment_type')
        target_id = request.data.get('target_id')
        phone_number = str(request.data.get('phone_number', '')).strip()
        receipt_image = request.FILES.get('receipt_image')

        if payment_type not in ('teacher_subscription', 'student_package'):
            return Response({'error': 'نوع عملية الدفع غير صالح.'}, status=status.HTTP_400_BAD_REQUEST)

        if not target_id or not phone_number or not receipt_image:
            return Response(
                {'error': 'يرجى إدخال رقم المحفظة المحول منها وإرفاق صورة إيصال التحويل.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if payment_type == 'teacher_subscription':
            plan = get_object_or_404(SubscriptionPlan, id=target_id)
            amount = plan.price
        else:
            pkg = get_object_or_404(CoursePackage, id=target_id)
            amount = pkg.price

        payment = ManualPayment.objects.create(
            user=request.user,
            payment_type=payment_type,
            target_id=int(target_id),
            amount=amount,
            phone_number=phone_number,
            receipt_image=receipt_image,
        )
        return Response({
            'message': 'تم إرسال طلب الدفع بنجاح. يرجى الانتظار حتى تتم مراجعته من قبل الإدارة.',
            'payment': ManualPaymentSerializer(payment, context={'request': request}).data,
        }, status=status.HTTP_201_CREATED)

