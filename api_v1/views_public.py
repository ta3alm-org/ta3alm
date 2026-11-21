"""
api_v1/views_public.py
نقاط النهاية العامة (الصفحة الرئيسية، الباقات، الدليل، المناهج، الإشعارات، الدفع اليدوي).
"""
import os
from django.db.models import Q
from django.http import FileResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404
from django.views import View
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from core.constants import GRADE_CHOICES, ROLE_CHOICES
from core.models import (
    SiteSetting,
    Subject,
    Notification,
    FCMDeviceToken,
    ManualPayment,
    CurriculumUnit,
    TERM_CHOICES,
)
from core.fcm_service import is_fcm_configured
from core.notifications_service import (
    generate_notif_pull_token,
    verify_notif_pull_token,
)
from teachers.models import TeacherProfile, SubscriptionPlan, CoursePackage

from .permissions import IsNotBanned
from .serializers import (
    SubjectSerializer,
    TeacherCardSerializer,
    SubscriptionPlanSerializer,
    CoursePackageSerializer,
    NotificationSerializer,
    FCMDeviceTokenSerializer,
    ManualPaymentSerializer,
    CurriculumUnitSerializer,
)


class PublicHomeAPIView(APIView):
    """بيانات الصفحة الرئيسية مع فلترة المدرسين حسب الصف والمادة."""
    permission_classes = [AllowAny]

    def get(self, request):
        teachers = TeacherProfile.ordered_for_home()
        q_grade = request.query_params.get('grade', '').strip()
        q_subject = request.query_params.get('subject', '').strip()
        q_search = request.query_params.get('q', '').strip()

        if q_subject:
            teachers = teachers.filter(subject_id=q_subject)
        if q_grade:
            teachers = teachers.filter(groups__grade=q_grade).distinct()
        if q_search:
            teachers = teachers.filter(
                Q(user__first_name__icontains=q_search) | Q(user__last_name__icontains=q_search)
            )

        subjects = Subject.objects.all()
        featured_packages = (
            CoursePackage.objects
            .select_related('teacher__user', 'teacher__subject')
            .filter(
                is_active=True,
                teacher__is_approved=True,
                teacher__user__is_banned=False,
                teacher__current_plan__allow_online_packages=True,
            )
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
        google_web_client_id = (
            os.environ.get('GOOGLE_OAUTH_CLIENT_ID', '').strip()
            or os.environ.get('GOOGLE_CLIENT_ID', '').strip()
        )
        if not google_web_client_id:
            try:
                from allauth.socialaccount.models import SocialApp
                app = SocialApp.objects.filter(provider='google').first()
                if app:
                    google_web_client_id = (app.client_id or '').strip()
            except Exception:
                pass

        site_settings = SiteSetting.load()
        raw_build = (
            request.query_params.get('version_code')
            or request.META.get('HTTP_X_APP_BUILD')
            or ''
        ).strip()
        client_build = int(raw_build) if raw_build.isdigit() else None

        meta = getattr(request, 'META', {}) or {}
        qp = getattr(request, 'query_params', {})
        def _flag(hdr: str, param: str) -> bool:
            v = str(qp.get(param) or meta.get(hdr) or '').strip().lower()
            return v in ('1', 'true', 'yes', 'on')

        client_signals = {
            'vpn_interface_active': _flag('HTTP_X_VPN_ACTIVE', 'vpn_active'),
            'developer_options_enabled': _flag('HTTP_X_DEV_OPTIONS', 'dev_options'),
            'adb_enabled': _flag('HTTP_X_ADB_ENABLED', 'adb_enabled'),
            'proxy_detected': _flag('HTTP_X_PROXY_DETECTED', 'proxy_detected'),
            'port_forwarding_detected': _flag('HTTP_X_PORT_FORWARDING', 'port_forwarding'),
            'abnormal_dns_detected': _flag('HTTP_X_ABNORMAL_DNS', 'abnormal_dns'),
        }
        from .device_security_service import evaluate_boot_security_gate
        resolved_user = request.user if getattr(request.user, 'is_authenticated', False) else None
        boot_gate = evaluate_boot_security_gate(
            request,
            client_signals=client_signals,
            user=resolved_user,
        )

        return Response({
            'subjects': SubjectSerializer(subjects, many=True).data,
            'grades': [{'code': code, 'name': str(label)} for code, label in GRADE_CHOICES],
            'terms': [{'code': code, 'name': str(label)} for code, label in TERM_CHOICES],
            'roles': [{'code': code, 'name': str(label)} for code, label in ROLE_CHOICES],
            'payment_wallets': [
                {'type': 'Vodafone / E-Wallet', 'holder': 'عبدالرحمن طارق', 'number': '01094724932'},
            ],
            'instapay_link': 'https://ipn.eg/S/theboda/instapay/1lnFUL',
            'support_whatsapp': '+201507200894',
            'support_email': 'support@ta3alm.online',
            'google_web_client_id': google_web_client_id,
            'is_maintenance_mode': site_settings.is_maintenance_mode,
            'boot_gate': boot_gate,
            'app_update': site_settings.build_app_update_payload(
                request=request,
                client_version_code=client_build,
            ),
        })


class AppUpdateCheckAPIView(APIView):
    """فحص إصدار تطبيق أندرويد وإرجاع معلومات التحديث الإجباري ورابط ملف التحديث APK."""
    permission_classes = [AllowAny]

    def get(self, request):
        site_settings = SiteSetting.load()
        raw_build = str(
            request.query_params.get('version_code')
            or request.query_params.get('build')
            or request.META.get('HTTP_X_APP_BUILD')
            or ''
        ).strip()
        client_build = int(raw_build) if raw_build.isdigit() else None
        payload = site_settings.build_app_update_payload(
            request=request,
            client_version_code=client_build,
        )
        return Response(payload, status=status.HTTP_200_OK)


class AppUpdateDownloadAPIView(APIView):
    """تنزيل ملف التحديث APK مباشرة من الخادم أو تحويل العميل لرابط التحميل المباشر."""
    permission_classes = [AllowAny]

    def get(self, request):
        site_settings = SiteSetting.load()
        external_url = (site_settings.android_apk_url or '').strip()
        if external_url:
            return HttpResponseRedirect(external_url)

        if site_settings.android_apk_file:
            file_field = site_settings.android_apk_file
            try:
                file_handle = file_field.open('rb')
                version_tag = site_settings.android_latest_version_code or 1
                filename = f"ta3alm-v{version_tag}.apk"
                response = FileResponse(
                    file_handle,
                    as_attachment=True,
                    filename=filename,
                    content_type='application/vnd.android.package-archive',
                )
                return response
            except Exception:
                try:
                    url = file_field.url
                    if url:
                        return HttpResponseRedirect(url)
                except Exception:
                    pass

        return Response(
            {'error': 'ملف التحديث غير مرفوع حالياً على الخادم.', 'code': 'APK_NOT_AVAILABLE'},
            status=status.HTTP_404_NOT_FOUND,
        )


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
    permission_classes = [AllowAny]

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
    """جلب الإشعارات وعدد غير المقروء، مع دعم السحب التدريجي عبر since_id وإصدار رمز المزامنة بالخلفية."""
    permission_classes = [IsAuthenticated, IsNotBanned]

    def get(self, request):
        base_qs = Notification.objects.filter(recipient=request.user)
        unread_count = base_qs.filter(is_read=False).count()
        latest_id = base_qs.order_by('-id').values_list('id', flat=True).first() or 0

        raw_since = (request.query_params.get('since_id') or '').strip()
        unread_only = str(request.query_params.get('unread_only', '')).lower() in ('1', 'true', 'yes')
        try:
            limit = min(max(int(request.query_params.get('limit') or 100), 1), 200)
        except (TypeError, ValueError):
            limit = 100

        qs = base_qs
        if unread_only:
            qs = qs.filter(is_read=False)
        if raw_since.isdigit():
            qs = qs.filter(id__gt=int(raw_since)).order_by('id')
        else:
            qs = qs.order_by('-created_at', '-id')

        return Response({
            'unread_count': unread_count,
            'latest_id': latest_id,
            'notif_sync_token': generate_notif_pull_token(request.user),
            'fcm_configured': is_fcm_configured(),
            'notifications': NotificationSerializer(qs[:limit], many=True).data,
        })


class NotificationBackgroundPullAPIView(APIView):
    """
    نقطة سحب الإشعارات للقراءة فقط لخدمة JobScheduler بالخلفية على الأندرويد.
    تعتمد رمز سحب موقّعاً ومقيداً بالمستخدم دون إتاحة أي عمليات كتابة أو وصول لباقي البيانات.
    """
    permission_classes = [AllowAny]

    def get(self, request):
        token = (
            request.META.get('HTTP_X_TA3ALM_NOTIF_TOKEN')
            or request.query_params.get('token')
            or ''
        ).strip()
        user = verify_notif_pull_token(token)
        if not user:
            return Response(
                {'error': 'رمز مزامنة الإشعارات غير صالح أو منتهي.'},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        base_qs = Notification.objects.filter(recipient=user)
        unread_count = base_qs.filter(is_read=False).count()
        latest_id = base_qs.order_by('-id').values_list('id', flat=True).first() or 0

        raw_since = (request.query_params.get('since_id') or '').strip()
        qs = base_qs.filter(is_read=False)
        if raw_since.isdigit():
            qs = qs.filter(id__gt=int(raw_since)).order_by('id')
        else:
            qs = qs.order_by('-id')

        return Response({
            'unread_count': unread_count,
            'latest_id': latest_id,
            'notifications': NotificationSerializer(qs[:20], many=True).data,
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


class FCMDeviceTokenAPIView(APIView):
    """تسجيل وإلغاء رمز إشعارات Firebase Cloud Messaging (FCM) لجهاز المستخدم الحالي."""
    permission_classes = [IsAuthenticated, IsNotBanned]

    def post(self, request):
        serializer = FCMDeviceTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        token = data['token'].strip()
        installation_id = (
            data.get('installation_id')
            or request.META.get('HTTP_X_DEVICE_ID')
            or ''
        ).strip()[:128]
        platform = data.get('platform') or 'android'
        app_version = (
            data.get('app_version')
            or request.META.get('HTTP_X_APP_VERSION')
            or ''
        ).strip()[:32]

        FCMDeviceToken.objects.update_or_create(
            token=token,
            defaults={
                'user': request.user,
                'installation_id': installation_id,
                'platform': platform,
                'app_version': app_version,
                'is_active': True,
            },
        )
        if installation_id:
            FCMDeviceToken.objects.filter(
                user=request.user,
                installation_id=installation_id,
                is_active=True,
            ).exclude(token=token).update(is_active=False)

        return Response(
            {
                'message': 'تم تسجيل رمز الإشعارات بنجاح.',
                'fcm_configured': is_fcm_configured(),
                'platform': platform,
            },
            status=status.HTTP_200_OK,
        )

    def delete(self, request):
        token = str(
            request.data.get('token')
            or request.query_params.get('token')
            or ''
        ).strip()
        installation_id = str(
            request.data.get('installation_id')
            or request.query_params.get('installation_id')
            or request.META.get('HTTP_X_DEVICE_ID')
            or ''
        ).strip()
        deactivate_all = str(
            request.data.get('all')
            or request.query_params.get('all')
            or ''
        ).lower() in ('1', 'true', 'yes')

        qs = FCMDeviceToken.objects.filter(user=request.user, is_active=True)
        if token and installation_id:
            qs = qs.filter(Q(token=token) | Q(installation_id=installation_id))
        elif token:
            qs = qs.filter(token=token)
        elif installation_id:
            qs = qs.filter(installation_id=installation_id)
        elif not deactivate_all:
            return Response({'deactivated': 0}, status=status.HTTP_200_OK)

        updated = qs.update(is_active=False)
        return Response({'deactivated': updated}, status=status.HTTP_200_OK)


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


def _format_sha256_colons(raw: str) -> str:
    return SiteSetting.format_sha256_colons(raw)


class AndroidAssetLinksView(View):
    """خدمة Digital Asset Links على /.well-known/assetlinks.json لتفعيل Android App Links."""

    def get(self, request):
        package_name = os.environ.get('PLAY_INTEGRITY_PACKAGE_NAME', 'online.ta3alm.ta3alm_flutter').strip() or 'online.ta3alm.ta3alm_flutter'
        try:
            fingerprints = SiteSetting.load().get_assetlinks_fingerprints()
        except Exception:
            raw_fps = (
                os.environ.get('ANDROID_ASSETLINKS_SHA256', '').strip()
                or os.environ.get('ANDROID_RELEASE_CERT_SHA256', '').strip()
                or os.environ.get('ANDROID_DEBUG_CERT_SHA256', '').strip()
            )
            fingerprints = []
            for part in raw_fps.replace('\n', ',').replace(';', ',').split(','):
                formatted = _format_sha256_colons(part.strip())
                if formatted and formatted not in fingerprints:
                    fingerprints.append(formatted)

        packages = [package_name]
        if not package_name.endswith('.debug'):
            packages.append(f'{package_name}.debug')

        payload = [
            {
                'relation': ['delegate_permission/common.handle_all_urls'],
                'target': {
                    'namespace': 'android_app',
                    'package_name': pkg,
                    'sha256_cert_fingerprints': fingerprints,
                },
            }
            for pkg in packages
        ]
        response = JsonResponse(payload, safe=False)
        response['Access-Control-Allow-Origin'] = '*'
        response['Cache-Control'] = 'public, max-age=300'
        return response

