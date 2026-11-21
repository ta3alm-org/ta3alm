"""api_v1.views.admin.support
Extracted from api_v1/views_admin.py.
"""

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from core.notifications_service import maybe_notify_zoho_inbox
from dashboard_admin.models import ZohoMailConfig
from services.zoho_mail_service import ZohoMailService
from api_v1.permissions import IsPlatformModerator


class AdminSupportInboxAPIView(APIView):
    """بريد الدعم الفني (Zoho Mail REST API) وإعدادات الربط."""
    permission_classes = [IsAuthenticated, IsPlatformModerator]

    def get(self, request):
        config = ZohoMailConfig.load()
        service = ZohoMailService(config=config)
        message_id = request.query_params.get('message_id', '').strip()
        folder_id = request.query_params.get('folder_id')

        if message_id and service.is_connected():
            try:
                content_data = service.get_message_content(message_id, folder_id=folder_id)
                return Response({'message_detail': content_data})
            except Exception as exc:
                return Response({'error': f'تعذر جلب محتوى الرسالة: {exc}'}, status=status.HTTP_400_BAD_REQUEST)

        messages_list = []
        error_message = None
        if service.is_connected():
            q = request.query_params.get('q', '').strip()
            try:
                res = service.list_messages(limit=25, search_key=q or None)
                raw = res.get('data', []) if isinstance(res, dict) else []
                maybe_notify_zoho_inbox(raw)
                for m in raw:
                    messages_list.append({
                        'messageId': str(m.get('messageId', '')),
                        'folderId': str(m.get('folderId', '')),
                        'fromAddress': m.get('fromAddress', ''),
                        'sender': m.get('sender', m.get('fromAddress', '')),
                        'subject': m.get('subject', '(بدون عنوان)'),
                        'summary': m.get('summary', ''),
                        'receivedTime': m.get('formatted_date', ''),
                        'isRead': m.get('isRead', m.get('status') == '1'),
                    })
            except Exception as exc:
                error_message = str(exc)

        return Response({
            'is_configured': service.is_configured(),
            'is_connected': service.is_connected(),
            'support_email': service.support_email,
            'account_id': config.get_effective_account_id(),
            'api_domain': config.zoho_api_url,
            'accounts_domain': config.zoho_accounts_url,
            'client_id': config.get_effective_client_id(),
            'messages': messages_list,
            'error_message': error_message,
        })

    def post(self, request):
        config = ZohoMailConfig.load()
        service = ZohoMailService(config=config)
        action = request.data.get('action')

        if action == 'save_settings':
            if not request.user.is_superuser:
                return Response({'error': 'إعدادات الربط متاحة للمالك فقط.'}, status=status.HTTP_403_FORBIDDEN)
            config.support_email = str(request.data.get('support_email', config.support_email)).strip() or 'support@ta3alm.online'
            api_url = request.data.get('zoho_api_url') or request.data.get('api_domain') or config.zoho_api_url
            accounts_url = request.data.get('zoho_accounts_url') or request.data.get('accounts_domain') or config.zoho_accounts_url
            config.zoho_api_url = str(api_url).strip() or 'https://mail.zoho.com/api'
            config.zoho_accounts_url = str(accounts_url).strip() or 'https://accounts.zoho.com'
            config.client_id = str(request.data.get('client_id', config.client_id)).strip()
            client_secret = str(request.data.get('client_secret', '')).strip()
            if client_secret:
                config.client_secret = client_secret
            refresh_token = str(request.data.get('refresh_token', '')).strip()
            if refresh_token:
                config.refresh_token = refresh_token
                config.access_token = ''
            account_id = str(request.data.get('account_id', '')).strip()
            if account_id:
                config.account_id = account_id
            config.save()
            return Response({'message': 'تم حفظ إعدادات بريد الدعم Zoho بنجاح.'})

        if not service.is_connected():
            return Response({'error': 'بريد الدعم Zoho غير مربوط حالياً.'}, status=status.HTTP_400_BAD_REQUEST)

        to_address = str(request.data.get('to_address', '')).strip()
        subject = str(request.data.get('subject', '')).strip()
        body_text = str(request.data.get('body', '')).strip()

        if not to_address or not body_text:
            return Response({'error': 'يرجى إدخال البريد المرسل إليه ونص الرسالة.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            body_html = f'<div dir="rtl" style="font-family:Cairo,Tahoma,sans-serif;font-size:15px;line-height:1.8;">{body_text.replace(chr(10), "<br>")}</div>'
            service.compose_new_message(
                to_email=to_address,
                subject=subject or 'رسالة من الدعم الفني - منصة تعلّم',
                content=body_html,
            )
            return Response({'message': f'تم إرسال الرسالة إلى {to_address} بنجاح.'})
        except Exception as exc:
            return Response({'error': f'فشل إرسال البريد: {exc}'}, status=status.HTTP_400_BAD_REQUEST)
