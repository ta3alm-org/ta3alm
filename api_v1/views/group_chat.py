"""
api_v1/views/group_chat.py
نقاط النهاية الخاصة بالشات الجماعي الموحد داخل كل مجموعة دراسية.
"""
from __future__ import annotations

from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from api_v1.permissions import IsNotBanned
from assistants.models import AssistantJob
from core.profanity_filter import handle_chat_profanity_violation
from students.models import Enrollment
from teachers.models import Group, GroupChatMessage


def resolve_group_chat_access(user, group: Group):
    """
    تحديد صلاحية الوصول وإدارة الشات للمستخدم داخل المجموعة.
    Returns: (allowed: bool, is_moderator: bool, role_label: str)
    """
    if user.is_superuser or getattr(user, 'role', '') == 'admin':
        return True, True, 'admin'
    admin_profile = getattr(user, 'admin_profile', None)
    if admin_profile and getattr(admin_profile, 'is_active_admin', False):
        return True, True, 'admin'
    if group.teacher.user_id == user.id:
        return True, True, 'teacher'
    if getattr(user, 'role', '') == 'assistant':
        has_job = AssistantJob.objects.filter(
            assistant__user=user,
            teacher=group.teacher,
            is_active=True,
        ).exists()
        if has_job:
            return True, True, 'assistant'
    if getattr(user, 'role', '') == 'student':
        enrolled = Enrollment.objects.filter(
            group=group,
            student__user=user,
            is_active=True,
        ).exists()
        if enrolled:
            return True, False, 'student'
    return False, False, ''


def serialize_group_chat_message(msg: GroupChatMessage, current_user=None, is_moderator: bool = False) -> dict:
    sender = msg.sender
    if sender.is_superuser or getattr(sender, 'role', '') == 'admin':
        sender_role = 'admin'
        sender_role_display = 'إدارة المنصة'
    elif msg.group.teacher.user_id == sender.id:
        sender_role = 'teacher'
        sender_role_display = 'المعلم'
    elif getattr(sender, 'role', '') == 'assistant':
        sender_role = 'assistant'
        sender_role_display = 'مساعد'
    else:
        sender_role = 'student'
        sender_role_display = 'طالب'

    return {
        'id': msg.id,
        'group_id': msg.group_id,
        'sender_id': msg.sender_id,
        'sender_name': sender.get_full_name() or sender.username,
        'sender_role': sender_role,
        'sender_role_display': sender_role_display,
        'sender_gender': sender.gender,
        'sender_gender_display': sender.get_gender_display() if sender.gender else '',
        'body': msg.body,
        'is_pinned': msg.is_pinned,
        'is_mine': bool(current_user and msg.sender_id == current_user.id),
        'can_delete': bool(current_user and (is_moderator or msg.sender_id == current_user.id)),
        'created_at': msg.created_at.isoformat(),
    }


class GroupChatAPIView(APIView):
    """جلب رسائل الشات الجماعي للمجموعة أو إرسال رسالة / التحكم في القفل والمسح."""
    permission_classes = [IsAuthenticated, IsNotBanned]

    def get(self, request, group_id):
        group = get_object_or_404(Group.objects.select_related('teacher__user'), id=group_id)
        allowed, is_moderator, my_role = resolve_group_chat_access(request.user, group)
        if not allowed:
            return Response(
                {'error': 'غير مصرح لك بدخول شات هذه المجموعة.'},
                status=status.HTTP_403_FORBIDDEN,
            )

        since_raw = request.query_params.get('since_id')
        try:
            limit = min(max(int(request.query_params.get('limit', 100)), 1), 200)
        except (TypeError, ValueError):
            limit = 100

        base_qs = GroupChatMessage.objects.filter(group=group).select_related('sender', 'group__teacher')
        if since_raw is not None:
            try:
                since_id = int(since_raw)
            except (TypeError, ValueError):
                since_id = 0
            msgs = list(base_qs.filter(id__gt=since_id).order_by('id')[:limit])
        else:
            msgs = list(base_qs.order_by('-id')[:limit])
            msgs.reverse()

        pinned_qs = base_qs.filter(is_pinned=True).order_by('-id')[:5]
        pinned_messages = [
            serialize_group_chat_message(m, current_user=request.user, is_moderator=is_moderator)
            for m in pinned_qs
        ]

        return Response({
            'group_id': group.id,
            'group_name': group.name,
            'teacher_name': group.teacher.user.get_full_name() or group.teacher.user.username,
            'is_chat_locked': group.is_chat_locked,
            'is_moderator': is_moderator,
            'my_role': my_role,
            'can_send': bool(is_moderator or not group.is_chat_locked),
            'pinned_messages': pinned_messages,
            'messages': [
                serialize_group_chat_message(m, current_user=request.user, is_moderator=is_moderator)
                for m in msgs
            ],
        })

    def post(self, request, group_id):
        group = get_object_or_404(Group.objects.select_related('teacher__user'), id=group_id)
        allowed, is_moderator, _ = resolve_group_chat_access(request.user, group)
        if not allowed:
            return Response(
                {'error': 'غير مصرح لك بالوصول إلى شات هذه المجموعة.'},
                status=status.HTTP_403_FORBIDDEN,
            )

        action = str(request.data.get('action') or '').strip().lower()
        if action == 'toggle_lock':
            if not is_moderator:
                return Response({'error': 'هذا الإجراء للمعلم أو المساعد أو الإدارة فقط.'}, status=status.HTTP_403_FORBIDDEN)
            explicit_lock = request.data.get('is_locked')
            if explicit_lock is None:
                group.is_chat_locked = not group.is_chat_locked
            else:
                group.is_chat_locked = str(explicit_lock).lower() in ('1', 'true', 'yes')
            group.save(update_fields=['is_chat_locked'])
            return Response({
                'message': 'تم قفل الشات.' if group.is_chat_locked else 'تم فتح الشات.',
                'is_chat_locked': group.is_chat_locked,
            })

        if action == 'clear':
            if not is_moderator:
                return Response({'error': 'مسح الشات للمعلم أو المساعد أو الإدارة فقط.'}, status=status.HTTP_403_FORBIDDEN)
            deleted_count, _ = GroupChatMessage.objects.filter(group=group).delete()
            return Response({
                'message': f'تم مسح الشات ({deleted_count} رسالة).',
                'cleared': True,
                'deleted_count': deleted_count,
            })

        if group.is_chat_locked and not is_moderator:
            return Response(
                {'error': 'الشات مغلق حالياً بواسطة المعلم أو الإدارة.'},
                status=status.HTTP_403_FORBIDDEN,
            )

        body = str(request.data.get('body') or request.data.get('message') or '').strip()
        if not body:
            return Response({'error': 'يرجى كتابة نص الرسالة.'}, status=status.HTTP_400_BAD_REQUEST)
        if len(body) > 2000:
            return Response({'error': 'الرسالة يجب ألا تتجاوز 2000 حرف.'}, status=status.HTTP_400_BAD_REQUEST)

        violated, violation_payload = handle_chat_profanity_violation(
            request,
            request.user,
            body,
            source_label=f'شات المجموعة ({group.name})',
        )
        if violated:
            if violation_payload and violation_payload.get('banned'):
                return Response(violation_payload, status=status.HTTP_403_FORBIDDEN)
            return Response(
                {'error': (violation_payload or {}).get('error') or 'محتوى غير لائق.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        msg = GroupChatMessage.objects.create(
            group=group,
            sender=request.user,
            body=body,
        )
        return Response(
            {
                'message': serialize_group_chat_message(msg, current_user=request.user, is_moderator=is_moderator),
                'is_chat_locked': group.is_chat_locked,
            },
            status=status.HTTP_201_CREATED,
        )


class GroupChatMessageActionAPIView(APIView):
    """تثبيت/إلغاء تثبيت أو حذف رسالة في شات المجموعة."""
    permission_classes = [IsAuthenticated, IsNotBanned]

    def patch(self, request, group_id, message_id):
        group = get_object_or_404(Group.objects.select_related('teacher__user'), id=group_id)
        allowed, is_moderator, _ = resolve_group_chat_access(request.user, group)
        if not allowed or not is_moderator:
            return Response(
                {'error': 'تثبيت الرسائل للمعلم أو المساعد أو الإدارة فقط.'},
                status=status.HTTP_403_FORBIDDEN,
            )

        msg = get_object_or_404(GroupChatMessage, id=message_id, group=group)
        if 'is_pinned' in request.data:
            msg.is_pinned = str(request.data.get('is_pinned')).lower() in ('1', 'true', 'yes')
        else:
            msg.is_pinned = not msg.is_pinned
        msg.save(update_fields=['is_pinned'])
        return Response({
            'message': serialize_group_chat_message(msg, current_user=request.user, is_moderator=True),
        })

    def delete(self, request, group_id, message_id):
        group = get_object_or_404(Group.objects.select_related('teacher__user'), id=group_id)
        allowed, is_moderator, _ = resolve_group_chat_access(request.user, group)
        if not allowed:
            return Response({'error': 'غير مصرح لك.'}, status=status.HTTP_403_FORBIDDEN)

        msg = get_object_or_404(GroupChatMessage, id=message_id, group=group)
        if not is_moderator and msg.sender_id != request.user.id:
            return Response({'error': 'يمكنك حذف رسائلك فقط.'}, status=status.HTTP_403_FORBIDDEN)

        msg.delete()
        return Response({'deleted': True, 'id': message_id})
