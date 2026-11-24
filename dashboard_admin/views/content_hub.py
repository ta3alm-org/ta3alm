"""
dashboard_admin/views/content_hub.py
مركز إدارة المجموعات والباقات والمحتوى التعليمي لجميع المعلمين (منظم بدون إعادة تحميل).
"""

from decimal import Decimal, InvalidOperation
from django.contrib import messages
from django.db import DataError, transaction
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string

from accounts.models import StudentProfile
from core.constants import GRADE_CHOICES
from dashboard_admin.decorators import admin_required
from dashboard_admin.models import AuditLog
from dashboard_admin.views.ajax import (
    ajax_error,
    ajax_success,
    is_ajax_request,
)
from dashboard_admin.views.base import _base_context
from exams.models import Exam
from students.models import Enrollment, PackageEnrollment
from teachers.models import (
    CoursePackage,
    Group,
    GroupChatMessage,
    Lecture,
    PDFFile,
    TeacherProfile,
)


def _find_student_profile(identifier: str):
    q = str(identifier or '').strip()
    if not q:
        return None
    if q.isdigit():
        by_sp = StudentProfile.objects.filter(id=int(q)).select_related('user').first()
        if by_sp:
            return by_sp
    return (
        StudentProfile.objects.select_related('user')
        .filter(
            Q(user__email__iexact=q)
            | Q(user__phone=q)
            | Q(user__custom_id__iexact=q)
            | Q(user__username__iexact=q)
        )
        .first()
    )


def _hub_respond(request, ok: bool, msg: str, data=None, redirect_to='admin_panel:content_hub', **redirect_kwargs):
    if is_ajax_request(request):
        if ok:
            return ajax_success(msg, data=data or {})
        return ajax_error(msg, data=data or {}, status=400)
    if ok:
        messages.success(request, msg)
    else:
        messages.error(request, msg)
    return redirect(redirect_to, **redirect_kwargs)


def _content_hub_context(request):
    ctx = _base_context(request)
    teacher_id = request.GET.get('teacher', '').strip()
    grade_filter = request.GET.get('grade', '').strip()
    query = request.GET.get('q', '').strip()
    active_tab = request.GET.get('tab', '').strip() or 'groups'
    if active_tab not in ('groups', 'packages'):
        active_tab = 'groups'

    teachers = (
        TeacherProfile.objects.select_related('user', 'subject')
        .annotate(
            groups_count=Count('groups', distinct=True),
            packages_count=Count('packages', distinct=True),
        )
        .order_by('user__first_name', 'user__last_name', 'id')
    )

    groups = (
        Group.objects.select_related('teacher__user', 'teacher__subject')
        .annotate(
            active_students=Count('enrollments', filter=Q(enrollments__is_active=True), distinct=True),
            pending_students=Count('enrollments', filter=Q(enrollments__is_active=False), distinct=True),
            lectures_cnt=Count('lectures', distinct=True),
            exams_cnt=Count('exams', distinct=True),
            pdfs_cnt=Count('pdfs', distinct=True),
            chat_cnt=Count('chat_messages', distinct=True),
        )
        .order_by('-created_at', '-id')
    )

    packages = (
        CoursePackage.objects.select_related('teacher__user', 'teacher__subject')
        .annotate(
            lectures_cnt=Count('lectures', distinct=True),
            exams_cnt=Count('exams', distinct=True),
            pdfs_cnt=Count('pdfs', distinct=True),
            subs_cnt=Count('enrollments', filter=Q(enrollments__is_paid=True), distinct=True),
        )
        .order_by('-created_at', '-id')
    )

    if teacher_id.isdigit():
        tid = int(teacher_id)
        groups = groups.filter(teacher_id=tid)
        packages = packages.filter(teacher_id=tid)
    if grade_filter:
        groups = groups.filter(grade=grade_filter)
        packages = packages.filter(grade=grade_filter)
    if query:
        groups = groups.filter(
            Q(name__icontains=query)
            | Q(teacher__user__first_name__icontains=query)
            | Q(teacher__user__last_name__icontains=query)
            | Q(teacher__user__email__icontains=query)
        )
        packages = packages.filter(
            Q(title__icontains=query)
            | Q(description__icontains=query)
            | Q(teacher__user__first_name__icontains=query)
            | Q(teacher__user__last_name__icontains=query)
        )

    groups_list = list(groups)
    packages_list = list(packages)
    ctx.update({
        'teachers': teachers,
        'groups': groups_list,
        'packages': packages_list,
        'grades': GRADE_CHOICES,
        'selected_teacher': teacher_id,
        'selected_grade': grade_filter,
        'query': query,
        'active_tab': active_tab,
        'hub_stats': {
            'teachers_count': TeacherProfile.objects.count(),
            'groups_count': Group.objects.count(),
            'packages_count': CoursePackage.objects.count(),
            'lectures_count': Lecture.objects.count(),
            'exams_count': Exam.objects.count(),
            'locked_chats_count': Group.objects.filter(is_chat_locked=True).count(),
        },
    })
    return ctx


@admin_required
def manage_content_hub(request):
    valid_grades = {code for code, _ in GRADE_CHOICES}

    if request.method == 'POST':
        action = request.POST.get('action', '').strip()

        if action == 'create_group':
            teacher = get_object_or_404(TeacherProfile, id=request.POST.get('teacher_id'))
            name = request.POST.get('name', '').strip()
            grade = request.POST.get('grade', '').strip()
            if not name or grade not in valid_grades:
                return _hub_respond(request, False, 'يرجى إدخال اسم المجموعة والصف الدراسي الصحيح.')
            group = Group.objects.create(teacher=teacher, name=name[:100], grade=grade)
            AuditLog.log(request, AuditLog.ACTION_EDIT_USER, target_label=f'إنشاء مجموعة: {group.name}', target_id=group.id)
            return _hub_respond(request, True, f'تم إنشاء المجموعة «{group.name}» بنجاح.', data={'group_id': group.id})

        if action == 'update_group':
            group = get_object_or_404(Group, id=request.POST.get('group_id'))
            name = request.POST.get('name', '').strip()
            grade = request.POST.get('grade', '').strip()
            teacher_id = request.POST.get('teacher_id', '').strip()
            if name:
                group.name = name[:100]
            if grade in valid_grades:
                group.grade = grade
            if teacher_id.isdigit():
                group.teacher = get_object_or_404(TeacherProfile, id=int(teacher_id))
            group.save()
            AuditLog.log(request, AuditLog.ACTION_EDIT_USER, target_label=f'تعديل مجموعة: {group.name}', target_id=group.id)
            return _hub_respond(request, True, f'تم تحديث المجموعة «{group.name}».')

        if action == 'delete_group':
            group = get_object_or_404(Group, id=request.POST.get('group_id'))
            name = group.name
            gid = group.id
            group.delete()
            AuditLog.log(request, AuditLog.ACTION_DELETE, target_label=f'حذف مجموعة: {name}', target_id=gid)
            return _hub_respond(request, True, f'تم حذف المجموعة «{name}».')

        if action == 'toggle_group_chat_lock':
            group = get_object_or_404(Group, id=request.POST.get('group_id'))
            group.is_chat_locked = not group.is_chat_locked
            group.save(update_fields=['is_chat_locked'])
            msg = 'تم قفل شات المجموعة.' if group.is_chat_locked else 'تم فتح شات المجموعة.'
            return _hub_respond(request, True, msg, data={'is_chat_locked': group.is_chat_locked})

        if action == 'enroll_student_group':
            group = get_object_or_404(Group, id=request.POST.get('group_id'))
            sp = _find_student_profile(request.POST.get('identifier'))
            if not sp:
                return _hub_respond(request, False, 'لم يتم العثور على طالب بهذا البريد أو الهاتف أو الكود.')
            Enrollment.objects.update_or_create(student=sp, group=group, defaults={'is_active': True})
            return _hub_respond(request, True, f'تم ضم الطالب {sp.user.get_full_name() or sp.user.username} إلى {group.name}.')

        if action == 'create_package':
            teacher = get_object_or_404(TeacherProfile, id=request.POST.get('teacher_id'))
            title = request.POST.get('title', '').strip()
            grade = request.POST.get('grade', '').strip()
            description = request.POST.get('description', '').strip()
            is_active = request.POST.get('is_active') in ('1', 'true', 'on', 'yes')
            try:
                price = max(Decimal(request.POST.get('price', '0').strip() or '0'), Decimal('0'))
            except (InvalidOperation, ValueError):
                price = Decimal('0')
            if not title or grade not in valid_grades:
                return _hub_respond(request, False, 'عنوان الحزمة والصف الدراسي مطلوبان.')
            pkg = CoursePackage.objects.create(
                teacher=teacher,
                title=title[:200],
                grade=grade,
                price=price,
                description=description,
                is_active=is_active,
            )
            AuditLog.log(request, AuditLog.ACTION_EDIT_USER, target_label=f'إنشاء حزمة: {pkg.title}', target_id=pkg.id)
            return _hub_respond(request, True, f'تم إنشاء الحزمة «{pkg.title}» بنجاح.', data={'package_id': pkg.id})

        if action == 'update_package':
            pkg = get_object_or_404(CoursePackage, id=request.POST.get('package_id'))
            title = request.POST.get('title', '').strip()
            grade = request.POST.get('grade', '').strip()
            description = request.POST.get('description', '').strip()
            teacher_id = request.POST.get('teacher_id', '').strip()
            if title:
                pkg.title = title[:200]
            if grade in valid_grades:
                pkg.grade = grade
            pkg.description = description
            if 'price' in request.POST:
                try:
                    pkg.price = max(Decimal(request.POST.get('price', '0').strip() or '0'), Decimal('0'))
                except (InvalidOperation, ValueError):
                    pass
            if teacher_id.isdigit():
                pkg.teacher = get_object_or_404(TeacherProfile, id=int(teacher_id))
            pkg.is_active = request.POST.get('is_active') in ('1', 'true', 'on', 'yes')
            pkg.save()
            AuditLog.log(request, AuditLog.ACTION_EDIT_USER, target_label=f'تعديل حزمة: {pkg.title}', target_id=pkg.id)
            return _hub_respond(request, True, f'تم تحديث الحزمة «{pkg.title}».')

        if action == 'delete_package':
            pkg = get_object_or_404(CoursePackage, id=request.POST.get('package_id'))
            title = pkg.title
            pid = pkg.id
            pkg.delete()
            AuditLog.log(request, AuditLog.ACTION_DELETE, target_label=f'حذف حزمة: {title}', target_id=pid)
            return _hub_respond(request, True, f'تم حذف الحزمة «{title}».')

        if action == 'toggle_package_active':
            pkg = get_object_or_404(CoursePackage, id=request.POST.get('package_id'))
            pkg.is_active = not pkg.is_active
            pkg.save(update_fields=['is_active'])
            msg = 'تم تفعيل الحزمة.' if pkg.is_active else 'تم إيقاف الحزمة.'
            return _hub_respond(request, True, msg, data={'is_active': pkg.is_active})

        if action == 'grant_package_student':
            pkg = get_object_or_404(CoursePackage, id=request.POST.get('package_id'))
            sp = _find_student_profile(request.POST.get('identifier'))
            if not sp:
                return _hub_respond(request, False, 'لم يتم العثور على طالب بهذا البريد أو الهاتف أو الكود.')
            PackageEnrollment.objects.update_or_create(student=sp, package=pkg, defaults={'is_paid': True})
            return _hub_respond(request, True, f'تم تفعيل الحزمة «{pkg.title}» للطالب {sp.user.get_full_name() or sp.user.username}.')

        return _hub_respond(request, False, 'إجراء غير صالح.')

    ctx = _content_hub_context(request)
    if is_ajax_request(request) and request.GET.get('partial') == '1':
        html = render_to_string('admin_panel/partials/_content_hub_body.html', ctx, request=request)
        return ajax_success(
            data={
                'html': html,
                'active_tab': ctx['active_tab'],
                'counts': {
                    'groups': len(ctx['groups']),
                    'packages': len(ctx['packages']),
                },
            }
        )
    return render(request, 'admin_panel/content_hub.html', ctx)


def _group_workspace_context(request, group):
    ctx = _base_context(request)
    active_tab = request.GET.get('tab', '').strip() or 'lectures'
    if active_tab not in ('lectures', 'exams', 'pdfs', 'students', 'chat'):
        active_tab = 'lectures'

    lectures = group.lectures.all().order_by('-created_at', '-id')
    exams = group.exams.annotate(q_count=Count('questions')).order_by('-created_at', '-id')
    pdfs = group.pdfs.all().order_by('-created_at', '-id')
    active_enrollments = group.enrollments.filter(is_active=True).select_related('student__user').order_by('-id')
    pending_enrollments = group.enrollments.filter(is_active=False).select_related('student__user').order_by('-id')
    chat_messages = list(
        GroupChatMessage.objects.filter(group=group).select_related('sender').order_by('-id')[:120]
    )
    chat_messages.reverse()

    ctx.update({
        'group': group,
        'grades': GRADE_CHOICES,
        'teachers': TeacherProfile.objects.select_related('user').order_by('user__first_name', 'id'),
        'lectures': lectures,
        'exams': exams,
        'pdfs': pdfs,
        'active_enrollments': active_enrollments,
        'pending_enrollments': pending_enrollments,
        'chat_messages': chat_messages,
        'active_tab': active_tab,
    })
    return ctx


@admin_required
def admin_group_workspace(request, group_id):
    group = get_object_or_404(Group.objects.select_related('teacher__user', 'teacher__subject'), id=group_id)
    valid_grades = {code for code, _ in GRADE_CHOICES}

    if request.method == 'POST':
        action = request.POST.get('action', '').strip()

        if action == 'update_group':
            name = request.POST.get('name', '').strip()
            grade = request.POST.get('grade', '').strip()
            if name:
                group.name = name[:100]
            if grade in valid_grades:
                group.grade = grade
            group.save()
            return _hub_respond(request, True, 'تم حفظ إعدادات المجموعة.', redirect_to='admin_panel:content_group_workspace', group_id=group.id)

        if action == 'add_lecture':
            title = request.POST.get('title', '').strip()
            video_link = Lecture.normalize_video_link(request.POST.get('video_link', ''))
            description = request.POST.get('description', '').strip()
            if not title or not video_link:
                return _hub_respond(request, False, 'عنوان المحاضرة ورابط الفيديو مطلوبان.', redirect_to='admin_panel:content_group_workspace', group_id=group.id)
            try:
                Lecture.objects.create(group=group, title=title[:200], video_link=video_link, description=description)
            except DataError:
                return _hub_respond(request, False, 'رابط الفيديو أو العنوان أطول من الحد المسموح.', redirect_to='admin_panel:content_group_workspace', group_id=group.id)
            return _hub_respond(request, True, 'تم إضافة المحاضرة للمجموعة.', redirect_to='admin_panel:content_group_workspace', group_id=group.id)

        if action == 'toggle_lecture':
            lec = get_object_or_404(Lecture, id=request.POST.get('lecture_id'), group=group)
            lec.is_active = not lec.is_active
            lec.save(update_fields=['is_active'])
            return _hub_respond(request, True, 'تم تحديث حالة المحاضرة.', redirect_to='admin_panel:content_group_workspace', group_id=group.id)

        if action == 'delete_lecture':
            lec = get_object_or_404(Lecture, id=request.POST.get('lecture_id'), group=group)
            lec.delete()
            return _hub_respond(request, True, 'تم حذف المحاضرة.', redirect_to='admin_panel:content_group_workspace', group_id=group.id)

        if action == 'add_exam':
            title = request.POST.get('title', '').strip()
            try:
                duration = max(int(request.POST.get('duration_minutes', 30)), 1)
            except (TypeError, ValueError):
                duration = 30
            if not title:
                return _hub_respond(request, False, 'يرجى إدخال عنوان الامتحان.', redirect_to='admin_panel:content_group_workspace', group_id=group.id)
            Exam.objects.create(group=group, title=title[:200], duration_minutes=duration, is_active=False)
            return _hub_respond(request, True, 'تم إنشاء الامتحان (مغلق لحين إضافة الأسئلة).', redirect_to='admin_panel:content_group_workspace', group_id=group.id)

        if action == 'toggle_exam':
            exam = get_object_or_404(Exam, id=request.POST.get('exam_id'), group=group)
            exam.is_active = not exam.is_active
            exam.save(update_fields=['is_active'])
            return _hub_respond(request, True, 'تم تحديث حالة الامتحان.', redirect_to='admin_panel:content_group_workspace', group_id=group.id)

        if action == 'delete_exam':
            exam = get_object_or_404(Exam, id=request.POST.get('exam_id'), group=group)
            exam.delete()
            return _hub_respond(request, True, 'تم حذف الامتحان.', redirect_to='admin_panel:content_group_workspace', group_id=group.id)

        if action == 'add_pdf':
            title = request.POST.get('title', '').strip()
            link = request.POST.get('link', '').strip()
            file_obj = request.FILES.get('file')
            if not title or (not link and not file_obj):
                return _hub_respond(request, False, 'عنوان المذكرة والملف أو الرابط مطلوبان.', redirect_to='admin_panel:content_group_workspace', group_id=group.id)
            PDFFile.objects.create(group=group, title=title[:200], link=link or None, file=file_obj)
            return _hub_respond(request, True, 'تم رفع المذكرة للمجموعة.', redirect_to='admin_panel:content_group_workspace', group_id=group.id)

        if action == 'delete_pdf':
            pdf = get_object_or_404(PDFFile, id=request.POST.get('pdf_id'), group=group)
            pdf.delete()
            return _hub_respond(request, True, 'تم حذف المذكرة.', redirect_to='admin_panel:content_group_workspace', group_id=group.id)

        if action == 'enroll_student':
            sp = _find_student_profile(request.POST.get('identifier'))
            if not sp:
                return _hub_respond(request, False, 'لم يتم العثور على الطالب.', redirect_to='admin_panel:content_group_workspace', group_id=group.id)
            Enrollment.objects.update_or_create(student=sp, group=group, defaults={'is_active': True})
            return _hub_respond(request, True, f'تم تفعيل الطالب {sp.user.get_full_name() or sp.user.username} في المجموعة.', redirect_to='admin_panel:content_group_workspace', group_id=group.id)

        if action == 'approve_enrollment':
            en = get_object_or_404(Enrollment, id=request.POST.get('enrollment_id'), group=group)
            en.is_active = True
            en.save(update_fields=['is_active'])
            return _hub_respond(request, True, 'تم قبول الطالب في المجموعة.', redirect_to='admin_panel:content_group_workspace', group_id=group.id)

        if action == 'reject_enrollment':
            en = get_object_or_404(Enrollment, id=request.POST.get('enrollment_id'), group=group)
            en.delete()
            return _hub_respond(request, True, 'تمت إزالة الطالب/الطلب من المجموعة.', redirect_to='admin_panel:content_group_workspace', group_id=group.id)

        if action == 'toggle_chat_lock':
            group.is_chat_locked = not group.is_chat_locked
            group.save(update_fields=['is_chat_locked'])
            msg = 'تم قفل شات المجموعة.' if group.is_chat_locked else 'تم فتح شات المجموعة.'
            return _hub_respond(request, True, msg, redirect_to='admin_panel:content_group_workspace', group_id=group.id)

        if action == 'send_chat_message':
            body = request.POST.get('body', '').strip()
            if not body:
                return _hub_respond(request, False, 'يرجى كتابة الرسالة.', redirect_to='admin_panel:content_group_workspace', group_id=group.id)
            GroupChatMessage.objects.create(group=group, sender=request.user, body=body[:2000])
            return _hub_respond(request, True, 'تم إرسال الرسالة لشات المجموعة.', redirect_to='admin_panel:content_group_workspace', group_id=group.id)

        if action == 'toggle_pin_message':
            msg = get_object_or_404(GroupChatMessage, id=request.POST.get('message_id'), group=group)
            msg.is_pinned = not msg.is_pinned
            msg.save(update_fields=['is_pinned'])
            return _hub_respond(request, True, 'تم تثبيت الرسالة.' if msg.is_pinned else 'تم إلغاء التثبيت.', redirect_to='admin_panel:content_group_workspace', group_id=group.id)

        if action == 'delete_chat_message':
            msg = get_object_or_404(GroupChatMessage, id=request.POST.get('message_id'), group=group)
            msg.delete()
            return _hub_respond(request, True, 'تم حذف الرسالة.', redirect_to='admin_panel:content_group_workspace', group_id=group.id)

        if action == 'clear_chat_messages':
            deleted_cnt, _ = GroupChatMessage.objects.filter(group=group).delete()
            return _hub_respond(request, True, f'تم مسح الشات ({deleted_cnt} رسالة).', redirect_to='admin_panel:content_group_workspace', group_id=group.id)

        return _hub_respond(request, False, 'إجراء غير صالح.', redirect_to='admin_panel:content_group_workspace', group_id=group.id)

    ctx = _group_workspace_context(request, group)
    if is_ajax_request(request) and request.GET.get('partial') == '1':
        html = render_to_string('admin_panel/partials/_content_group_workspace_body.html', ctx, request=request)
        return ajax_success(data={'html': html, 'active_tab': ctx['active_tab']})
    return render(request, 'admin_panel/content_group_workspace.html', ctx)


def _package_workspace_context(request, package):
    ctx = _base_context(request)
    active_tab = request.GET.get('tab', '').strip() or 'content'
    if active_tab not in ('content', 'subscribers'):
        active_tab = 'content'

    enrollments = package.enrollments.filter(is_paid=True).select_related('student__user').order_by('-id')
    teacher_groups = package.teacher.groups.filter(grade=package.grade).prefetch_related('lectures', 'exams')
    ctx.update({
        'package': package,
        'grades': GRADE_CHOICES,
        'lectures': package.lectures.all(),
        'exams': package.exams.annotate(q_count=Count('questions')),
        'pdfs': package.pdfs.all(),
        'enrollments': enrollments,
        'teacher_groups': teacher_groups,
        'active_tab': active_tab,
    })
    return ctx


@admin_required
def admin_package_workspace(request, package_id):
    package = get_object_or_404(CoursePackage.objects.select_related('teacher__user', 'teacher__subject'), id=package_id)
    valid_grades = {code for code, _ in GRADE_CHOICES}

    if request.method == 'POST':
        action = request.POST.get('action', '').strip()

        if action == 'update_package':
            title = request.POST.get('title', '').strip()
            grade = request.POST.get('grade', '').strip()
            description = request.POST.get('description', '').strip()
            if title:
                package.title = title[:200]
            if grade in valid_grades:
                package.grade = grade
            package.description = description
            if 'price' in request.POST:
                try:
                    package.price = max(Decimal(request.POST.get('price', '0').strip() or '0'), Decimal('0'))
                except (InvalidOperation, ValueError):
                    pass
            package.is_active = request.POST.get('is_active') in ('1', 'true', 'on', 'yes')
            package.save()
            return _hub_respond(request, True, 'تم حفظ بيانات الحزمة.', redirect_to='admin_panel:content_package_workspace', package_id=package.id)

        if action == 'add_lecture':
            title = request.POST.get('title', '').strip()
            video_link = Lecture.normalize_video_link(request.POST.get('video_link', ''))
            description = request.POST.get('description', '').strip()
            if not title or not video_link:
                return _hub_respond(request, False, 'عنوان المحاضرة ورابط الفيديو مطلوبان.', redirect_to='admin_panel:content_package_workspace', package_id=package.id)
            try:
                lec = Lecture.objects.create(group=None, title=title[:200], video_link=video_link, description=description)
            except DataError:
                return _hub_respond(request, False, 'رابط الفيديو أو العنوان طويل جداً.', redirect_to='admin_panel:content_package_workspace', package_id=package.id)
            package.lectures.add(lec)
            return _hub_respond(request, True, 'تمت إضافة المحاضرة إلى الحزمة.', redirect_to='admin_panel:content_package_workspace', package_id=package.id)

        if action == 'remove_lecture':
            lec = get_object_or_404(Lecture, id=request.POST.get('lecture_id'))
            package.lectures.remove(lec)
            return _hub_respond(request, True, 'تمت إزالة المحاضرة من الحزمة.', redirect_to='admin_panel:content_package_workspace', package_id=package.id)

        if action == 'add_exam':
            title = request.POST.get('title', '').strip()
            try:
                duration = max(int(request.POST.get('duration_minutes', 30)), 1)
            except (TypeError, ValueError):
                duration = 30
            if not title:
                return _hub_respond(request, False, 'يرجى إدخال عنوان الامتحان.', redirect_to='admin_panel:content_package_workspace', package_id=package.id)
            exam = Exam.objects.create(group=None, title=title[:200], duration_minutes=duration, is_active=False)
            package.exams.add(exam)
            return _hub_respond(request, True, 'تم إنشاء الامتحان في الحزمة.', redirect_to='admin_panel:content_package_workspace', package_id=package.id)

        if action == 'remove_exam':
            exam = get_object_or_404(Exam, id=request.POST.get('exam_id'))
            package.exams.remove(exam)
            return _hub_respond(request, True, 'تمت إزالة الامتحان من الحزمة.', redirect_to='admin_panel:content_package_workspace', package_id=package.id)

        if action == 'add_pdf':
            title = request.POST.get('title', '').strip()
            link = request.POST.get('link', '').strip()
            file_obj = request.FILES.get('file')
            if not title or (not link and not file_obj):
                return _hub_respond(request, False, 'عنوان المذكرة والملف أو الرابط مطلوبان.', redirect_to='admin_panel:content_package_workspace', package_id=package.id)
            pdf = PDFFile.objects.create(group=None, title=title[:200], link=link or None, file=file_obj)
            package.pdfs.add(pdf)
            return _hub_respond(request, True, 'تمت إضافة المذكرة إلى الحزمة.', redirect_to='admin_panel:content_package_workspace', package_id=package.id)

        if action == 'remove_pdf':
            pdf = get_object_or_404(PDFFile, id=request.POST.get('pdf_id'))
            package.pdfs.remove(pdf)
            return _hub_respond(request, True, 'تمت إزالة المذكرة من الحزمة.', redirect_to='admin_panel:content_package_workspace', package_id=package.id)

        if action == 'grant_student':
            sp = _find_student_profile(request.POST.get('identifier'))
            if not sp:
                return _hub_respond(request, False, 'لم يتم العثور على الطالب.', redirect_to='admin_panel:content_package_workspace', package_id=package.id)
            PackageEnrollment.objects.update_or_create(student=sp, package=package, defaults={'is_paid': True})
            return _hub_respond(request, True, f'تم تفعيل الحزمة للطالب {sp.user.get_full_name() or sp.user.username}.', redirect_to='admin_panel:content_package_workspace', package_id=package.id)

        if action == 'revoke_student':
            pe = get_object_or_404(PackageEnrollment, id=request.POST.get('enrollment_id'), package=package)
            pe.delete()
            return _hub_respond(request, True, 'تم إلغاء اشتراك الطالب من الحزمة.', redirect_to='admin_panel:content_package_workspace', package_id=package.id)

        return _hub_respond(request, False, 'إجراء غير صالح.', redirect_to='admin_panel:content_package_workspace', package_id=package.id)

    ctx = _package_workspace_context(request, package)
    if is_ajax_request(request) and request.GET.get('partial') == '1':
        html = render_to_string('admin_panel/partials/_content_package_workspace_body.html', ctx, request=request)
        return ajax_success(data={'html': html, 'active_tab': ctx['active_tab']})
    return render(request, 'admin_panel/content_package_workspace.html', ctx)
