"""students.views.groups
Extracted from students/views.py.
"""

from django.shortcuts import (
    render,
    redirect,
    get_object_or_404,
)
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from teachers.models import (
    Lecture,
    VideoCode,
)
from exams.models import (
    Exam,
    ExamResult,
)
from students.models import PerformanceLog
from django.db import transaction
import json as _json
from django.http import JsonResponse as _JsonResponse
from django.views.decorators.http import require_POST as _require_POST

from students.views.access import (
    _clear_student_web_watch_state,
    calculate_leaderboard,
    check_student_access,
)


# ==========================================
# 1. صفحة المحاضرات (الرئيسية للمجموعة)
# ==========================================
@login_required
def student_group_content(request, group_id):
    _clear_student_web_watch_state(request)
    group, status = check_student_access(request.user, group_id)
    
    if status == "teacher_expired":
        return render(request, 'students/teacher_unavailable.html', {'teacher_name': group.teacher.user.first_name})
    elif status == "limit_exceeded": # <--- الحالة الجديدة
        return render(request, 'students/teacher_full.html', {'teacher_name': group.teacher.user.first_name})
    elif status != "ok":
        return redirect('student_dashboard')

    lectures = group.lectures.filter(is_active=True).order_by('-created_at')
    
    # معرفة الفيديوهات التي فتحها الطالب بالفعل
    unlocked_lectures = VideoCode.objects.filter(
        used_by=request.user.student_profile, 
        lecture__group=group
    ).values_list('lecture_id', flat=True)

    from api_v1.device_security_service import check_web_ios_only_lecture_access
    ios_access = check_web_ios_only_lecture_access(request, request.user, force_web=True)
    web_lectures_allowed = bool(ios_access.get('allowed'))

    context = {
        'group': group,
        'lectures': lectures if web_lectures_allowed else [],
        'unlocked_ids': unlocked_lectures if web_lectures_allowed else [],
        'web_lectures_allowed': web_lectures_allowed,
        'web_lectures_block_reason': '' if web_lectures_allowed else (ios_access.get('error') or ''),
        'web_lectures_needs_ipad_probe': bool(ios_access.get('needs_ipad_probe')) if not web_lectures_allowed else False,
        'active_tab': 'content'
    }
    return render(request, 'students/group_content.html', context)


# ==========================================
# 2. مشاهدة محاضرة (إدخال الكود)
# ==========================================
@login_required
def student_watch_lecture(request, lecture_id):
    lecture = get_object_or_404(Lecture, id=lecture_id)
    group, status = check_student_access(request.user, lecture.group.id)
    
    if status != "ok": return redirect('student_dashboard')

    from api_v1.device_security_service import check_web_ios_only_lecture_access
    ios_access = check_web_ios_only_lecture_access(request, request.user, force_web=True)
    if not ios_access.get('allowed'):
        return render(
            request,
            'students/web_lectures_blocked.html',
            {
                'group': group,
                'block_reason': ios_access.get('error') or '',
                'needs_ipad_probe': bool(ios_access.get('needs_ipad_probe')),
            },
            status=403,
        )

    student = request.user.student_profile
    
    # جلب الكود المستخدم (إن وجد) الأحدث
    active_code = VideoCode.objects.filter(lecture=lecture, used_by=student).order_by('-used_at').first()
    
    # 1. التحقق من السماح بالمشاهدة
    from api_v1.video_security import (
        get_active_watch_window_expiry,
        grant_watch_window,
    )
    watch_window_exp = get_active_watch_window_expiry(request.user, lecture.id)
    is_currently_viewing = watch_window_exp is not None
    is_unlocked = False
    if active_code:
        request.session.pop(f"viewed_lec_{lecture.id}_{active_code.id}", None)
        # إذا لم يكن في نافذة المشاهدة الحالية، وتجاوز الحد المسموح
        if active_code.current_views >= active_code.max_views and not (
            is_currently_viewing and active_code.current_views <= active_code.max_views
        ):
            messages.error(request, "لقد استهلكت عدد مرات مشاهدة هذا الفيديو. يرجى شراء كود جديد.")
            is_unlocked = False
        else:
            is_unlocked = True

    # 2. معالجة إدخال كود جديد (POST)
    if request.method == 'POST':
        # لو الفيديو مفتوح ولسه فيه مشاهدات، ليه يدخل كود؟
        if is_unlocked: 
            return redirect('student_watch_lecture', lecture_id=lecture.id)

        code_input = request.POST.get('code', '').strip()
        try:
            # نبحث عن كود جديد، سليم، وغير مستخدم
            new_code = VideoCode.objects.get(code=code_input, lecture=lecture, is_used=False)
            
            # تفعيل الكود الجديد
            new_code.is_used = True
            new_code.used_by = student
            new_code.used_at = timezone.now()
            # لا نزيد العداد هنا لأن الـ GET redirect سيتكفل به
            new_code.save()
            
            messages.success(request, "تم تفعيل الكود بنجاح!")
            return redirect('student_watch_lecture', lecture_id=lecture.id)
            
        except VideoCode.DoesNotExist:
            messages.error(request, "الكود غير صحيح أو مستخدم من قبل.")

    playback_ctx = {}
    if is_unlocked:
        from django.utils.translation import gettext as _
        from api_v1.device_security_service import enforce_web_lecture_playback
        from api_v1.models import PlaybackSession
        playback_res = enforce_web_lecture_playback(request, request.user, lecture)
        if not playback_res.get('allowed'):
            messages.error(request, playback_res.get('error') or _("هذا المتصفح غير مخوّل لتشغيل المحاضرة."))
            return redirect('web_trusted_devices')
        if request.method == 'GET' and active_code and not is_currently_viewing:
            with transaction.atomic():
                locked_code = VideoCode.objects.select_for_update().get(pk=active_code.pk)
                if locked_code.current_views >= locked_code.max_views:
                    messages.error(request, "لقد استهلكت عدد مرات مشاهدة هذا الفيديو. يرجى شراء كود جديد.")
                    is_unlocked = False
                else:
                    locked_code.current_views += 1
                    locked_code.save(update_fields=['current_views'])
                    active_code = locked_code
                    watch_window_exp = grant_watch_window(request.user, lecture.id)
        if is_unlocked and playback_res.get('playback_session_uuid') and watch_window_exp is not None:
            PlaybackSession.objects.filter(
                session_id=playback_res.get('playback_session_uuid')
            ).update(view_window_expires_at=watch_window_exp)
        playback_ctx = {
            'playback_session_uuid': playback_res.get('playback_session_uuid', ''),
            'web_installation_id': playback_res.get('installation_id', ''),
            'watermark': playback_res.get('watermark', {}),
        }

    return render(request, 'students/watch_lecture.html', {
        'lecture': lecture,
        'group': group,
        'is_unlocked': is_unlocked,
        'active_code': active_code, # لنعرض له (المتبقي: X)
        **playback_ctx,
    })


@login_required
@_require_POST
def web_lecture_heartbeat(request, lecture_id):
    """
    نبض جلسة المشاهدة على الويب: يتحقق من بقاء المتصفح مخوّلاً ومن عدم فتح نفس المحاضرة
    من جهاز أو متصفح آخر، ويمدّد صلاحية الجلسة النشطة.
    """
    from api_v1.device_security_service import check_web_ios_only_lecture_access
    ios_access = check_web_ios_only_lecture_access(request, request.user, force_web=True)
    if not ios_access.get('allowed'):
        return _JsonResponse(
            {
                'ok': False,
                'error': ios_access.get('error') or 'المحاضرات عبر الويب متاحة فقط على iPhone و iPad.',
                'code': ios_access.get('code') or 'WEB_LECTURES_IOS_ONLY',
            },
            status=403,
        )
    from datetime import timedelta as _td
    from django.utils import timezone as _tz
    from django.utils.translation import gettext as _
    from api_v1.device_security_service import check_device_allowed, get_or_create_web_installation_id
    from api_v1.models import PlaybackSession

    session_id = ''
    if request.content_type and 'application/json' in request.content_type:
        try:
            data = _json.loads((request.body or b'{}').decode('utf-8'))
            if isinstance(data, dict):
                session_id = str(data.get('session_id') or '').strip()
        except Exception:
            session_id = ''
    if not session_id:
        session_id = str(request.POST.get('session_id') or '').strip()

    installation_id = get_or_create_web_installation_id(request)
    allowed, code, err = check_device_allowed(request.user, installation_id)
    if not allowed:
        return _JsonResponse({
            'ok': False,
            'code': code or 'DEVICE_NOT_ALLOWED',
            'error': err or _("تم إيقاف تصريح هذا المتصفح."),
        }, status=409)

    if not session_id:
        return _JsonResponse({'ok': False, 'code': 'MISSING_SESSION'}, status=400)

    try:
        playback_session = PlaybackSession.objects.filter(
            session_id=session_id,
            user=request.user,
            lecture_id=lecture_id,
        ).first()
    except Exception:
        playback_session = None

    if playback_session is None:
        return _JsonResponse({'ok': False, 'code': 'SESSION_NOT_FOUND'}, status=404)

    now = _tz.now()
    if playback_session.status != 'active':
        return _JsonResponse({
            'ok': False,
            'code': 'SESSION_REVOKED',
            'error': playback_session.revoked_reason or _("تم إيقاف هذه الجلسة لأن المحاضرة فُتحت من جهاز آخر."),
        }, status=409)

    if playback_session.expires_at and playback_session.expires_at <= now:
        playback_session.status = 'expired'
        playback_session.save(update_fields=['status'])
        return _JsonResponse({
            'ok': False,
            'code': 'SESSION_EXPIRED',
            'error': _("انتهت صلاحية جلسة المشاهدة، يرجى تحديث الصفحة."),
        }, status=409)

    playback_session.last_heartbeat_at = now
    if playback_session.expires_at is None or playback_session.expires_at < now + _td(minutes=10):
        playback_session.expires_at = now + _td(minutes=10)
        playback_session.save(update_fields=['last_heartbeat_at', 'expires_at'])
    else:
        playback_session.save(update_fields=['last_heartbeat_at'])

    return _JsonResponse({'ok': True, 'status': 'active'})


@login_required
def web_lecture_end(request, lecture_id):
    """إنهاء نافذة وجلسة المشاهدة على الويب فوراً عند إغلاق الصفحة أو الرجوع للخلف."""
    if request.method != 'POST':
        return _JsonResponse({'ok': False}, status=405)

    from api_v1.models import PlaybackSession
    from api_v1.video_security import clear_watch_window

    session_id = ''
    if request.content_type and 'application/json' in request.content_type:
        try:
            data = _json.loads((request.body or b'{}').decode('utf-8'))
            if isinstance(data, dict):
                session_id = str(data.get('session_id') or '').strip()
        except Exception:
            session_id = ''
    if not session_id:
        session_id = str(request.POST.get('session_id') or '').strip()

    now = timezone.now()
    if session_id:
        PlaybackSession.objects.filter(
            session_id=session_id,
            user=request.user,
            lecture_id=lecture_id,
            status='active',
        ).update(status='ended', revoked_reason='web_page_exit', view_window_expires_at=now)

    clear_watch_window(request.user, lecture_id=lecture_id, now=now)
    return _JsonResponse({'ok': True})


# ==========================================
# 3. قائمة الامتحانات
# ==========================================
@login_required
def student_group_exams(request, group_id):
    group, status = check_student_access(request.user, group_id)
    if status == "teacher_expired": return render(request, 'students/teacher_unavailable.html', {'teacher_name': group.teacher.user.first_name})
    elif status != "ok": return redirect('student_dashboard')

    # الامتحانات المفعلة فقط
    exams = group.exams.filter(is_active=True).order_by('-created_at')
    
    # الامتحانات التي دخلها الطالب سابقاً
    taken_exam_ids = ExamResult.objects.filter(
        student=request.user.student_profile, 
        exam__group=group
    ).values_list('exam_id', flat=True)

    context = {
        'group': group,
        'exams': exams,
        'taken_ids': taken_exam_ids,
        'active_tab': 'exams'
    }
    return render(request, 'students/group_exams.html', context)


# ==========================================
# 4. أداء الامتحان
# ==========================================
@login_required
def student_take_exam(request, exam_id):
    exam = get_object_or_404(Exam, id=exam_id)
    group, status = check_student_access(request.user, exam.group.id)
    
    if status == "teacher_expired": return render(request, 'students/teacher_unavailable.html', {'teacher_name': group.teacher.user.first_name})
    elif status != "ok": return redirect('student_dashboard')

    student = request.user.student_profile

    # منع الدخول إذا كان الامتحان مغلقاً أو تم أداؤه
    if not exam.is_active:
        messages.error(request, "هذا الامتحان مغلق حالياً.")
        return redirect('student_group_exams', group_id=group.id)
    
    if ExamResult.objects.filter(student=student, exam=exam).exists():
        messages.info(request, "لقد قمت بأداء هذا الامتحان مسبقاً.")
        return redirect('student_group_exams', group_id=group.id)

    # معالجة الإجابات (التصحيح)
    if request.method == 'POST':
        score = 0
        questions = exam.questions.all()
        
        for q in questions:
            # اسم الحقل في الفورم هو question_ID
            selected_option = request.POST.get(f'question_{q.id}')
            if selected_option == q.correct_answer:
                score += q.marks
        
        # حفظ النتيجة
        ExamResult.objects.create(student=student, exam=exam, score=score)
        
        messages.success(request, f"تم تسليم الامتحان. درجتك: {score} / {exam.total_marks()}")
        return redirect('student_group_exams', group_id=group.id)

    questions = exam.questions.all()
    return render(request, 'students/take_exam.html', {'exam': exam, 'questions': questions})


# ==========================================
# 5. درجاتي (السجل)
# ==========================================
@login_required
def student_group_marks(request, group_id):
    group, status = check_student_access(request.user, group_id)
    if status == "teacher_expired": return render(request, 'students/teacher_unavailable.html', {'teacher_name': group.teacher.user.first_name})
    elif status != "ok": return redirect('student_dashboard')

    # سجلات الأداء (واجب، حصة، غياب)
    logs = PerformanceLog.objects.filter(student=request.user.student_profile, group=group).order_by('-date')
    
        # +++++ فلتر الشهر +++++
    selected_month = request.GET.get('month')
    if selected_month:
        logs = logs.filter(date__month=selected_month)
    # ++++++++++++++++++++++

    # نتائج الامتحانات الإلكترونية
    exam_results = ExamResult.objects.filter(student=request.user.student_profile, exam__group=group).order_by('-submitted_at')

    context = {
        'group': group,
        'logs': logs,
        'exam_results': exam_results,
        'active_tab': 'marks',
        'selected_month': selected_month
    }
    return render(request, 'students/group_marks.html', context)


# ==========================================
# صفحة الترتيب للطالب (الدالة الناقصة)
# ==========================================
@login_required
def student_group_ranking(request, group_id):
    group, status = check_student_access(request.user, group_id)
    if status != "ok": return redirect('student_dashboard')

    leaderboard = calculate_leaderboard(group)
    
    # معرفة ترتيب الطالب الحالي
    my_rank = next((item['rank'] for item in leaderboard if item['student'] == request.user.student_profile), '-')

    # عرض أول 20 طالب فقط
    return render(request, 'students/group_ranking.html', {
        'group': group,
        'leaderboard': leaderboard[:20], 
        'my_rank': my_rank,
        'active_tab': 'ranking'
    })


@login_required
def student_group_contact(request, group_id):
    group, status = check_student_access(request.user, group_id)
    if status != "ok": return redirect('student_dashboard')
    
    teacher = group.teacher
    # جلب المساعدين النشطين
    assistants = teacher.assistants_jobs.filter(is_active=True).select_related('assistant__user')
    
    return render(request, 'students/group_contact.html', {
        'group': group,
        'teacher': teacher,
        'assistants': assistants,
        'active_tab': 'contact' # أضف تاب جديد في الناف بار
    })


# ملفات المجموعة
@login_required
def student_group_files(request, group_id):
    group, status = check_student_access(request.user, group_id)
    if status != "ok": return redirect('student_dashboard')

    pdfs = group.pdfs.all().order_by('-created_at')

    return render(request, 'students/group_files.html', {
        'group': group,
        'pdfs': pdfs,
        'active_tab': 'files' # تفعيل التبويب
    })
