"""
dashboard_admin/views/ajax.py
أدوات مساعدة موحّدة لطلبات AJAX واستجابات JSON في لوحة الإدارة.
"""

from django.http import JsonResponse


def is_ajax_request(request):
    """التحقق مما إذا كان الطلب مرسلاً عبر AJAX / Fetch API أو يطلب JSON."""
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return True
    accept = request.headers.get('Accept', '')
    return 'application/json' in accept


def ajax_success(message='', data=None, status=200):
    """إرجاع استجابة JSON قياسية للعمليات الناجحة."""
    return JsonResponse(
        {
            'success': True,
            'message': message or '',
            'data': data if data is not None else {},
            'errors': {},
        },
        status=status,
    )


def ajax_error(message='حدث خطأ أثناء تنفيذ العملية.', errors=None, status=400, data=None):
    """إرجاع استجابة JSON قياسية للأخطاء والصلاحيات والتحقق."""
    return JsonResponse(
        {
            'success': False,
            'message': message or 'حدث خطأ غير متوقع.',
            'data': data if data is not None else {},
            'errors': errors or {},
        },
        status=status,
    )


def form_errors_dict(form, prefix=''):
    """تحويل أخطاء Django Form إلى قاموس {field_name: [messages]}."""
    result = {}
    if form is None:
        return result
    try:
        json_errors = form.errors.get_json_data()
    except Exception:
        return result

    for field, items in json_errors.items():
        key = f'{prefix}{field}' if (prefix and field != '__all__') else field
        result[key] = [item.get('message', '') for item in items if item.get('message')]
    return result


def formset_errors_list(formset):
    """استخراج رسائل الأخطاء من Inline Formset للعرض الموحّد."""
    messages_list = []
    field_errors = {}
    if formset is None:
        return messages_list, field_errors

    for non_form_err in formset.non_form_errors():
        messages_list.append(str(non_form_err))

    for idx, f_err in enumerate(formset.errors):
        if not f_err:
            continue
        for field, errs in f_err.items():
            key = f'{formset.prefix}-{idx}-{field}'
            msgs = [str(e) for e in errs]
            field_errors[key] = msgs
            messages_list.extend(msgs)

    return messages_list, field_errors
