/**
 * المعالج الموحد لنماذج AJAX ([data-ajax-form]) مع التأكيد، منع الإرسال المزدوج، وعرض أخطاء التحقق.
 */
import { api } from '../core/api.js';
import { emit } from '../core/events.js';
import { setButtonLoading } from '../core/loading.js';
import { closeDrawer } from '../core/drawer.js';
import { closeModal, confirmDialog } from '../core/modal.js';
import { toast } from '../core/notifications.js';

function clearFormErrors(form) {
    form.querySelectorAll('.is-invalid').forEach((el) => el.classList.remove('is-invalid'));
    form.querySelectorAll('.ap-field-error[data-ajax-err]').forEach((el) => el.remove());
}

function renderFieldErrors(form, errors) {
    if (!errors || typeof errors !== 'object') return;
    Object.entries(errors).forEach(([fieldName, msgs]) => {
        if (!Array.isArray(msgs) || msgs.length === 0) return;
        const input = form.querySelector(`[name="${CSS.escape(fieldName)}"]`);
        if (input) {
            input.classList.add('is-invalid');
            const errEl = document.createElement('div');
            errEl.className = 'ap-field-error';
            errEl.dataset.ajaxErr = '1';
            errEl.textContent = msgs[0];
            const fieldWrap = input.closest('.ap-field') || input.parentElement;
            if (fieldWrap) fieldWrap.appendChild(errEl);
        }
    });
}

function buildFormData(form, submitter) {
    let fd;
    try {
        fd = submitter ? new FormData(form, submitter) : new FormData(form);
    } catch (_) {
        fd = new FormData(form);
        if (submitter && submitter.name) {
            fd.append(submitter.name, submitter.value || '');
        }
    }
    return fd;
}

export function initAjaxForms() {
    document.addEventListener('submit', async (e) => {
        const form = e.target.closest('form[data-ajax-form]');
        if (!form) return;
        e.preventDefault();

        if (form.dataset.apSubmitting === '1') return;

        const submitter = e.submitter || form.querySelector('button[type="submit"], input[type="submit"]');
        const confirmMsg = submitter?.dataset.confirm || form.dataset.confirm;
        const promptLabel = submitter?.dataset.promptLabel || form.dataset.promptLabel;
        const promptName = submitter?.dataset.promptName || form.dataset.promptName;

        let promptValue = '';
        if (confirmMsg || promptLabel) {
            const res = await confirmDialog({
                title: submitter?.dataset.confirmTitle || form.dataset.confirmTitle || 'تأكيد الإجراء',
                message: confirmMsg || 'هل تريد تأكيد تنفيذ هذا الإجراء؟',
                confirmText: submitter?.dataset.confirmOk || form.dataset.confirmOk || 'تأكيد',
                variant: submitter?.dataset.confirmVariant || form.dataset.confirmVariant || 'primary',
                promptLabel: promptLabel || '',
                promptPlaceholder: submitter?.dataset.promptPlaceholder || form.dataset.promptPlaceholder || '',
                promptRequired: (submitter?.dataset.promptRequired || form.dataset.promptRequired) === '1',
            });
            if (!res.confirmed) return;
            promptValue = res.value || '';
        }

        const fd = buildFormData(form, submitter);
        if (promptName) {
            fd.set(promptName, promptValue);
        }

        clearFormErrors(form);
        form.dataset.apSubmitting = '1';
        setButtonLoading(submitter, true);

        try {
            const actionUrl = form.getAttribute('action') || window.location.pathname;
            const payload = await api.request(actionUrl, {
                method: (form.getAttribute('method') || 'POST').toUpperCase(),
                body: fd,
                form,
            });

            if (payload.message) {
                toast.success(payload.message);
            }

            if (form.dataset.resetOnSuccess === '1') {
                form.reset();
            }

            if (form.dataset.closeOverlay === '1') {
                const modal = form.closest('.ap-modal');
                const drawer = form.closest('.ap-drawer');
                if (modal) closeModal(modal);
                if (drawer) closeDrawer(drawer);
            }

            emit('ap:form:success', { form, submitter, payload });

            if (form.dataset.redirectOnSuccess === '1' && payload.data?.redirect_url) {
                setTimeout(() => {
                    window.location.href = payload.data.redirect_url;
                }, 450);
            }
        } catch (err) {
            if (err.name === 'AbortError') return;
            renderFieldErrors(form, err.errors);
            toast.error(err.message || 'تعذر حفظ التغييرات.');
            emit('ap:form:error', { form, submitter, error: err });
        } finally {
            delete form.dataset.apSubmitting;
            setButtonLoading(submitter, false);
        }
    });
}
