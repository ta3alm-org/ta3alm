

const openModals = new Set();

function syncBodyScroll() {
    const anyOverlay = openModals.size > 0 || document.querySelector('.ap-drawer.open');
    document.body.style.overflow = anyOverlay ? 'hidden' : '';
}

export function openModal(modalOrId) {
    const el = typeof modalOrId === 'string' ? document.getElementById(modalOrId) : modalOrId;
    if (!el) return null;
    el.classList.add('open');
    el.setAttribute('aria-hidden', 'false');
    openModals.add(el);
    syncBodyScroll();
    const autofocusEl = el.querySelector('[autofocus], input:not([type="hidden"]), select, textarea');
    if (autofocusEl) {
        setTimeout(() => autofocusEl.focus(), 40);
    }
    return el;
}

export function closeModal(modalOrId) {
    const el = typeof modalOrId === 'string' ? document.getElementById(modalOrId) : modalOrId;
    if (!el) return;
    el.classList.remove('open');
    el.setAttribute('aria-hidden', 'true');
    openModals.delete(el);
    syncBodyScroll();
}

export function initModalTriggers() {
    document.addEventListener('click', (e) => {
        const openTrigger = e.target.closest('[data-modal-open]');
        if (openTrigger) {
            e.preventDefault();
            openModal(openTrigger.dataset.modalOpen);
            return;
        }
        const closeTrigger = e.target.closest('[data-modal-close]');
        if (closeTrigger) {
            e.preventDefault();
            const modal = closeTrigger.closest('.ap-modal');
            if (modal && modal.id !== 'apConfirmModal') closeModal(modal);
        }
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && openModals.size > 0) {
            const top = Array.from(openModals).pop();
            if (top && top.id !== 'apConfirmModal') closeModal(top);
        }
    });
}



export function confirmDialog({
    title = 'تأكيد الإجراء',
    message = 'هل تريد المتابعة؟',
    confirmText = 'تأكيد',
    cancelText = 'إلغاء',
    variant = 'primary',
    promptLabel = '',
    promptPlaceholder = '',
    promptRequired = false,
} = {}) {
    const modal = document.getElementById('apConfirmModal');
    if (!modal) {
        return Promise.resolve({ confirmed: window.confirm(message), value: '' });
    }

    const titleEl = modal.querySelector('[data-confirm-title]');
    const msgEl = modal.querySelector('[data-confirm-message]');
    const promptWrap = modal.querySelector('[data-confirm-prompt-wrap]');
    const promptLabelEl = modal.querySelector('[data-confirm-prompt-label]');
    const promptInput = modal.querySelector('[data-confirm-prompt-input]');
    const confirmBtn = modal.querySelector('[data-confirm-ok]');
    const cancelBtns = modal.querySelectorAll('[data-confirm-cancel]');

    titleEl.textContent = title;
    msgEl.textContent = message;
    confirmBtn.textContent = confirmText;
    confirmBtn.className = `ap-btn ap-btn-${variant === 'danger' ? 'danger' : variant === 'success' ? 'success' : variant === 'warning' ? 'warning' : 'primary'}`;

    const hasPrompt = Boolean(promptLabel);
    promptWrap.classList.toggle('ap-hidden', !hasPrompt);
    promptLabelEl.textContent = promptLabel || '';
    promptInput.placeholder = promptPlaceholder || '';
    promptInput.value = '';
    promptInput.required = Boolean(promptRequired);

    const cancelPrimary = modal.querySelector('[data-confirm-cancel-btn]');
    if (cancelPrimary) cancelPrimary.textContent = cancelText;

    return new Promise((resolve) => {
        const cleanup = () => {
            confirmBtn.removeEventListener('click', onConfirm);
            cancelBtns.forEach((b) => b.removeEventListener('click', onCancel));
            document.removeEventListener('keydown', onKey);
            closeModal(modal);
        };

        const onConfirm = () => {
            const val = promptInput.value.trim();
            if (hasPrompt && promptRequired && !val) {
                promptInput.focus();
                promptInput.classList.add('is-invalid');
                return;
            }
            promptInput.classList.remove('is-invalid');
            cleanup();
            resolve({ confirmed: true, value: val });
        };

        const onCancel = () => {
            cleanup();
            resolve({ confirmed: false, value: '' });
        };

        const onKey = (ev) => {
            if (ev.key === 'Escape') {
                ev.preventDefault();
                onCancel();
            } else if (ev.key === 'Enter' && (!hasPrompt || document.activeElement !== promptInput)) {
                ev.preventDefault();
                onConfirm();
            }
        };

        confirmBtn.addEventListener('click', onConfirm);
        cancelBtns.forEach((b) => b.addEventListener('click', onCancel));
        document.addEventListener('keydown', onKey);
        openModal(modal);
    });
}

export function openImageLightbox(src, title = 'معاينة المرفق') {
    const modal = document.getElementById('apLightboxModal');
    if (!modal || !src) return;
    const titleEl = modal.querySelector('[data-lightbox-title]');
    const imgEl = modal.querySelector('[data-lightbox-img]');
    const extLink = modal.querySelector('[data-lightbox-external]');
    if (titleEl) titleEl.textContent = title;
    if (imgEl) {
        imgEl.src = src;
        imgEl.alt = title;
    }
    if (extLink) extLink.href = src;
    openModal(modal);
}
