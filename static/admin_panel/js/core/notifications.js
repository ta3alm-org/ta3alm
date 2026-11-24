

const ICON_BY_VARIANT = {
    success: 'bi-check-circle-fill',
    warning: 'bi-exclamation-triangle-fill',
    danger: 'bi-x-circle-fill',
    error: 'bi-x-circle-fill',
    info: 'bi-info-circle-fill',
};

function getStack() {
    return document.getElementById('apToastStack');
}

function normalizeVariant(variant) {
    if (!variant) return 'info';
    if (variant === 'error') return 'danger';
    if (['success', 'warning', 'danger', 'info'].includes(variant)) return variant;
    return 'info';
}

export function showToast(message, variant = 'info', duration = 4800) {
    if (!message) return null;
    const stack = getStack();
    if (!stack) return null;

    const kind = normalizeVariant(variant);
    const toast = document.createElement('div');
    toast.className = `ap-toast is-${kind}`;
    toast.setAttribute('role', kind === 'danger' ? 'alert' : 'status');

    const icon = document.createElement('i');
    icon.className = `bi ${ICON_BY_VARIANT[kind] || 'bi-info-circle-fill'} ap-toast-icon`;

    const msg = document.createElement('div');
    msg.className = 'ap-toast-msg';
    msg.textContent = String(message);

    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'ap-toast-close';
    closeBtn.setAttribute('aria-label', 'إغلاق');
    const closeIcon = document.createElement('i');
    closeIcon.className = 'bi bi-x-lg';
    closeBtn.appendChild(closeIcon);

    const remove = () => {
        if (toast.isConnected) toast.remove();
    };
    closeBtn.addEventListener('click', remove);

    toast.appendChild(icon);
    toast.appendChild(msg);
    toast.appendChild(closeBtn);
    stack.appendChild(toast);

    if (duration > 0) {
        let timer = setTimeout(remove, duration);
        toast.addEventListener('mouseenter', () => clearTimeout(timer));
        toast.addEventListener('mouseleave', () => {
            timer = setTimeout(remove, 2000);
        });
    }
    return toast;
}

export const toast = {
    show: showToast,
    success: (msg, duration) => showToast(msg, 'success', duration),
    error: (msg, duration) => showToast(msg, 'danger', duration),
    warning: (msg, duration) => showToast(msg, 'warning', duration),
    info: (msg, duration) => showToast(msg, 'info', duration),
};

export function flushDjangoMessages() {
    const holder = document.getElementById('apDjangoMessages');
    if (!holder) return;
    holder.querySelectorAll('[data-toast-msg]').forEach((el) => {
        const text = (el.dataset.toastMsg || '').trim();
        const tag = (el.dataset.toastTag || 'info').trim();
        if (text) showToast(text, tag);
    });
    holder.remove();
}
