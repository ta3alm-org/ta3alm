/**
 * إدارة حالات التحميل للأزرار والحاويات.
 */
export function setButtonLoading(btn, isLoading) {
    if (!btn) return;
    if (isLoading) {
        btn.dataset.apWasDisabled = btn.disabled ? '1' : '0';
        btn.disabled = true;
        btn.classList.add('is-loading');
        if (!btn.querySelector('.ap-spinner')) {
            const spinner = document.createElement('span');
            spinner.className = 'ap-spinner';
            spinner.setAttribute('aria-hidden', 'true');
            const firstIcon = btn.querySelector(':scope > i');
            if (firstIcon) {
                firstIcon.dataset.apOrigHidden = firstIcon.style.display || '';
                firstIcon.style.display = 'none';
            }
            btn.prepend(spinner);
        }
    } else {
        btn.classList.remove('is-loading');
        if (btn.dataset.apWasDisabled !== '1') {
            btn.disabled = false;
        }
        delete btn.dataset.apWasDisabled;
        const spinner = btn.querySelector(':scope > .ap-spinner');
        if (spinner) spinner.remove();
        const hiddenIcon = btn.querySelector(':scope > i[data-ap-orig-hidden]');
        if (hiddenIcon) {
            hiddenIcon.style.display = hiddenIcon.dataset.apOrigHidden;
            delete hiddenIcon.dataset.apOrigHidden;
        }
    }
}

export function setContainerLoading(container, isLoading) {
    if (!container) return;
    container.classList.toggle('ap-is-loading', Boolean(isLoading));
    container.setAttribute('aria-busy', isLoading ? 'true' : 'false');
}
