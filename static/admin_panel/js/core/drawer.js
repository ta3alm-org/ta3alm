

const openDrawers = new Set();

function syncBodyScroll() {
    const anyOverlay = openDrawers.size > 0 || document.querySelector('.ap-modal.open');
    document.body.style.overflow = anyOverlay ? 'hidden' : '';
}

export function openDrawer(drawerOrId) {
    const el = typeof drawerOrId === 'string' ? document.getElementById(drawerOrId) : drawerOrId;
    if (!el) return null;
    el.classList.add('open');
    el.setAttribute('aria-hidden', 'false');
    openDrawers.add(el);
    syncBodyScroll();
    const autofocusEl = el.querySelector('[autofocus], input:not([type="hidden"]), select, textarea');
    if (autofocusEl) {
        setTimeout(() => autofocusEl.focus(), 50);
    }
    return el;
}

export function closeDrawer(drawerOrId) {
    const el = typeof drawerOrId === 'string' ? document.getElementById(drawerOrId) : drawerOrId;
    if (!el) return;
    el.classList.remove('open');
    el.setAttribute('aria-hidden', 'true');
    openDrawers.delete(el);
    syncBodyScroll();
}

export function initDrawerTriggers() {
    document.addEventListener('click', (e) => {
        const openTrigger = e.target.closest('[data-drawer-open]');
        if (openTrigger) {
            e.preventDefault();
            openDrawer(openTrigger.dataset.drawerOpen);
            return;
        }
        const closeTrigger = e.target.closest('[data-drawer-close]');
        if (closeTrigger) {
            e.preventDefault();
            const drawer = closeTrigger.closest('.ap-drawer');
            if (drawer) closeDrawer(drawer);
        }
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && openDrawers.size > 0 && !document.querySelector('.ap-modal.open')) {
            const top = Array.from(openDrawers).pop();
            if (top) closeDrawer(top);
        }
    });
}
