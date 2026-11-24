

let activeDropdown = null;

function positionMenu(trigger, menu) {
    const rect = trigger.getBoundingClientRect();
    menu.classList.add('open');
    const menuRect = menu.getBoundingClientRect();
    const vw = window.innerWidth;
    const vh = window.innerHeight;

    let top = rect.bottom + 6;
    if (top + menuRect.height > vh - 12 && rect.top - menuRect.height - 6 > 12) {
        top = rect.top - menuRect.height - 6;
    }

    const alignEnd = trigger.dataset.dropdownAlign === 'start';
    let left = alignEnd ? rect.right - menuRect.width : rect.left;
    if (left + menuRect.width > vw - 12) left = vw - menuRect.width - 12;
    if (left < 12) left = 12;

    menu.style.top = `${Math.round(top)}px`;
    menu.style.left = `${Math.round(left)}px`;
}

export function closeAllDropdowns() {
    if (!activeDropdown) return;
    activeDropdown.menu.classList.remove('open');
    activeDropdown.trigger.setAttribute('aria-expanded', 'false');
    activeDropdown = null;
}

export function initDropdowns() {
    document.addEventListener('click', (e) => {
        const trigger = e.target.closest('[data-dropdown-trigger]');
        if (trigger) {
            e.preventDefault();
            e.stopPropagation();
            const wrapper = trigger.closest('.ap-dropdown');
            const menu = wrapper ? wrapper.querySelector('.ap-dropdown-menu') : null;
            if (!menu) return;

            const isSame = activeDropdown && activeDropdown.menu === menu;
            closeAllDropdowns();
            if (!isSame) {
                activeDropdown = { trigger, menu };
                trigger.setAttribute('aria-expanded', 'true');
                positionMenu(trigger, menu);
            }
            return;
        }

        if (activeDropdown) {
            if (!e.target.closest('.ap-dropdown-menu')) {
                closeAllDropdowns();
            } else if (e.target.closest('a, button:not([data-keep-open])')) {
                setTimeout(closeAllDropdowns, 0);
            }
        }
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeAllDropdowns();
    });
    window.addEventListener('resize', closeAllDropdowns, { passive: true });
    document.addEventListener('scroll', closeAllDropdowns, { passive: true, capture: true });
}
