/**
 * إدارة القائمة الجانبية (طي/توسيع على الديسكتوب + درج على الموبايل + حفظ الحالة).
 */
const STORAGE_KEY = 'ta3alm_admin_sidebar_collapsed';

export function initSidebar() {
    const html = document.documentElement;
    const collapseBtn = document.getElementById('apSidebarCollapseBtn');
    const mobileBtn = document.getElementById('apMobileMenuBtn');
    const closeMobileBtn = document.getElementById('apSidebarCloseMobile');
    const backdrop = document.getElementById('apSidebarBackdrop');

    const updateCollapseIcon = () => {
        if (!collapseBtn) return;
        const collapsed = html.classList.contains('ap-sidebar-collapsed');
        const icon = collapseBtn.querySelector('i');
        if (icon) {
            icon.className = collapsed ? 'bi bi-layout-sidebar-inset' : 'bi bi-layout-sidebar-inset-reverse';
        }
        collapseBtn.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
        collapseBtn.title = collapsed ? 'توسيع القائمة' : 'تصغير القائمة';
    };

    if (collapseBtn) {
        updateCollapseIcon();
        collapseBtn.addEventListener('click', () => {
            const next = !html.classList.contains('ap-sidebar-collapsed');
            html.classList.toggle('ap-sidebar-collapsed', next);
            try {
                localStorage.setItem(STORAGE_KEY, next ? '1' : '0');
            } catch (_) {
                // ignore storage errors
            }
            updateCollapseIcon();
        });
    }

    const closeMobile = () => html.classList.remove('ap-mobile-nav-open');
    const openMobile = () => html.classList.add('ap-mobile-nav-open');

    if (mobileBtn) mobileBtn.addEventListener('click', openMobile);
    if (closeMobileBtn) closeMobileBtn.addEventListener('click', closeMobile);
    if (backdrop) backdrop.addEventListener('click', closeMobile);

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && html.classList.contains('ap-mobile-nav-open')) {
            closeMobile();
        }
    });

    // حساب موضع tooltip الرأسي بدقة عند التصغير
    document.querySelectorAll('.ap-nav-link[data-tooltip]').forEach((link) => {
        link.addEventListener('mouseenter', () => {
            if (!html.classList.contains('ap-sidebar-collapsed')) return;
            const rect = link.getBoundingClientRect();
            link.style.setProperty('--tooltip-top', `${Math.round(rect.top + rect.height / 2)}px`);
        });
    });
}
