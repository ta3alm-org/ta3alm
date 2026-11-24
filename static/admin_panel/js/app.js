

import { initClientTables } from './components/data-table.js';
import { initDropdowns } from './components/dropdown.js';
import { initAjaxForms } from './components/form-handler.js';
import { initLiveSearchAndFilters } from './components/search.js';
import { initSidebar } from './components/sidebar.js';
import { initTabs } from './components/tabs.js';
import { initDrawerTriggers } from './core/drawer.js';
import { emit, on } from './core/events.js';
import { initModalTriggers } from './core/modal.js';
import { flushDjangoMessages, toast } from './core/notifications.js';

import { initAppReleasePage } from './pages/app-release.js';
import { initContentHubPage } from './pages/content-hub.js';
import { initCurriculumPage } from './pages/curriculum.js';
import { initDashboardPage } from './pages/dashboard.js';
import { initErrorReportsPage } from './pages/error-reports.js';
import { initFinancePage } from './pages/finance.js';
import { initNotificationsPage } from './pages/notifications.js';
import { initPlansPage } from './pages/plans.js';
import { initSecurityPage } from './pages/security.js';
import { initStaffPage } from './pages/staff.js';
import { initSupportChatPage } from './pages/support-chat.js';
import { initSupportPage } from './pages/support.js';
import { initUsersPage } from './pages/users.js';

function initGlobalMaintenanceSync() {
    on('ap:form:success', ({ form, payload }) => {
        if (form.dataset.maintenanceForm === '1' && typeof payload?.data?.is_maintenance_mode === 'boolean') {
            emit('ap:maintenance:changed', { isMaintenance: payload.data.is_maintenance_mode });
        }
    });

    on('ap:maintenance:changed', ({ isMaintenance }) => {
        const pill = document.getElementById('apTopbarMaintBtn');
        if (!pill) return;
        pill.classList.toggle('is-active', Boolean(isMaintenance));
        pill.title = isMaintenance ? 'وضع الصيانة مفعّل — اضغط للإيقاف' : 'تفعيل وضع الصيانة';
        const txt = pill.querySelector('[data-topbar-maint-text]');
        if (txt) {
            txt.textContent = isMaintenance ? 'الصيانة مفعّلة' : 'وضع الصيانة';
        }
    });
}

function initCopyHelpers() {
    document.addEventListener('click', async (e) => {
        const copyBtn = e.target.closest('[data-copy-text], [data-copy-target]');
        if (!copyBtn) return;
        e.preventDefault();
        let text = copyBtn.dataset.copyText || '';
        if (!text && copyBtn.dataset.copyTarget) {
            const target = document.querySelector(copyBtn.dataset.copyTarget);
            text = target ? (target.value ?? target.textContent ?? '') : '';
        }
        if (!text) return;
        try {
            await navigator.clipboard.writeText(text);
            toast.success(copyBtn.dataset.copyMessage || 'تم النسخ إلى الحافظة.');
        } catch (_) {
            toast.info('يرجى تحديد النص ونسخه يدوياً.');
        }
    });
}

const PAGE_INITIALIZERS = {
    dashboard: initDashboardPage,
    users: initUsersPage,
    'edit-user': initUsersPage,
    finance: initFinancePage,
    plans: initPlansPage,
    staff: initStaffPage,
    curriculum: initCurriculumPage,
    support: initSupportPage,
    'support-chat': initSupportChatPage,
    security: initSecurityPage,
    'error-reports': initErrorReportsPage,
    notifications: initNotificationsPage,
    'app-release': initAppReleasePage,
    'content-hub': initContentHubPage,
};

document.addEventListener('DOMContentLoaded', () => {
    initSidebar();
    initDropdowns();
    initTabs();
    initModalTriggers();
    initDrawerTriggers();
    initAjaxForms();
    initLiveSearchAndFilters();
    initClientTables();
    initGlobalMaintenanceSync();
    initCopyHelpers();
    flushDjangoMessages();

    const pageName = document.body.dataset.page || '';
    const initPage = PAGE_INITIALIZERS[pageName];
    if (typeof initPage === 'function') {
        initPage();
    }
});
