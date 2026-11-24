

import { loadPartialFromForm } from '../components/search.js';
import { on } from '../core/events.js';

export function initSupportPage() {
    const inboxFilterForm = document.getElementById('supportInboxFilterForm');
    const refreshBtn = document.getElementById('supportRefreshBtn');
    const countBadge = document.getElementById('supportInboxCount');


    document.addEventListener('click', (e) => {
        const snippetBtn = e.target.closest('[data-email-snippet]');
        if (!snippetBtn) return;
        const targetSelector = snippetBtn.dataset.snippetTarget || '#composeContent';
        const area = document.querySelector(targetSelector);
        if (area) {
            area.value = snippetBtn.dataset.emailSnippet || '';
            area.focus();
        }
    });

    if (refreshBtn && inboxFilterForm) {
        refreshBtn.addEventListener('click', (e) => {
            e.preventDefault();
            loadPartialFromForm(inboxFilterForm, { syncUrl: false });
        });
    }

    on('ap:partial:updated', ({ data }) => {
        if (countBadge && typeof data?.count === 'number') {
            countBadge.textContent = String(data.count);
        }
    });


    on('ap:form:success', ({ form, payload }) => {
        if (form.dataset.supportSettingsForm !== '1') return;
        const data = payload?.data || {};
        if (data.action === 'disconnect' || typeof data.is_connected === 'boolean') {
            setTimeout(() => {
                window.location.reload();
            }, 650);
        }
    });
}
