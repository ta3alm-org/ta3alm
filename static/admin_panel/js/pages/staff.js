

import { on } from '../core/events.js';

export function initStaffPage() {
    const tableContainer = document.getElementById('staffTableContainer');
    const countSubtitle = document.getElementById('staffCountSubtitle');

    on('ap:form:success', ({ form, payload }) => {
        if (form.dataset.staffForm !== '1') return;
        const data = payload?.data || {};
        if (tableContainer && typeof data.table_html === 'string') {
            tableContainer.innerHTML = data.table_html;
        }
        if (countSubtitle && typeof data.staff_count === 'number') {
            countSubtitle.textContent = `${data.staff_count} مسؤول مُعيَّن`;
        }
    });
}
