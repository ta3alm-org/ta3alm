

import { on } from '../core/events.js';
import { openImageLightbox } from '../core/modal.js';

function createStatusBadge(text, variant) {
    const badge = document.createElement('span');
    badge.className = `ap-badge ap-badge-${variant}`;
    const dot = document.createElement('span');
    dot.className = 'ap-dot';
    badge.appendChild(dot);
    badge.appendChild(document.createTextNode(text));
    return badge;
}

export function initFinancePage() {

    document.addEventListener('click', (e) => {
        const trigger = e.target.closest('[data-receipt-preview]');
        if (!trigger) return;
        e.preventDefault();
        openImageLightbox(trigger.dataset.receiptPreview, trigger.dataset.receiptTitle || 'صورة الإيصال');
    });


    on('ap:partial:updated', ({ data }) => {
        const revEl = document.getElementById('financeTotalRevenueValue');
        const cntEl = document.getElementById('financeTransactionsCount');
        if (revEl && data?.total_revenue !== undefined) {
            revEl.textContent = String(data.total_revenue);
        }
        if (cntEl && data?.count !== undefined) {
            cntEl.textContent = `${data.count} معاملة`;
        }
    });


    on('ap:form:success', ({ form, payload }) => {
        const data = payload?.data || {};

        if (form.dataset.financeContext === 'withdrawal') {
            const row = form.closest('tr[data-row]');
            if (!row) return;
            const status = data.status;
            row.dataset.status = status;

            const statusCell = row.querySelector('[data-status-cell]');
            const actionsCell = row.querySelector('[data-actions-cell]');
            if (statusCell) {
                statusCell.innerHTML = '';
                if (status === 'paid') {
                    statusCell.appendChild(createStatusBadge('تم التحويل', 'success'));
                } else {
                    statusCell.appendChild(createStatusBadge('مرفوض', 'danger'));
                    if (data.rejection_reason) {
                        const reasonEl = document.createElement('div');
                        reasonEl.className = 'ap-xs ap-text-danger ap-mt-1';
                        reasonEl.textContent = data.rejection_reason;
                        statusCell.appendChild(reasonEl);
                    }
                }
            }
            if (actionsCell) {
                const note = document.createElement('span');
                note.className = status === 'paid' ? 'ap-xs ap-text-success ap-strong' : 'ap-xs ap-text-danger';
                note.textContent = status === 'paid' ? 'تم التحويل' : 'تم الرفض وإعادة الرصيد';
                actionsCell.innerHTML = '';
                actionsCell.appendChild(note);
            }
        }

        if (form.dataset.financeContext === 'manual-payment') {
            const row = form.closest('tr[data-row]');
            if (!row) return;
            const status = data.status;
            row.dataset.status = status;

            const statusCell = row.querySelector('[data-status-cell]');
            const actionsCell = row.querySelector('[data-actions-cell]');
            if (statusCell) {
                statusCell.innerHTML = '';
                statusCell.appendChild(
                    status === 'approved'
                        ? createStatusBadge('مقبول', 'success')
                        : createStatusBadge('مرفوض', 'danger')
                );
            }
            if (actionsCell) {
                const note = document.createElement('span');
                note.className = 'ap-xs ap-muted';
                note.textContent = status === 'approved' ? 'تم الاعتماد' : 'مرفوض';
                actionsCell.innerHTML = '';
                actionsCell.appendChild(note);
            }
        }
    });
}
