

import { loadPartialFromForm } from '../components/search.js';
import { on } from '../core/events.js';

export function initErrorReportsPage() {
    const filterForm = document.getElementById('errorReportsFilterForm');
    const statusInput = document.getElementById('errorReportsStatusInput');
    const searchInput = filterForm?.querySelector('input[name="q"]');
    const clearBtn = filterForm?.querySelector('[data-filter-reset]');
    const resolveAllWrap = document.getElementById('errorResolveAllWrap');

    const syncClearButton = () => {
        if (!clearBtn || !searchInput) return;
        clearBtn.classList.toggle('ap-hidden', !searchInput.value.trim());
    };

    const syncStats = (stats) => {
        if (!stats || typeof stats !== 'object') return;
        const unresolved = Number(stats.unresolved ?? 0);
        const map = {
            unresolved,
            resolved: Number(stats.resolved ?? 0),
            total: Number(stats.total ?? 0),
            occurrences: Number(stats.occurrences ?? 0),
        };
        Object.entries(map).forEach(([key, val]) => {
            document.querySelectorAll(`[data-error-stat="${key}"]`).forEach((el) => {
                el.textContent = String(val);
            });
        });
        if (resolveAllWrap) {
            resolveAllWrap.classList.toggle('ap-hidden', unresolved <= 0);
        }
        const navCountEl = document.querySelector('[data-nav-count="error_reports"]');
        if (navCountEl) {
            navCountEl.textContent = String(unresolved);
            navCountEl.classList.toggle('ap-hidden', unresolved <= 0);
        }
    };

    document.addEventListener('click', (e) => {
        const tabBtn = e.target.closest('[data-error-status-tab]');
        if (!tabBtn || !filterForm || !statusInput) return;
        e.preventDefault();

        const nextStatus = tabBtn.dataset.errorStatusTab || 'unresolved';
        statusInput.value = nextStatus;
        statusInput.defaultValue = nextStatus;

        document.querySelectorAll('[data-error-status-tab]').forEach((btn) => {
            const isActive = btn === tabBtn;
            btn.classList.toggle('ap-btn-primary', isActive);
            btn.classList.toggle('ap-btn-secondary', !isActive);
        });

        loadPartialFromForm(filterForm);
    });

    if (searchInput) {
        searchInput.addEventListener('input', syncClearButton);
    }
    if (clearBtn) {
        clearBtn.addEventListener('click', () => {
            clearBtn.classList.add('ap-hidden');
        });
    }

    on('ap:partial:updated', ({ data }) => {
        syncClearButton();
        if (data?.stats) {
            syncStats(data.stats);
        }
    });

    on('ap:form:success', ({ form, payload }) => {
        if (form.dataset.errorAction !== '1') return;
        if (payload?.data?.stats) {
            syncStats(payload.data.stats);
        }
        if (filterForm) {
            loadPartialFromForm(filterForm, { syncUrl: false });
        }
    });
}
