/**
 * وحدة تحكم مركز الأمان والحماية وصفحة تفاصيل الجهاز.
 */
import { loadPartialFromForm } from '../components/search.js';
import { activateTab } from '../components/tabs.js';
import { on } from '../core/events.js';

export function initSecurityPage() {
    const filterForm = document.getElementById('securityFilterForm');
    let savedTabId = null;

    on('ap:tab:changed', ({ group, tabId }) => {
        if (group === 'security-sections') {
            savedTabId = tabId;
        }
    });

    const updateKpiStats = (stats) => {
        if (!stats || typeof stats !== 'object') return;
        Object.entries(stats).forEach(([key, val]) => {
            const el = document.querySelector(`[data-security-stat="${key}"]`);
            if (el) el.textContent = String(val);
        });
    };

    on('ap:partial:updated', ({ data }) => {
        if (data?.stats) updateKpiStats(data.stats);
        if (savedTabId) {
            const tabGroup = document.querySelector('[data-tabs="security-sections"]');
            if (tabGroup) activateTab(tabGroup, savedTabId);
        }
    });

    on('ap:form:success', ({ form, payload }) => {
        if (form.dataset.securityAction !== '1') return;

        // لو في صفحة security_dashboard: أعد جلب اللوحات والجدول تلقائياً بدون إعادة تحميل
        if (filterForm) {
            const activeBtn = document.querySelector('[data-tabs="security-sections"] .ap-tab-btn.active');
            if (activeBtn) savedTabId = activeBtn.dataset.tabTarget;
            loadPartialFromForm(filterForm, { syncUrl: false });
            return;
        }

        // لو في صفحة security_device_detail: حدّث حالة الحظر محلياً في رأس الصفحة
        const data = payload?.data || {};
        const blockForm = document.getElementById('deviceDetailBlockForm');
        if (blockForm && typeof data.is_blocked === 'boolean') {
            const actionInp = blockForm.querySelector('input[name="action"]');
            const btn = blockForm.querySelector('button[type="submit"]');
            if (data.is_blocked) {
                if (actionInp) actionInp.value = 'unblock_device';
                if (btn) {
                    btn.className = 'ap-btn ap-btn-sm ap-btn-success';
                    btn.textContent = 'فك حظر الجهاز';
                }
            } else {
                if (actionInp) actionInp.value = 'block_device';
                if (btn) {
                    btn.className = 'ap-btn ap-btn-sm ap-btn-danger';
                    btn.textContent = 'حظر الجهاز دائماً';
                }
            }
        }
    });
}
