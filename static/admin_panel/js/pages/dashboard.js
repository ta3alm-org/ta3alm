/**
 * وحدة تحكم صفحة لوحة القيادة الرئيسية.
 */
import { emit, on } from '../core/events.js';

export function initDashboardPage() {
    on('ap:form:success', ({ payload }) => {
        const data = payload?.data || {};
        if (typeof data.is_maintenance_mode === 'boolean') {
            emit('ap:maintenance:changed', { isMaintenance: data.is_maintenance_mode });
        }

        if (typeof data.latest_version_code !== 'undefined') {
            const badge = document.getElementById('dashboardApkBuildBadge');
            if (badge) {
                badge.textContent = `أحدث بناء: ${data.latest_version_code} (${data.latest_version_name || ''})`;
            }
        }
    });

    on('ap:maintenance:changed', ({ isMaintenance }) => {
        const dashBtn = document.getElementById('dashboardMaintBtn');
        if (dashBtn) {
            dashBtn.className = `ap-btn ap-btn-sm ${isMaintenance ? 'ap-btn-danger' : 'ap-btn-secondary'}`;
            const label = dashBtn.querySelector('[data-maint-label]');
            if (label) {
                label.textContent = isMaintenance ? 'إيقاف الصيانة' : 'تفعيل الصيانة';
            }
        }
    });
}
