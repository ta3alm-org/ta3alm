/**
 * وحدة تحكم صفحات إدارة المستخدمين وتعديل بيانات المستخدم.
 */
import { loadPartialFromForm } from '../components/search.js';
import { openDrawer } from '../core/drawer.js';
import { on } from '../core/events.js';
import { toast } from '../core/notifications.js';

export function initUsersPage() {
    const filterForm = document.getElementById('usersFilterForm');
    const renewDrawer = document.getElementById('apRenewDrawer');
    const renewForm = document.getElementById('apRenewForm');
    const renewUserIdInput = document.getElementById('apRenewUserId');
    const renewTeacherName = document.getElementById('apRenewTeacherName');
    const renewPlanSelect = document.getElementById('apRenewPlanSelect');

    document.addEventListener('click', (e) => {
        const btn = e.target.closest('[data-renew-open]');
        if (!btn || !renewDrawer) return;
        e.preventDefault();
        if (renewUserIdInput) renewUserIdInput.value = btn.dataset.userId || '';
        if (renewTeacherName) renewTeacherName.textContent = btn.dataset.userName || '';
        if (renewPlanSelect && btn.dataset.planId) {
            renewPlanSelect.value = btn.dataset.planId;
        }
        openDrawer(renewDrawer);
    });

    // مزامنة تبويب users في نموذج البحث الحي مع التبويب النشط
    on('ap:tab:changed', ({ group, tabId }) => {
        if (group === 'users-role' && filterForm) {
            const tabInput = filterForm.querySelector('input[name="tab"]');
            if (tabInput) tabInput.value = tabId.replace(/^tab-/, '');
        }
    });

    on('ap:partial:updated', ({ data }) => {
        if (!data?.counts) return;
        const map = {
            teachers: document.getElementById('tabCountTeachers'),
            students: document.getElementById('tabCountStudents'),
            assistants: document.getElementById('tabCountAssistants'),
            summary: document.getElementById('usersSummaryCounts'),
        };
        if (map.teachers) map.teachers.textContent = String(data.counts.teachers ?? 0);
        if (map.students) map.students.textContent = String(data.counts.students ?? 0);
        if (map.assistants) map.assistants.textContent = String(data.counts.assistants ?? 0);
        if (map.summary) {
            map.summary.textContent = `${data.counts.teachers ?? 0} معلم · ${data.counts.students ?? 0} طالب · ${data.counts.assistants ?? 0} مساعد`;
        }
    });

    on('ap:form:success', ({ form, payload }) => {
        if (form.dataset.usersAction === '1' || form === renewForm) {
            if (filterForm) loadPartialFromForm(filterForm, { syncUrl: false });
            return;
        }

        // صفحة edit_user.html
        if (form.id === 'generateLoginLinkForm' && payload?.data?.magic_link) {
            const box = document.getElementById('magicLinkResultBox');
            const input = document.getElementById('magicLoginLink');
            if (box && input) {
                input.value = payload.data.magic_link;
                box.classList.remove('ap-hidden');
            }
        }

        if (form.id === 'editUserForm' && payload?.data?.full_name) {
            const titleEl = document.getElementById('editUserHeaderName');
            const emailEl = document.getElementById('editUserHeaderEmail');
            if (titleEl) titleEl.textContent = payload.data.full_name;
            if (emailEl && payload.data.email) emailEl.textContent = payload.data.email;
        }
    });

    const copyBtn = document.getElementById('copyMagicLinkBtn');
    if (copyBtn) {
        copyBtn.addEventListener('click', async () => {
            const input = document.getElementById('magicLoginLink');
            if (!input || !input.value) return;
            try {
                await navigator.clipboard.writeText(input.value);
                toast.success('تم نسخ رابط الدخول المباشر إلى الحافظة.');
            } catch (_) {
                input.select();
                toast.info('حدد الرابط واضغط Ctrl+C للنسخ.');
            }
        });
    }
}
