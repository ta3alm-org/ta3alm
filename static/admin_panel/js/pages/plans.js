/**
 * وحدة تحكم صفحة إدارة الباقات (درج موحّد للإضافة والتعديل + تحديث الشبكة عبر AJAX).
 */
import { openDrawer } from '../core/drawer.js';
import { on } from '../core/events.js';

export function initPlansPage() {
    const drawer = document.getElementById('apPlanDrawer');
    const drawerTitle = document.getElementById('apPlanDrawerTitle');
    const form = document.getElementById('apPlanDrawerForm');
    const gridContainer = document.getElementById('plansGridContainer');
    const countSubtitle = document.getElementById('plansCountSubtitle');
    if (!drawer || !form) return;

    const actionInput = form.querySelector('input[name="action"]');
    const planIdInput = form.querySelector('input[name="plan_id"]');
    const nameInput = form.querySelector('[name="name"]');
    const priceInput = form.querySelector('[name="price"]');
    const studentLimitInput = form.querySelector('[name="student_limit"]');
    const groupLimitInput = form.querySelector('[name="group_limit"]');
    const assistantLimitInput = form.querySelector('[name="assistant_limit"]');
    const descInput = form.querySelector('[name="desc"]');
    const allowOnlineInput = form.querySelector('[name="allow_online"]');
    const allowImagesInput = form.querySelector('[name="allow_images"]');
    const isDefaultInput = form.querySelector('[name="is_default"]');
    const submitBtn = form.querySelector('[data-plan-submit-label]');

    const openForAdd = () => {
        form.reset();
        if (actionInput) actionInput.value = 'add';
        if (planIdInput) planIdInput.value = '';
        if (priceInput) priceInput.value = '0';
        if (studentLimitInput) studentLimitInput.value = '1000';
        if (groupLimitInput) groupLimitInput.value = '5';
        if (assistantLimitInput) assistantLimitInput.value = '2';
        if (drawerTitle) drawerTitle.textContent = 'إضافة باقة جديدة';
        if (submitBtn) submitBtn.textContent = 'إضافة الباقة';
        openDrawer(drawer);
    };

    const openForEdit = (btn) => {
        form.reset();
        if (actionInput) actionInput.value = 'edit';
        if (planIdInput) planIdInput.value = btn.dataset.planId || '';
        if (nameInput) nameInput.value = btn.dataset.planName || '';
        if (priceInput) priceInput.value = btn.dataset.planPrice || '0';
        if (studentLimitInput) studentLimitInput.value = btn.dataset.planStudentLimit || '1000';
        if (groupLimitInput) groupLimitInput.value = btn.dataset.planGroupLimit || '5';
        if (assistantLimitInput) assistantLimitInput.value = btn.dataset.planAssistantLimit || '2';
        if (descInput) descInput.value = btn.dataset.planDesc || '';
        if (allowOnlineInput) allowOnlineInput.checked = btn.dataset.planAllowOnline === '1';
        if (allowImagesInput) allowImagesInput.checked = btn.dataset.planAllowImages === '1';
        if (isDefaultInput) isDefaultInput.checked = btn.dataset.planIsDefault === '1';
        if (drawerTitle) drawerTitle.textContent = `تعديل: ${btn.dataset.planName || ''}`;
        if (submitBtn) submitBtn.textContent = 'حفظ التعديلات';
        openDrawer(drawer);
    };

    document.addEventListener('click', (e) => {
        if (e.target.closest('[data-plan-add]')) {
            e.preventDefault();
            openForAdd();
            return;
        }
        const editBtn = e.target.closest('[data-plan-edit]');
        if (editBtn) {
            e.preventDefault();
            openForEdit(editBtn);
        }
    });

    on('ap:form:success', ({ form: submittedForm, payload }) => {
        if (submittedForm.dataset.planForm !== '1') return;
        const data = payload?.data || {};
        if (gridContainer && typeof data.grid_html === 'string') {
            gridContainer.innerHTML = data.grid_html;
        }
        if (countSubtitle && typeof data.plans_count === 'number') {
            countSubtitle.textContent = `${data.plans_count} باقة مُعرَّفة`;
        }
    });
}
