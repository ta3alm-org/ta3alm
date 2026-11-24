

import { on } from '../core/events.js';

export function initCurriculumPage() {

    const addButton = document.getElementById('add-lesson-btn');
    const container = document.getElementById('lesson-formset-container');
    const totalFormsInput = document.querySelector('input[name$="-TOTAL_FORMS"]');
    const emptyTemplateRow = document.querySelector('#empty-form tr');

    if (addButton && container && totalFormsInput && emptyTemplateRow) {
        addButton.addEventListener('click', () => {
            const count = parseInt(totalFormsInput.value || '0', 10);
            const clone = emptyTemplateRow.cloneNode(true);
            clone.innerHTML = clone.innerHTML.replace(/__prefix__/g, String(count));
            container.appendChild(clone);
            totalFormsInput.value = String(count + 1);
            const firstInput = clone.querySelector('input[type="text"]');
            if (firstInput) firstInput.focus();
        });
    }


    on('ap:form:success', ({ form, payload }) => {
        if (form.dataset.curriculumDelete === '1' && payload?.data?.deleted) {
            const row = form.closest('tr[data-row]');
            if (row) row.remove();
        }
    });
}
