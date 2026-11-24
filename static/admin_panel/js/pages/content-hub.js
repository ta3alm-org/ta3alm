import { loadPartialFromForm } from '../components/search.js';
import { on } from '../core/events.js';
import { openModal } from '../core/modal.js';

export function initContentHubPage() {
    const hubFilterForm = document.getElementById('contentHubFilterForm');
    const wsReloadForm = document.getElementById('groupWorkspaceReloadForm');

    document.addEventListener('click', (e) => {
        const editGroupBtn = e.target.closest('[data-hub-edit-group]');
        if (editGroupBtn) {
            e.preventDefault();
            document.getElementById('hubEditGroupId').value = editGroupBtn.dataset.groupId || '';
            document.getElementById('hubEditGroupTeacher').value = editGroupBtn.dataset.teacherId || '';
            document.getElementById('hubEditGroupName').value = editGroupBtn.dataset.name || '';
            document.getElementById('hubEditGroupGrade').value = editGroupBtn.dataset.grade || '';
            openModal('apEditGroupModal');
            return;
        }

        const editPkgBtn = e.target.closest('[data-hub-edit-package]');
        if (editPkgBtn) {
            e.preventDefault();
            document.getElementById('hubEditPkgId').value = editPkgBtn.dataset.packageId || '';
            document.getElementById('hubEditPkgTeacher').value = editPkgBtn.dataset.teacherId || '';
            document.getElementById('hubEditPkgTitle').value = editPkgBtn.dataset.title || '';
            document.getElementById('hubEditPkgGrade').value = editPkgBtn.dataset.grade || '';
            document.getElementById('hubEditPkgPrice').value = editPkgBtn.dataset.price || '0';
            document.getElementById('hubEditPkgDesc').value = editPkgBtn.dataset.description || '';
            document.getElementById('hubEditPkgActive').checked = editPkgBtn.dataset.active === '1';
            openModal('apEditPackageModal');
            return;
        }

        const enrollBtn = e.target.closest('[data-hub-enroll]');
        if (enrollBtn) {
            e.preventDefault();
            const kind = enrollBtn.dataset.hubEnroll;
            const targetId = enrollBtn.dataset.targetId || '';
            document.getElementById('hubEnrollTargetName').textContent = enrollBtn.dataset.targetName || '';
            if (kind === 'package') {
                document.getElementById('hubEnrollAction').value = 'grant_package_student';
                document.getElementById('hubEnrollPackageId').value = targetId;
                document.getElementById('hubEnrollGroupId').value = '';
            } else {
                document.getElementById('hubEnrollAction').value = 'enroll_student_group';
                document.getElementById('hubEnrollGroupId').value = targetId;
                document.getElementById('hubEnrollPackageId').value = '';
            }
            openModal('apHubEnrollModal');
        }
    });

    on('ap:tab:changed', ({ group, tabId }) => {
        if (group === 'content-hub' && hubFilterForm) {
            const tabInput = hubFilterForm.querySelector('input[name="tab"]');
            if (tabInput) tabInput.value = tabId.replace(/^tab-hub-/, '');
        }
        if ((group === 'group-ws' || group === 'pkg-ws') && wsReloadForm) {
            const tabInput = wsReloadForm.querySelector('input[name="tab"]');
            if (tabInput) tabInput.value = tabId.replace(/^tab-(?:ws|pkg)-/, '');
        }
    });

    on('ap:form:success', ({ form }) => {
        if (form.dataset.hubAction === '1' && hubFilterForm) {
            loadPartialFromForm(hubFilterForm, { syncUrl: false });
            form.reset();
        }
        if (form.dataset.wsAction === '1' && wsReloadForm) {
            loadPartialFromForm(wsReloadForm, { syncUrl: false });
            if (form.querySelector('input[name="action"]')?.value?.startsWith('add_') ||
                form.querySelector('input[name="action"]')?.value === 'send_chat_message' ||
                form.querySelector('input[name="action"]')?.value === 'enroll_student' ||
                form.querySelector('input[name="action"]')?.value === 'grant_student') {
                form.reset();
            }
        }
    });
}
