/**
 * وحدة تحكم صفحة إرسال الإشعارات المخصصة (المعاينة الحية، اختيار المستخدمين، الإرسال بـ AJAX).
 */
import { api } from '../core/api.js';
import { setButtonLoading } from '../core/loading.js';
import { confirmDialog } from '../core/modal.js';
import { toast } from '../core/notifications.js';

export function initNotificationsPage() {
    const form = document.getElementById('customNotificationForm');
    if (!form) return;

    const previewUrl = form.dataset.previewUrl || '';
    const modeCards = document.querySelectorAll('.ap-mode-card');
    const segmentOptionsBox = document.getElementById('segmentOptionsBox');
    const specificUsersBox = document.getElementById('specificUsersBox');
    const segmentSelect = document.getElementById('segmentSelect');
    const segmentDescText = document.getElementById('segmentDescText');
    const excludeBannedCheck = document.getElementById('excludeBannedCheck');

    const gradeSelect = document.getElementById('gradeSelect');
    const teacherSelect = document.getElementById('teacherSelect');
    const planSelect = document.getElementById('planSelect');
    const subjectSelect = document.getElementById('subjectSelect');

    const selectedContainer = document.getElementById('selectedUsersContainer');
    const selectedHiddenInputs = document.getElementById('selectedHiddenInputs');
    const selectedCountEl = document.getElementById('selectedUsersCount');
    const userSearchInput = document.getElementById('userSearchInput');
    const userSearchRole = document.getElementById('userSearchRole');
    const userSearchBtn = document.getElementById('userSearchBtn');
    const userSearchResults = document.getElementById('userSearchResults');

    const initialSelectedEl = document.getElementById('initialSelectedUsersData');
    const initialSearchEl = document.getElementById('initialSearchUsersData');

    const selectedUsers = new Map();
    const initialSelected = JSON.parse(initialSelectedEl?.textContent || '[]');
    initialSelected.forEach((u) => selectedUsers.set(Number(u.id), u));
    let cachedSearchResults = JSON.parse(initialSearchEl?.textContent || '[]');

    const currentMode = () => {
        const checked = form.querySelector('input[name="target_mode"]:checked');
        return checked ? checked.value : 'all';
    };

    const syncSegmentExtras = () => {
        if (!segmentSelect) return;
        const opt = segmentSelect.options[segmentSelect.selectedIndex];
        const extra = opt ? (opt.dataset.extra || '') : '';
        if (segmentDescText) segmentDescText.textContent = opt ? (opt.dataset.desc || '') : '';
        document.querySelectorAll('.segment-extra').forEach((el) => {
            el.classList.toggle('ap-hidden', el.dataset.extraField !== extra);
        });
    };

    const syncModeUI = () => {
        const mode = currentMode();
        modeCards.forEach((card) => {
            card.classList.toggle('active', card.dataset.mode === mode);
        });
        if (segmentOptionsBox) segmentOptionsBox.classList.toggle('ap-hidden', mode !== 'segment');
        if (specificUsersBox) specificUsersBox.classList.toggle('ap-hidden', mode !== 'users');
        syncSegmentExtras();
    };

    const renderSelectedUsers = () => {
        if (!selectedContainer || !selectedHiddenInputs || !selectedCountEl) return;
        selectedContainer.innerHTML = '';
        selectedHiddenInputs.innerHTML = '';
        selectedCountEl.textContent = String(selectedUsers.size);

        if (selectedUsers.size === 0) {
            const hint = document.createElement('span');
            hint.className = 'ap-muted ap-xs';
            hint.textContent = 'لم يتم اختيار أي مستخدم بعد — ابحث بالأسفل واضغط «إضافة».';
            selectedContainer.appendChild(hint);
            return;
        }

        selectedUsers.forEach((u, id) => {
            const chip = document.createElement('span');
            chip.className = 'ap-user-chip';

            const label = document.createElement('span');
            label.textContent = `${u.full_name} (${u.role_display || u.role})`;
            chip.appendChild(label);

            if (u.has_fcm) {
                const fcmTag = document.createElement('span');
                fcmTag.className = 'ap-badge ap-badge-success';
                fcmTag.textContent = 'FCM';
                chip.appendChild(fcmTag);
            }

            const removeBtn = document.createElement('button');
            removeBtn.type = 'button';
            removeBtn.title = 'إزالة';
            removeBtn.textContent = '×';
            removeBtn.addEventListener('click', () => {
                selectedUsers.delete(id);
                renderSelectedUsers();
                renderSearchResults(cachedSearchResults);
                refreshPreview();
            });
            chip.appendChild(removeBtn);
            selectedContainer.appendChild(chip);

            const hidden = document.createElement('input');
            hidden.type = 'hidden';
            hidden.name = 'user_ids';
            hidden.value = String(id);
            selectedHiddenInputs.appendChild(hidden);
        });
    };

    const renderSearchResults = (users) => {
        if (!userSearchResults) return;
        cachedSearchResults = users || [];
        userSearchResults.innerHTML = '';
        if (!cachedSearchResults.length) {
            const empty = document.createElement('div');
            empty.className = 'ap-muted ap-sm';
            empty.style.padding = '16px';
            empty.style.textAlign = 'center';
            empty.textContent = 'لا توجد نتائج مطابقة للبحث.';
            userSearchResults.appendChild(empty);
            return;
        }

        cachedSearchResults.forEach((u) => {
            const uid = Number(u.id);
            const isPicked = selectedUsers.has(uid);

            const row = document.createElement('div');
            row.className = 'ap-picker-row';

            const info = document.createElement('div');
            const nameLine = document.createElement('div');
            nameLine.className = 'ap-flex ap-items-center ap-gap-2 ap-wrap';

            const nameSpan = document.createElement('span');
            nameSpan.className = 'ap-strong ap-sm';
            nameSpan.textContent = u.full_name;
            nameLine.appendChild(nameSpan);

            const roleBadge = document.createElement('span');
            roleBadge.className = 'ap-badge ap-badge-neutral';
            roleBadge.textContent = u.role_display || u.role;
            nameLine.appendChild(roleBadge);

            if (u.has_fcm) {
                const fcmBadge = document.createElement('span');
                fcmBadge.className = 'ap-badge ap-badge-success';
                fcmBadge.textContent = 'FCM';
                nameLine.appendChild(fcmBadge);
            }
            if (u.is_banned) {
                const banBadge = document.createElement('span');
                banBadge.className = 'ap-badge ap-badge-danger';
                banBadge.textContent = 'محظور';
                nameLine.appendChild(banBadge);
            }

            const subLine = document.createElement('div');
            subLine.className = 'ap-xs ap-subtle-text';
            subLine.textContent = [u.email, u.phone, u.custom_id].filter(Boolean).join(' · ');

            info.appendChild(nameLine);
            info.appendChild(subLine);

            const actionBtn = document.createElement('button');
            actionBtn.type = 'button';
            actionBtn.className = isPicked ? 'ap-btn ap-btn-sm ap-btn-success' : 'ap-btn ap-btn-sm ap-btn-secondary';
            actionBtn.textContent = isPicked ? 'مُضاف ✓' : '+ إضافة';
            actionBtn.addEventListener('click', () => {
                if (selectedUsers.has(uid)) {
                    selectedUsers.delete(uid);
                } else {
                    selectedUsers.set(uid, u);
                }
                renderSelectedUsers();
                renderSearchResults(cachedSearchResults);
                refreshPreview();
            });

            row.appendChild(info);
            row.appendChild(actionBtn);
            userSearchResults.appendChild(row);
        });
    };

    const searchUsers = async () => {
        if (!previewUrl) return;
        const params = new URLSearchParams({
            action: 'search_users',
            q: (userSearchInput?.value || '').trim(),
            role: userSearchRole?.value || '',
        });
        try {
            const resp = await fetch(`${previewUrl}?${params.toString()}`, {
                headers: { 'X-Requested-With': 'XMLHttpRequest' },
            });
            const data = await resp.json();
            renderSearchResults(data.users || []);
        } catch (err) {
            console.error(err);
        }
    };

    let previewTimer = null;
    const refreshPreview = () => {
        clearTimeout(previewTimer);
        previewTimer = setTimeout(doRefreshPreview, 140);
    };

    const doRefreshPreview = async () => {
        if (!previewUrl) return;
        const spinner = document.getElementById('previewLoadingSpinner');
        if (spinner) spinner.classList.remove('ap-hidden');

        const params = new URLSearchParams({
            target_mode: currentMode(),
            segment: segmentSelect?.value || '',
            grade: gradeSelect?.value || '',
            teacher_id: teacherSelect?.value || '',
            plan_id: planSelect?.value || '',
            subject_id: subjectSelect?.value || '',
            exclude_banned: excludeBannedCheck?.checked ? '1' : '0',
        });
        selectedUsers.forEach((_, uid) => params.append('user_ids', String(uid)));

        try {
            const resp = await fetch(`${previewUrl}?${params.toString()}`, {
                headers: { 'X-Requested-With': 'XMLHttpRequest' },
            });
            const data = await resp.json();

            const audEl = document.getElementById('previewAudienceLabel');
            const totalEl = document.getElementById('previewTotalCount');
            const fcmEl = document.getElementById('previewFcmCount');
            if (audEl) audEl.textContent = data.audience_label || '—';
            if (totalEl) totalEl.textContent = String(data.recipient_count || 0);
            if (fcmEl) fcmEl.textContent = String(data.fcm_user_count || 0);

            const errBox = document.getElementById('previewErrorBox');
            if (errBox) {
                if (data.error) {
                    errBox.textContent = data.error;
                    errBox.classList.remove('ap-hidden');
                } else {
                    errBox.textContent = '';
                    errBox.classList.add('ap-hidden');
                }
            }

            const sampleList = document.getElementById('previewSampleList');
            if (sampleList) {
                sampleList.innerHTML = '';
                const samples = data.sample_recipients || [];
                if (!samples.length) {
                    const empty = document.createElement('span');
                    empty.className = 'ap-muted ap-xs';
                    empty.textContent = 'لا يوجد مستخدمون مطابقون حالياً';
                    sampleList.appendChild(empty);
                } else {
                    samples.forEach((s) => {
                        const row = document.createElement('div');
                        row.className = 'ap-kv-row';
                        const nameSpan = document.createElement('span');
                        nameSpan.className = 'ap-sm';
                        nameSpan.textContent = `${s.full_name} (${s.role_display || s.role})`;
                        row.appendChild(nameSpan);
                        if (s.has_fcm) {
                            const badge = document.createElement('span');
                            badge.className = 'ap-badge ap-badge-success';
                            badge.textContent = 'FCM';
                            row.appendChild(badge);
                        }
                        sampleList.appendChild(row);
                    });
                }
            }
        } catch (err) {
            console.error(err);
        } finally {
            if (spinner) spinner.classList.add('ap-hidden');
        }
    };

    modeCards.forEach((card) => {
        card.addEventListener('click', () => {
            const radio = card.querySelector('input[type="radio"]');
            if (radio) radio.checked = true;
            syncModeUI();
            refreshPreview();
        });
    });

    [segmentSelect, gradeSelect, teacherSelect, planSelect, subjectSelect, excludeBannedCheck].forEach((el) => {
        if (!el) return;
        el.addEventListener('change', () => {
            syncSegmentExtras();
            refreshPreview();
        });
    });

    if (userSearchBtn) userSearchBtn.addEventListener('click', searchUsers);
    if (userSearchRole) userSearchRole.addEventListener('change', searchUsers);
    if (userSearchInput) {
        let searchTimer = null;
        userSearchInput.addEventListener('input', () => {
            clearTimeout(searchTimer);
            searchTimer = setTimeout(searchUsers, 250);
        });
        userSearchInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                searchUsers();
            }
        });
    }

    const titleInput = document.getElementById('notifTitleInput');
    const msgInput = document.getElementById('notifMessageInput');
    const linkInput = document.getElementById('notifLinkInput');

    const syncLiveNotifCard = () => {
        const liveTitle = document.getElementById('liveNotifTitle');
        const liveMsg = document.getElementById('liveNotifMessage');
        const liveLink = document.getElementById('liveNotifLink');
        if (liveTitle) liveTitle.textContent = (titleInput?.value || '').trim() || 'عنوان الإشعار يظهر هنا';
        if (liveMsg) liveMsg.textContent = (msgInput?.value || '').trim() || 'نص الرسالة سيظهر للمستخدم في التطبيق والموقع...';
        if (liveLink) {
            const linkVal = (linkInput?.value || '').trim();
            liveLink.textContent = linkVal;
            liveLink.classList.toggle('ap-hidden', !linkVal);
        }
    };

    [titleInput, msgInput, linkInput].forEach((el) => {
        if (el) el.addEventListener('input', syncLiveNotifCard);
    });

    document.querySelectorAll('.link-preset-btn').forEach((btn) => {
        btn.addEventListener('click', () => {
            if (linkInput) linkInput.value = btn.dataset.url || '';
            syncLiveNotifCard();
        });
    });

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        if (form.dataset.apSubmitting === '1') return;

        const count = Number(document.getElementById('previewTotalCount')?.textContent || '0');
        const label = document.getElementById('previewAudienceLabel')?.textContent || '';
        if (count > 1) {
            const { confirmed } = await confirmDialog({
                title: 'تأكيد إرسال الإشعار',
                message: `سيتم إرسال الإشعار إلى ${count} مستخدم (${label}). هل تريد المتابعة؟`,
                confirmText: 'إرسال الإشعار',
                variant: 'primary',
            });
            if (!confirmed) return;
        }

        const submitBtn = form.querySelector('button[type="submit"]');
        form.dataset.apSubmitting = '1';
        setButtonLoading(submitBtn, true);

        try {
            const res = await api.post(form.getAttribute('action') || window.location.pathname, new FormData(form), { form });
            if (res.message) toast.success(res.message);

            const dispatchesContainer = document.getElementById('recentDispatchesContainer');
            if (dispatchesContainer && typeof res.data?.dispatches_html === 'string') {
                dispatchesContainer.innerHTML = res.data.dispatches_html;
            }

            if (titleInput) titleInput.value = '';
            if (msgInput) msgInput.value = '';
            syncLiveNotifCard();
        } catch (err) {
            toast.error(err.message || 'تعذّر إرسال الإشعار.');
        } finally {
            delete form.dataset.apSubmitting;
            setButtonLoading(submitBtn, false);
        }
    });

    syncModeUI();
    renderSelectedUsers();
    renderSearchResults(cachedSearchResults);
    syncLiveNotifCard();
}
