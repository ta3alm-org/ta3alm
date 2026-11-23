/**
 * وحدة تحكم صفحة شات الدعم المباشر (تبديل المحادثات، البحث، الإرسال، تغيير الحالة، والتحديث الفوري بدون ريفريش).
 */
import { loadPartialFromForm } from '../components/search.js';
import { api } from '../core/api.js';
import { on } from '../core/events.js';
import { setButtonLoading, setContainerLoading } from '../core/loading.js';
import { toast } from '../core/notifications.js';

export function initSupportChatPage() {
    const filterForm = document.getElementById('supportChatFilterForm');
    const statusInput = document.getElementById('chatStatusFilterInput');
    const activeThreadInput = document.getElementById('chatActiveThreadInput');
    const searchInput = filterForm?.querySelector('input[name="q"]');
    const clearBtn = filterForm?.querySelector('[data-filter-reset]');
    const threadsListEl = document.getElementById('apChatThreadsList');
    const paneEl = document.getElementById('apSupportChatPane');

    let activeThreadId = activeThreadInput?.value ? String(activeThreadInput.value) : '';
    let lastMsgId = 0;
    let pollUrl = '';

    const syncClearButton = () => {
        if (!clearBtn || !searchInput) return;
        clearBtn.classList.toggle('ap-hidden', !searchInput.value.trim());
    };

    const scrollStreamToBottom = () => {
        const stream = document.getElementById('apAdminChatStream');
        if (stream) stream.scrollTop = stream.scrollHeight;
    };

    const readStreamMeta = () => {
        const stream = document.getElementById('apAdminChatStream');
        if (!stream) {
            lastMsgId = 0;
            pollUrl = '';
            return;
        }
        const rawTid = stream.dataset.threadId || '';
        if (rawTid) {
            activeThreadId = String(rawTid);
            if (activeThreadInput) {
                activeThreadInput.value = activeThreadId;
                activeThreadInput.defaultValue = activeThreadId;
            }
        }
        lastMsgId = Number(stream.dataset.lastMsgId || 0) || 0;
        pollUrl = stream.dataset.pollUrl || '';
    };

    const syncNavUnread = (totalUnread) => {
        if (typeof totalUnread !== 'number') return;
        const navCountEl = document.querySelector('[data-nav-count="support_chat"]');
        if (!navCountEl) return;
        navCountEl.textContent = String(totalUnread);
        navCountEl.classList.toggle('ap-hidden', totalUnread <= 0);
    };

    const syncStatusUi = (status) => {
        if (!status) return;
        const isClosed = status === 'closed';
        const badge = document.getElementById('chatThreadStatusBadge');
        if (badge) {
            badge.className = `ap-badge ${isClosed ? 'ap-badge-neutral' : 'ap-badge-success'}`;
            badge.textContent = isClosed ? 'مغلقة' : 'مفتوحة';
        }

        const statusForm = document.getElementById('apChatStatusForm');
        if (!statusForm) return;

        const actionInput = statusForm.querySelector('input[name="action"]');
        const submitBtn = statusForm.querySelector('button[type="submit"]');
        if (actionInput) {
            actionInput.value = isClosed ? 'reopen' : 'close';
        }
        if (isClosed) {
            statusForm.removeAttribute('data-confirm');
            statusForm.removeAttribute('data-confirm-title');
            statusForm.removeAttribute('data-confirm-variant');
            if (submitBtn) {
                submitBtn.className = 'ap-btn ap-btn-sm ap-btn-success';
                submitBtn.innerHTML = '<i class="bi bi-unlock"></i> إعادة فتح';
            }
        } else {
            statusForm.dataset.confirm = 'هل تريد إغلاق هذه المحادثة؟ سيتمكن المستخدم من إعادة فتحها إذا أرسل رسالة جديدة.';
            statusForm.dataset.confirmTitle = 'إغلاق المحادثة';
            statusForm.dataset.confirmVariant = 'warning';
            if (submitBtn) {
                submitBtn.className = 'ap-btn ap-btn-sm ap-btn-secondary';
                submitBtn.innerHTML = '<i class="bi bi-lock"></i> إغلاق المحادثة';
            }
        }
    };

    const formatTime = (iso) => {
        if (!iso) return '';
        const d = new Date(iso);
        if (Number.isNaN(d.getTime())) return '';
        return d.toLocaleTimeString('ar-EG', { hour: '2-digit', minute: '2-digit' });
    };

    const appendMessage = (m) => {
        const stream = document.getElementById('apAdminChatStream');
        if (!stream || !m || !m.id || stream.querySelector(`[data-msg-id="${m.id}"]`)) return;

        const emptyEl = document.getElementById('apAdminChatEmpty');
        if (emptyEl) emptyEl.remove();

        const isMe = Boolean(m.is_from_admin);
        const row = document.createElement('div');
        row.className = `ap-chat-bubble-row ${isMe ? 'is-me' : 'is-peer'}`;
        row.setAttribute('data-msg-id', String(m.id));

        const bubble = document.createElement('div');
        bubble.className = 'ap-chat-bubble';

        const senderDiv = document.createElement('div');
        senderDiv.className = 'ap-chat-bubble-sender';
        const nameSpan = document.createElement('span');
        nameSpan.textContent = isMe ? `الإدارة (${m.sender_name || 'مشرف'})` : (m.sender_name || 'مستخدم');
        senderDiv.appendChild(nameSpan);

        if (m.via_notification_reply) {
            const badge = document.createElement('span');
            badge.className = 'ap-badge ap-badge-warning';
            badge.textContent = 'رد من الإشعارات';
            senderDiv.appendChild(badge);
        }

        const bodyDiv = document.createElement('div');
        bodyDiv.className = 'ap-chat-bubble-body';
        bodyDiv.textContent = m.body || '';

        const timeDiv = document.createElement('div');
        timeDiv.className = 'ap-chat-bubble-time';
        timeDiv.textContent = formatTime(m.created_at);

        bubble.appendChild(senderDiv);
        bubble.appendChild(bodyDiv);
        bubble.appendChild(timeDiv);
        row.appendChild(bubble);
        stream.appendChild(row);

        const numId = Number(m.id);
        if (numId > lastMsgId) {
            lastMsgId = numId;
            stream.dataset.lastMsgId = String(numId);
        }
        scrollStreamToBottom();
    };

    const highlightThreadInList = (threadId) => {
        if (!threadsListEl) return;
        threadsListEl.querySelectorAll('[data-chat-thread-link]').forEach((item) => {
            const isMatch = String(item.dataset.chatThreadLink) === String(threadId);
            item.classList.toggle('is-active', isMatch);
            if (isMatch) {
                const unreadBadge = item.querySelector('[data-thread-unread]');
                if (unreadBadge) unreadBadge.remove();
            }
        });
    };

    const loadThreadPane = async (baseHref, threadId, { pushState = true } = {}) => {
        if (!paneEl || !baseHref) return;
        const paneUrl = baseHref.includes('?') ? `${baseHref}&pane=1` : `${baseHref}?pane=1`;
        setContainerLoading(paneEl, true);
        try {
            const res = await api.get(paneUrl, { abortKey: 'support-chat-pane' });
            if (typeof res.data?.html === 'string') {
                paneEl.innerHTML = res.data.html;
            }
            const nextId = res.data?.thread_id ? String(res.data.thread_id) : String(threadId || '');
            activeThreadId = nextId;
            if (activeThreadInput) {
                activeThreadInput.value = nextId;
                activeThreadInput.defaultValue = nextId;
            }
            readStreamMeta();
            scrollStreamToBottom();
            highlightThreadInList(nextId);
            syncNavUnread(res.data?.total_unread);

            if (pushState) {
                window.history.pushState({ threadId: nextId }, '', baseHref);
            }
        } catch (err) {
            if (err.name !== 'AbortError') {
                toast.error(err.message || 'تعذر تحميل المحادثة.');
            }
        } finally {
            setContainerLoading(paneEl, false);
        }
    };

    readStreamMeta();
    scrollStreamToBottom();

    // تبديل المحادثة من القائمة الجانبية بدون ريفريش
    if (threadsListEl) {
        threadsListEl.addEventListener('click', (e) => {
            const link = e.target.closest('[data-chat-thread-link]');
            if (!link) return;
            e.preventDefault();
            const href = link.getAttribute('href');
            const tid = link.dataset.chatThreadLink || '';
            if (tid && tid === activeThreadId) return;
            loadThreadPane(href, tid, { pushState: true });
        });
    }

    // زر الرجوع/التقدم في المتصفح بدون ريفريش
    window.addEventListener('popstate', (e) => {
        loadThreadPane(window.location.pathname, e.state?.threadId || '', { pushState: false });
    });

    // فلترة حالة المحادثات (الكل / مفتوحة / مغلقة) بدون ريفريش
    document.addEventListener('click', (e) => {
        const filterBtn = e.target.closest('[data-chat-status-filter]');
        if (!filterBtn || !filterForm || !statusInput) return;
        e.preventDefault();

        const nextStatus = filterBtn.dataset.chatStatusFilter ?? '';
        statusInput.value = nextStatus;
        statusInput.defaultValue = nextStatus;

        document.querySelectorAll('[data-chat-status-filter]').forEach((btn) => {
            const isActive = btn === filterBtn;
            btn.classList.toggle('ap-btn-primary', isActive);
            btn.classList.toggle('ap-btn-ghost', !isActive);
        });

        loadPartialFromForm(filterForm, { syncUrl: false });
    });

    if (searchInput) {
        searchInput.addEventListener('input', syncClearButton);
    }
    if (clearBtn) {
        clearBtn.addEventListener('click', () => {
            clearBtn.classList.add('ap-hidden');
        });
    }

    // إرسال الرد الفوري بتفويض الحدث لأن محتوى #apSupportChatPane يتبدل ديناميكياً
    document.addEventListener('submit', async (e) => {
        const form = e.target.closest('#apAdminChatForm');
        if (!form || form.dataset.apSending === '1') return;
        e.preventDefault();

        const input = form.querySelector('#apAdminChatInput');
        const submitBtn = form.querySelector('button[type="submit"]');
        const text = (input?.value || '').trim();
        if (!text) return;

        const fd = new FormData(form);
        form.dataset.apSending = '1';
        if (input) {
            input.value = '';
            input.disabled = true;
        }
        setButtonLoading(submitBtn, true);

        try {
                const actionUrl = form.getAttribute('action') || pollUrl || window.location.pathname;
                const payload = await api.request(actionUrl, {
                    method: 'POST',
                    body: fd,
                    form,
                });
                if(payload?.data?.message) {
                    appendMessage(payload.data.message);
                }
            if(payload?.data?.status) {
                    syncStatusUi(payload.data.status);
                }
            const previewEl = document.querySelector(`[data-thread-preview="${activeThreadId}"]`);
                if(previewEl) {
                    previewEl.textContent = payload?.data?.preview || text;
                }
            } catch (err) {
                if (input) input.value = text;
                toast.error(err.message || 'تعذر إرسال الرد.');
            } finally {
                delete form.dataset.apSending;
                if (input) {
                    input.disabled = false;
                    input.focus();
                }
                setButtonLoading(submitBtn, false);
            }
        });

    // مزامنة إغلاق / إعادة فتح المحادثة بدون ريفريش
    on('ap:form:success', ({ form, payload }) => {
        if (form.dataset.chatStatusForm !== '1') return;
        if (payload?.data?.status) {
            syncStatusUi(payload.data.status);
        }
        if (filterForm) {
            loadPartialFromForm(filterForm, { syncUrl: false });
        }
    });

    on('ap:partial:updated', () => {
        syncClearButton();
    });

    // التحديث اللحظي للرسائل الجديدة وقائمة المحادثات وعدّاد غير المقروء
    setInterval(async () => {
        if (document.hidden) return;
        const requestedThreadId = activeThreadId;
        const base = pollUrl || filterForm?.getAttribute('action') || window.location.pathname;
        const params = new URLSearchParams();
        params.set('poll', '1');
        params.set('after_id', String(lastMsgId));
        if (statusInput?.value) params.set('status', statusInput.value);
        if (searchInput?.value.trim()) params.set('q', searchInput.value.trim());
        if (requestedThreadId) params.set('active_thread_id', requestedThreadId);

        try {
            const resp = await fetch(`${base}?${params.toString()}`, {
                headers: {
                    'Accept': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                },
                credentials: 'same-origin',
            });
            if (!resp.ok) return;
            const data = await resp.json();
            if (!data || requestedThreadId !== activeThreadId) return;

            if (Array.isArray(data.messages)) {
                data.messages.forEach(appendMessage);
            }
            if (requestedThreadId && data.thread_status) {
                syncStatusUi(data.thread_status);
            }
            if (typeof data.total_unread === 'number') {
                syncNavUnread(data.total_unread);
            }
            if (threadsListEl && typeof data.threads_html === 'string') {
                const prevScroll = threadsListEl.scrollTop;
                threadsListEl.innerHTML = data.threads_html;
                threadsListEl.scrollTop = prevScroll;
            }
        } catch (_) { }
    }, 4500);
}
