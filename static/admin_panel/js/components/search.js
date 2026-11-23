/**
 * البحث الحي بالخادم (Partial HTML Fetch + Debounce) وموجّه الانتقال السريع (Ctrl+K).
 */
import { api } from '../core/api.js';
import { emit } from '../core/events.js';
import { setContainerLoading } from '../core/loading.js';
import { closeModal, openModal } from '../core/modal.js';
import { toast } from '../core/notifications.js';

export async function loadPartialFromForm(form, { syncUrl = true } = {}) {
    const targetSelector = form.dataset.filterTarget;
    const targetEl = targetSelector ? document.querySelector(targetSelector) : null;
    if (!targetEl) return;

    const baseUrl = form.getAttribute('action') || window.location.pathname;
    const params = new URLSearchParams(new FormData(form));
    const displayParams = new URLSearchParams(params);
    params.set('partial', '1');

    setContainerLoading(targetEl, true);
    try {
        const res = await api.get(`${baseUrl}?${params.toString()}`, {
            abortKey: `live-filter:${targetSelector}`,
        });
        if (typeof res.data?.html === 'string') {
            targetEl.innerHTML = res.data.html;
        }
        if (syncUrl) {
            const cleanQuery = displayParams.toString();
            const nextUrl = cleanQuery ? `${baseUrl}?${cleanQuery}` : baseUrl;
            window.history.replaceState({}, '', nextUrl);
        }
        emit('ap:partial:updated', { form, targetEl, data: res.data || {} });
    } catch (err) {
        if (err.name !== 'AbortError') {
            toast.error(err.message || 'تعذر تحديث البيانات.');
        }
    } finally {
        setContainerLoading(targetEl, false);
    }
}

function initQuickJump() {
    const modal = document.getElementById('apQuickJumpModal');
    const trigger = document.getElementById('apQuickJumpTrigger');
    const input = document.getElementById('apQuickJumpInput');
    const list = document.getElementById('apQuickJumpList');
    if (!modal || !input || !list) return;

    const items = Array.from(document.querySelectorAll('.ap-sidebar-scroll .ap-nav-link[href]')).map((a) => ({
        title: (a.querySelector('.ap-nav-label')?.textContent || a.textContent || '').trim(),
        href: a.getAttribute('href'),
        icon: a.querySelector('i')?.className || 'bi bi-arrow-left',
        target: a.getAttribute('target') || '',
    }));

    const renderList = (query = '') => {
        list.innerHTML = '';
        const q = query.trim().toLowerCase();
        const filtered = q ? items.filter((it) => it.title.toLowerCase().includes(q)) : items;
        if (!filtered.length) {
            const empty = document.createElement('div');
            empty.className = 'ap-muted ap-sm';
            empty.style.padding = '16px';
            empty.style.textAlign = 'center';
            empty.textContent = 'لا توجد صفحات مطابقة.';
            list.appendChild(empty);
            return;
        }
        filtered.forEach((it, idx) => {
            const a = document.createElement('a');
            a.className = `ap-cmd-item${idx === 0 ? ' is-selected' : ''}`;
            a.href = it.href;
            if (it.target) a.target = it.target;
            const left = document.createElement('span');
            left.className = 'ap-flex ap-items-center ap-gap-2';
            const icon = document.createElement('i');
            icon.className = it.icon;
            const span = document.createElement('span');
            span.textContent = it.title;
            left.appendChild(icon);
            left.appendChild(span);

            const hint = document.createElement('span');
            hint.className = 'ap-xs ap-subtle-text';
            hint.textContent = 'انتقال';

            a.appendChild(left);
            a.appendChild(hint);
            list.appendChild(a);
        });
    };

    const openQuickJump = () => {
        input.value = '';
        renderList('');
        openModal(modal);
    };

    if (trigger) trigger.addEventListener('click', openQuickJump);
    input.addEventListener('input', () => renderList(input.value));
    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            const first = list.querySelector('.ap-cmd-item');
            if (first) {
                e.preventDefault();
                closeModal(modal);
                window.location.href = first.getAttribute('href');
            }
        }
    });

    document.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
            e.preventDefault();
            openQuickJump();
        }
    });
}

export function initLiveSearchAndFilters() {
    const timers = new WeakMap();

    document.addEventListener('submit', (e) => {
        const form = e.target.closest('form[data-live-filter-form]');
        if (!form) return;
        e.preventDefault();
        loadPartialFromForm(form);
    });

    document.addEventListener('input', (e) => {
        const input = e.target;
        const form = input.closest('form[data-live-filter-form]');
        if (!form || input.tagName === 'SELECT') return;

        clearTimeout(timers.get(form));
        timers.set(form, setTimeout(() => loadPartialFromForm(form), 300));
    });

    document.addEventListener('change', (e) => {
        const el = e.target;
        const form = el.closest('form[data-live-filter-form]');
        if (!form || el.tagName !== 'SELECT') return;
        loadPartialFromForm(form);
    });

    document.addEventListener('click', (e) => {
        const resetBtn = e.target.closest('[data-filter-reset]');
        if (!resetBtn) return;
        const form = resetBtn.closest('form[data-live-filter-form]');
        if (!form) return;
        e.preventDefault();
        form.reset();
        form.querySelectorAll('input[type="text"], input[type="search"]').forEach((inp) => {
            inp.value = '';
        });
        form.querySelectorAll('select').forEach((sel) => {
            sel.value = '';
        });
        loadPartialFromForm(form);
    });

    initQuickJump();
}
