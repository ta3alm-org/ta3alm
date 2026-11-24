

import { emit } from '../core/events.js';

export function activateTab(tabGroup, tabId, { syncUrl = false } = {}) {
    if (!tabGroup || !tabId) return;
    const buttons = tabGroup.querySelectorAll('[data-tab-target]');
    const groupName = tabGroup.dataset.tabs;
    const panelsScope = tabGroup.dataset.tabsContainer
        ? document.querySelector(tabGroup.dataset.tabsContainer)
        : document;

    buttons.forEach((btn) => {
        const active = btn.dataset.tabTarget === tabId;
        btn.classList.toggle('active', active);
        btn.setAttribute('aria-selected', active ? 'true' : 'false');
    });

    if (panelsScope) {
        panelsScope.querySelectorAll(`.ap-tab-panel[data-tab-group="${groupName}"]`).forEach((panel) => {
            const active = panel.id === tabId || panel.dataset.tabId === tabId;
            panel.classList.toggle('active', active);
        });
    }

    if (syncUrl) {
        const url = new URL(window.location.href);
        url.searchParams.set('tab', tabId.replace(/^tab-/, ''));
        window.history.replaceState({}, '', url.toString());
    }

    emit('ap:tab:changed', { group: groupName, tabId });
}

export function initTabs() {
    document.addEventListener('click', (e) => {
        const btn = e.target.closest('[data-tabs] [data-tab-target]');
        if (!btn) return;
        e.preventDefault();
        const group = btn.closest('[data-tabs]');
        const syncUrl = group.dataset.tabsSyncUrl === '1';
        activateTab(group, btn.dataset.tabTarget, { syncUrl });
    });


    const urlTab = new URLSearchParams(window.location.search).get('tab');
    if (urlTab) {
        document.querySelectorAll('[data-tabs][data-tabs-sync-url="1"]').forEach((group) => {
            const candidate = group.querySelector(`[data-tab-target="tab-${urlTab}"], [data-tab-target="${urlTab}"]`);
            if (candidate) activateTab(group, candidate.dataset.tabTarget);
        });
    }
}
