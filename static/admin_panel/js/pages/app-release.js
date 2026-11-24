

import { on } from '../core/events.js';

export function initAppReleasePage() {
    on('ap:form:success', ({ form, payload }) => {
        if (form.id !== 'appReleaseForm') return;
        const data = payload?.data || {};

        const verStat = document.getElementById('appReleaseLatestStat');
        const minStat = document.getElementById('appReleaseMinStat');
        const sourceBadge = document.getElementById('appReleaseSourceBadge');
        const fpCountEl = document.getElementById('appReleaseFpCount');
        const preEl = document.getElementById('assetlinksPreviewPre');
        const currentLinkBox = document.getElementById('appReleaseCurrentUrlBox');

        if (verStat && data.latest_version_name) {
            verStat.textContent = `v${data.latest_version_name} (+${data.latest_version_code})`;
        }
        if (minStat && typeof data.min_required_version_code !== 'undefined') {
            minStat.textContent = `أقل بناء مسموح: ${data.min_required_version_code}`;
        }
        if (sourceBadge) {
            if (data.android_apk_url) {
                sourceBadge.className = 'ap-badge ap-badge-success';
                sourceBadge.textContent = 'رابط خارجي (GitHub / CDN)';
            } else if (data.has_apk_file) {
                sourceBadge.className = 'ap-badge ap-badge-warning';
                sourceBadge.textContent = 'ملف مرفوع على الخادم';
            } else {
                sourceBadge.className = 'ap-badge ap-badge-danger';
                sourceBadge.textContent = 'غير مضبوط بعد';
            }
        }
        if (fpCountEl && typeof data.assetlinks_fingerprints_count !== 'undefined') {
            fpCountEl.textContent = String(data.assetlinks_fingerprints_count);
        }
        if (preEl && data.assetlinks_preview) {
            preEl.textContent = data.assetlinks_preview;
        }
        if (currentLinkBox) {
            const linkEl = currentLinkBox.querySelector('a');
            if (data.android_apk_url && linkEl) {
                linkEl.href = data.android_apk_url;
                linkEl.textContent = data.android_apk_url;
                currentLinkBox.classList.remove('ap-hidden');
            } else {
                currentLinkBox.classList.add('ap-hidden');
            }
        }
    });
}
