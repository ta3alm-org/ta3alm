(function () {
    'use strict';

    var noop = function () {};
    if (window.console) {
        ['log', 'debug', 'info', 'warn', 'dir', 'table', 'trace', 'group', 'groupCollapsed'].forEach(function (fn) {
            try {
                window.console[fn] = noop;
            } catch (_) {}
        });
    }

    function isEditableTarget(el) {
        if (!el || !el.tagName) return false;
        var tag = el.tagName.toUpperCase();
        if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return true;
        return Boolean(el.isContentEditable);
    }

    document.addEventListener('contextmenu', function (e) {
        if (!isEditableTarget(e.target)) {
            e.preventDefault();
        }
    }, true);

    document.addEventListener('dragstart', function (e) {
        if (!isEditableTarget(e.target)) {
            e.preventDefault();
        }
    }, true);

    document.addEventListener('keydown', function (e) {
        var key = (e.key || '').toUpperCase();
        var ctrlOrMeta = e.ctrlKey || e.metaKey;
        if (
            e.keyCode === 123 ||
            key === 'F12' ||
            (ctrlOrMeta && e.shiftKey && (key === 'I' || key === 'J' || key === 'C' || key === 'K')) ||
            (ctrlOrMeta && !e.shiftKey && (key === 'U' || key === 'S' || key === 'P'))
        ) {
            e.preventDefault();
            e.stopPropagation();
            return false;
        }
    }, true);

    var shieldId = 'ta3almDevtoolsShield';
    var shieldActive = false;

    function pauseAllMedia() {
        try {
            document.querySelectorAll('video, audio').forEach(function (m) {
                if (typeof m.pause === 'function') m.pause();
            });
            document.querySelectorAll('iframe').forEach(function (fr) {
                try {
                    if (fr.contentWindow) {
                        fr.contentWindow.postMessage('{"event":"command","func":"pauseVideo","args":""}', '*');
                    }
                } catch (_) {}
            });
        } catch (_) {}
    }

    function showShield() {
        if (shieldActive) return;
        shieldActive = true;
        pauseAllMedia();
        var el = document.getElementById(shieldId);
        if (!el && document.body) {
            el = document.createElement('div');
            el.id = shieldId;
            el.style.cssText = 'position:fixed;inset:0;z-index:2147483647;background:rgba(10,14,23,0.97);color:#fff;display:flex;align-items:center;justify-content:center;text-align:center;padding:24px;font-family:Cairo,sans-serif;direction:rtl;';
            el.innerHTML = '<div style="max-width:440px"><div style="font-size:44px;margin-bottom:12px;">&#128274;</div><h3 style="margin:0 0 8px;font-weight:800;">تم إيقاف العرض لحماية المحتوى</h3><p style="margin:0;opacity:.82;line-height:1.7;">يرجى إغلاق أدوات المطور أو أي نافذة فحص للمتابعة بشكل آمن.</p></div>';
            document.body.appendChild(el);
        } else if (el) {
            el.style.display = 'flex';
        }
        try {
            if (window.console && typeof window.console.clear === 'function') {
                window.console.clear();
            }
        } catch (_) {}
    }

    function hideShield() {
        if (!shieldActive) return;
        shieldActive = false;
        var el = document.getElementById(shieldId);
        if (el) el.style.display = 'none';
    }

    function checkDevTools() {
        try {
            var isDesktop = !/Android|iPhone|iPad|iPod|Mobile/i.test(navigator.userAgent || '');
            if (!isDesktop || document.fullscreenElement) {
                hideShield();
                return;
            }
            var widthDiff = Math.abs((window.outerWidth || 0) - (window.innerWidth || 0));
            var heightDiff = Math.abs((window.outerHeight || 0) - (window.innerHeight || 0));
            if (widthDiff > 190 || heightDiff > 190) {
                showShield();
            } else {
                hideShield();
            }
        } catch (_) {}
    }

    window.addEventListener('resize', checkDevTools);
    setInterval(checkDevTools, 1200);

    try {
        var origFetch = window.fetch;
        if (typeof origFetch === 'function') {
            window.fetch = function () {
                return origFetch.apply(this, arguments).then(function (resp) {
                    if (resp && resp.status === 403) {
                        try {
                            resp.clone().json().then(function (d) {
                                if (d && (d.code === 'DEVICE_BLOCKED' || d.code === 'ACCOUNT_BANNED' || d.is_banned === true)) {
                                    window.location.reload();
                                }
                            }).catch(function () {});
                        } catch (_) {}
                    }
                    return resp;
                });
            };
        }
    } catch (_) {}
})();
