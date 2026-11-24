

import { getCsrfToken } from './csrf.js';
import { toast } from './notifications.js';

const activeControllers = new Map();

export class ApiError extends Error {
    constructor(message, { status = 0, errors = {}, data = {} } = {}) {
        super(message || 'حدث خطأ غير متوقع.');
        this.name = 'ApiError';
        this.status = status;
        this.errors = errors || {};
        this.data = data || {};
    }
}

export async function request(url, options = {}) {
    const {
        method = 'GET',
        body = null,
        headers = {},
        form = null,
        abortKey = null,
        silentAuthError = false,
        signal = null,
    } = options;

    const upperMethod = String(method).toUpperCase();
    let finalSignal = signal;

    if (abortKey) {
        const prev = activeControllers.get(abortKey);
        if (prev) prev.abort();
        const controller = new AbortController();
        activeControllers.set(abortKey, controller);
        finalSignal = controller.signal;
    }

    const reqHeaders = {
        'X-Requested-With': 'XMLHttpRequest',
        'Accept': 'application/json',
        ...headers,
    };

    if (!['GET', 'HEAD', 'OPTIONS', 'TRACE'].includes(upperMethod)) {
        const token = getCsrfToken(form);
        if (token) reqHeaders['X-CSRFToken'] = token;
    }

    let reqBody = body;
    if (reqBody && !(reqBody instanceof FormData) && !(reqBody instanceof URLSearchParams) && typeof reqBody === 'object') {
        if (!reqHeaders['Content-Type']) {
            reqHeaders['Content-Type'] = 'application/x-www-form-urlencoded;charset=UTF-8';
            const params = new URLSearchParams();
            Object.entries(reqBody).forEach(([k, v]) => {
                if (Array.isArray(v)) {
                    v.forEach((item) => params.append(k, String(item)));
                } else if (v !== undefined && v !== null) {
                    params.append(k, String(v));
                }
            });
            reqBody = params;
        }
    }

    let response;
    try {
        response = await fetch(url, {
            method: upperMethod,
            headers: reqHeaders,
            body: ['GET', 'HEAD'].includes(upperMethod) ? undefined : reqBody,
            credentials: 'same-origin',
            signal: finalSignal,
        });
    } catch (err) {
        if (err.name === 'AbortError') throw err;
        throw new ApiError('تعذر الاتصال بالخادم. تحقق من اتصال الشبكة.', { status: 0 });
    } finally {
        if (abortKey && activeControllers.get(abortKey)?.signal === finalSignal) {
            activeControllers.delete(abortKey);
        }
    }

    const contentType = response.headers.get('content-type') || '';
    let payload = null;
    if (contentType.includes('application/json')) {
        try {
            payload = await response.json();
        } catch (_) {
            payload = null;
        }
    }

    if (response.status === 401) {
        const msg = payload?.message || 'انتهت جلسة العمل. يرجى تسجيل الدخول مجدداً.';
        if (!silentAuthError) toast.warning(msg);
        if (payload?.data?.login_url) {
            setTimeout(() => {
                window.location.href = payload.data.login_url;
            }, 900);
        }
        throw new ApiError(msg, { status: 401, data: payload?.data || {} });
    }

    if (!response.ok || (payload && payload.success === false)) {
        const msg = payload?.message || (
            response.status === 403
                ? 'ليس لديك صلاحية لتنفيذ هذا الإجراء.'
                : response.status === 404
                    ? 'العنصر المطلوب غير موجود.'
                    : 'حدث خطأ أثناء معالجة الطلب.'
        );
        throw new ApiError(msg, {
            status: response.status,
            errors: payload?.errors || {},
            data: payload?.data || {},
        });
    }

    return payload || { success: true, message: '', data: {}, errors: {} };
}

export function get(url, options = {}) {
    return request(url, { ...options, method: 'GET' });
}

export function post(url, body = null, options = {}) {
    return request(url, { ...options, method: 'POST', body });
}

export const api = { request, get, post, ApiError };
