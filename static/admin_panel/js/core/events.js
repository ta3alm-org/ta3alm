/**
 * ناقل أحداث خفيف للتواصل بين مكونات لوحة الإدارة بدون ترابط مباشر.
 */
const listeners = new Map();

export function on(eventName, handler) {
    if (!listeners.has(eventName)) {
        listeners.set(eventName, new Set());
    }
    listeners.get(eventName).add(handler);
    return () => off(eventName, handler);
}

export function off(eventName, handler) {
    const set = listeners.get(eventName);
    if (set) set.delete(handler);
}

export function emit(eventName, detail = {}) {
    const set = listeners.get(eventName);
    if (set) {
        set.forEach((fn) => {
            try {
                fn(detail);
            } catch (err) {
                console.error(`[ap:event:${eventName}]`, err);
            }
        });
    }
    document.dispatchEvent(new CustomEvent(eventName, { detail }));
}
