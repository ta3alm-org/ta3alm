

export function getCsrfToken(form = null) {
    if (form) {
        const input = form.querySelector('input[name="csrfmiddlewaretoken"]');
        if (input && input.value) return input.value;
    }
    const meta = document.querySelector('meta[name="csrf-token"]');
    if (meta && meta.content && meta.content !== 'NOTPROVIDED') {
        return meta.content;
    }
    const cookieMatch = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]+)/);
    if (cookieMatch) {
        return decodeURIComponent(cookieMatch[1]);
    }
    const anyInput = document.querySelector('input[name="csrfmiddlewaretoken"]');
    return anyInput ? anyInput.value : '';
}
