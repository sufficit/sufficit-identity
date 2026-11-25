// Clipboard values stay in the authenticated form; never log, persist or auto-submit them.
export async function readClipboard() {
    if (!globalThis.isSecureContext || !navigator.clipboard?.readText) return null;
    try {
        const value = await navigator.clipboard.readText();
        return value.length > 0 && value.length <= 16384 ? value : null;
    } catch {
        return null; // Native paste remains available when permission/activation is missing.
    }
}

export function openSecretReveal(dialog, name) {
    if (dialog.open) return;

    const lifecycle = new AbortController();
    const { signal } = lifecycle;
    const form = dialog.querySelector("[data-challenge]");
    const code = form.elements.namedItem("code");
    const loading = dialog.querySelector("[data-loading]");
    const error = dialog.querySelector("[data-error-message]");
    const setup = dialog.querySelector("[data-setup]");
    const value = dialog.querySelector("[data-value]");
    const submit = form.querySelector('button[type="submit"]');
    let expiry;
    let expiresAt = 0;

    function clearValue() {
        value.textContent = "";
        value.hidden = true;
        clearTimeout(expiry);
        expiresAt = 0;
    }

    function cleanUp() {
        lifecycle.abort();
        clearValue();
        code.value = "";
    }

    function challenge() {
        clearValue();
        form.hidden = false;
        code.focus();
    }

    async function request() {
        const data = new FormData(form);
        data.set("name", name);
        code.value = "";
        const start = performance.now();
        loading.hidden = false;
        error.hidden = true;
        submit.disabled = true;
        try {
            const response = await fetch(form.action, {
                method: "POST",
                body: data,
                cache: "no-store",
                redirect: "error",
                signal
            });
            data.delete("code");
            if (!response.ok) throw new Error();
            const result = await response.json();
            if (signal.aborted || !dialog.open) return;

            switch (result.status) {
                case "Revealed": {
                    const remaining = result.remainingMs - (performance.now() - start);
                    if (remaining <= 0) {
                        challenge();
                        break;
                    }
                    form.hidden = true;
                    value.textContent = result.value;
                    value.hidden = false;
                    expiresAt = Date.now() + remaining;
                    expiry = setTimeout(challenge, remaining);
                    break;
                }
                case "Challenge":
                    challenge();
                    break;
                case "InvalidCode":
                    error.textContent = dialog.dataset.invalid;
                    error.hidden = false;
                    challenge();
                    break;
                default: {
                    const messages = {
                        AuthenticatorRequired: dialog.dataset.authenticator,
                        Unauthorized: dialog.dataset.unauthorized,
                        LockedOut: dialog.dataset.locked,
                        NotFound: dialog.dataset.notFound
                    };
                    form.hidden = true;
                    setup.hidden = result.status !== "AuthenticatorRequired";
                    error.textContent = messages[result.status] ?? dialog.dataset.error;
                    error.hidden = false;
                    break;
                }
            }
        } catch {
            if (!signal.aborted && dialog.open) {
                error.textContent = dialog.dataset.error;
                error.hidden = false;
            }
        } finally {
            data.delete("code");
            if (!signal.aborted) {
                loading.hidden = true;
                submit.disabled = false;
            }
        }
    }

    form.hidden = true;
    setup.hidden = true;
    clearValue();
    dialog.querySelector("[data-name]").textContent = name;
    dialog.addEventListener("close", cleanUp, { once: true, signal });
    dialog.addEventListener("cancel", cleanUp, { once: true, signal });
    dialog.querySelector("[data-close]").addEventListener("submit", cleanUp, { once: true, signal });
    window.addEventListener("pagehide", () => {
        cleanUp();
        dialog.close();
    }, { once: true, signal });
    document.addEventListener("visibilitychange", () => {
        if (!document.hidden && expiresAt && Date.now() >= expiresAt) challenge();
    }, { signal });
    form.addEventListener("submit", event => {
        event.preventDefault();
        if (!submit.disabled) void request();
    }, { signal });
    dialog.showModal();
    void request();
}
