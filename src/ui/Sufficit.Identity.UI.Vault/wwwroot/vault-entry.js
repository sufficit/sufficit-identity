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

export function mountSecretReveal(content, name) {
    const lifecycle = new AbortController();
    const { signal } = lifecycle;
    const form = content.querySelector("[data-challenge]");
    const code = form.elements.namedItem("code");
    const loading = content.querySelector("[data-loading]");
    const errorContainer = content.querySelector("[data-error-container]");
    const error = content.querySelector("[data-error-message]");
    const setup = content.querySelector("[data-setup]");
    const value = content.querySelector("[data-value]");
    const confirm = content.querySelector("[data-confirm]");
    const submit = confirm.querySelector("button");
    const close = content.querySelector("[data-close]");
    let expiry;
    let expiresAt = 0;

    function clearValue() {
        value.textContent = "";
        value.hidden = true;
        clearTimeout(expiry);
        expiresAt = 0;
    }

    function cleanUp() {
        removed.disconnect();
        lifecycle.abort();
        clearValue();
        code.value = "";
    }

    function setChallenge(visible) {
        form.hidden = !visible;
        confirm.hidden = !visible;
        code.disabled = !visible;
        submit.disabled = !visible;
    }

    function challenge() {
        clearValue();
        setChallenge(true);
        code.focus();
    }

    function showError(message) {
        error.textContent = message;
        errorContainer.hidden = false;
    }

    async function request() {
        const data = new FormData(form);
        data.set("name", name);
        code.value = "";
        const start = performance.now();
        loading.hidden = false;
        errorContainer.hidden = true;
        code.removeAttribute("aria-invalid");
        submit.disabled = true;
        code.disabled = true;
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
            if (signal.aborted || !content.isConnected) return;

            switch (result.status) {
                case "Revealed": {
                    const remaining = result.remainingMs - (performance.now() - start);
                    if (remaining <= 0) {
                        challenge();
                        break;
                    }
                    setChallenge(false);
                    value.textContent = result.value;
                    value.hidden = false;
                    close.focus();
                    expiresAt = Date.now() + remaining;
                    expiry = setTimeout(challenge, remaining);
                    break;
                }
                case "Challenge":
                    challenge();
                    break;
                case "InvalidCode":
                    code.setAttribute("aria-invalid", "true");
                    showError(content.dataset.invalid);
                    challenge();
                    break;
                default: {
                    const messages = {
                        AuthenticatorRequired: content.dataset.authenticator,
                        Unauthorized: content.dataset.unauthorized,
                        LockedOut: content.dataset.locked,
                        NotFound: content.dataset.notFound
                    };
                    setChallenge(false);
                    setup.hidden = result.status !== "AuthenticatorRequired";
                    showError(messages[result.status] ?? content.dataset.error);
                    break;
                }
            }
        } catch {
            if (!signal.aborted && content.isConnected) showError(content.dataset.error);
        } finally {
            data.delete("code");
            if (!signal.aborted) {
                loading.hidden = true;
                submit.disabled = form.hidden;
                code.disabled = form.hidden;
            }
        }
    }

    const removed = new MutationObserver(() => {
        if (!content.isConnected) cleanUp();
    });
    removed.observe(document.body, { childList: true, subtree: true });
    window.addEventListener("pagehide", event => {
        cleanUp();
        if (event.persisted) {
            window.addEventListener("pageshow", () => {
                if (content.isConnected) close.click();
            }, { once: true });
        }
    }, { once: true, signal });
    document.addEventListener("visibilitychange", () => {
        if (!document.hidden && expiresAt && Date.now() >= expiresAt) challenge();
    }, { signal });
    close.addEventListener("click", cleanUp, { once: true, signal });
    form.addEventListener("submit", event => {
        event.preventDefault();
        if (!submit.disabled) void request();
    }, { signal });
    setChallenge(false);
    void request();
}
