// Sufficit Identity UI — browser-side helpers
// Exposed globally as window.sufficitIdentity* so Blazor components can
// call them via JS interop (IJSRuntime.InvokeVoidAsync).

/**
 * Triggers a browser file download from a base64-encoded payload.
 * Used by PersonalData.razor to download the LGPD JSON.
 *
 * @param {string} fileName - Suggested file name.
 * @param {string} base64 - Base64-encoded file contents.
 * @param {string} [mimeType='application/octet-stream'] - MIME type.
 */
window.sufficitIdentityDownloadFile = function (fileName, base64, mimeType) {
    mimeType = mimeType || 'application/octet-stream';
    var bytes = atob(base64);
    var len = bytes.length;
    var u8 = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
        u8[i] = bytes.charCodeAt(i);
    }
    var blob = new Blob([u8], { type: mimeType });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 0);
};

/**
 * Persists the selected UI culture through a regular HTTP request. This is
 * deliberately browser-side rather than Blazor interop: the localization
 * cookie must be written on a fresh response, and the delegated listener also
 * works on statically rendered authentication pages.
 */
document.addEventListener('change', function (event) {
    var selector = event.target.closest('[data-culture-selector] select[name="culture"]');
    if (!selector || !selector.form) return;
    selector.form.requestSubmit();
});

/**
 * Ends the browser side of an RFC 8628 device flow. The close request is made
 * only from the explicit button gesture: browsers reject automatic close
 * attempts for user-created tabs and those attempts cannot be upgraded later.
 * When closing is blocked, the terminal page remains visible and explains the
 * manual action.
 */
(function () {
    function showManualCompletion(result) {
        var fallback = document.querySelector('[data-device-close-fallback]');
        if (fallback) {
            fallback.hidden = false;
            fallback.tabIndex = -1;
            // Move focus to the actionable explanation without stealing focus
            // from a successful close (this function only runs when close was
            // blocked).
            if (typeof fallback.focus === 'function') fallback.focus();
        }

        var button = document.querySelector('[data-device-flow-close]');
        if (button) {
            // A user-created tab cannot become script-closable after the
            // first attempt. Hide the control so it cannot produce repeated
            // browser warnings or imply that another click may succeed.
            button.hidden = true;
            button.disabled = true;
            button.setAttribute('aria-disabled', 'true');
        }

        if (result) {
            result.removeAttribute('aria-busy');
            result.dataset.deviceCloseBlocked = 'true';
        }

        if (typeof console !== 'undefined' && typeof console.warn === 'function' &&
            (!result || result.dataset.deviceCloseWarningShown !== 'true')) {
            if (result) result.dataset.deviceCloseWarningShown = 'true';
            console.warn(
                '[Sufficit Identity] O navegador bloqueou o fechamento desta aba. ' +
                'Use o controle de abas para encerrá-la.',
                { hasOpener: Boolean(window.opener && !window.opener.closed) });
        }
    }

    function tryCloseWindow() {
        try {
            window.close();
        } catch (_) {
            // Some browsers throw when script closure is disallowed.
        }

        if (window.closed) {
            return window.closed;
        }

        // Firefox and some Chromium versions require the current browsing
        // context to be retargeted before accepting a close requested by a
        // direct user gesture. This path is reached only from the button.
        try {
            var currentWindow = window.open('', '_self');
            if (currentWindow) currentWindow.close();
        } catch (_) {
            // The manual completion message below remains the safe fallback.
        }

        return window.closed;
    }

    function closeDeviceFlowTab(result) {
        if (result && result.dataset.deviceCloseAttempted === 'true') return;
        if (result) result.dataset.deviceCloseAttempted = 'true';
        if (result) result.setAttribute('aria-busy', 'true');
        var button = document.querySelector('[data-device-flow-close]');
        if (button) button.disabled = true;

        if (tryCloseWindow()) {
            return;
        }

        // If execution continues, the browser kept the tab open. Delay the
        // fallback just enough to avoid flashing it during a successful close.
        window.setTimeout(function () {
            showManualCompletion(result);
        }, 250);
    }

    function initializeDeviceFlowClose() {
        var result = document.querySelector('[data-device-flow-result]');
        if (!result || result.dataset.deviceCloseInitialized === 'true') return;

        result.dataset.deviceCloseInitialized = 'true';

        var closeButton = document.querySelector('[data-device-flow-close]');
        if (closeButton && closeButton.dataset.deviceCloseBound !== 'true') {
            closeButton.dataset.deviceCloseBound = 'true';
            closeButton.hidden = false;
            closeButton.setAttribute('aria-describedby', 'device-close-fallback');
            closeButton.addEventListener('click', function () {
                closeDeviceFlowTab(result);
            });
        }
    }

    function subscribeToEnhancedLoads() {
        if (!window.Blazor || typeof window.Blazor.addEventListener !== 'function') {
            return false;
        }

        window.Blazor.addEventListener('enhancedload', initializeDeviceFlowClose);
        return true;
    }

    initializeDeviceFlowClose();
    document.addEventListener('DOMContentLoaded', initializeDeviceFlowClose, { once: true });
    window.addEventListener('load', initializeDeviceFlowClose, { once: true });

    // identity.js is loaded before blazor.web.js. Subscribe as soon as Blazor
    // exposes its enhanced navigation events so a replaced terminal page gets
    // the same close behavior as a full page load.
    if (!subscribeToEnhancedLoads()) {
        window.addEventListener('load', function () {
            initializeDeviceFlowClose();
            subscribeToEnhancedLoads();
        }, { once: true });
    }
})();

/**
 * External-login redirect overlay.
 * Shows a full-page "connecting…" overlay when the user clicks an
 * external-login link (Google/Facebook). Pages are statically rendered
 * (no Blazor interactivity), so this is plain JS with a delegated
 * listener that survives page navigation.
 */
(function () {
    document.addEventListener('click', function (e) {
        var el = e.target.closest('[data-redirect-overlay]');
        if (!el || document.querySelector('.redirect-overlay')) return;
        var overlay = document.createElement('div');
        overlay.className = 'redirect-overlay';
        overlay.innerHTML =
            '<div class="redirect-overlay-box">' +
            '<div class="spinner"></div>' +
            '<p>Conectando a ' + el.getAttribute('data-redirect-overlay') + '…</p>' +
            '<p class="redirect-overlay-hint">Você será redirecionado automaticamente.</p>' +
            '</div>';
        document.body.appendChild(overlay);
    });
})();
