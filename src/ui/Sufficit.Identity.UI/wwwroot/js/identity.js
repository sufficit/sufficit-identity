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
 * Ends the browser side of an RFC 8628 device flow. Browsers only allow a
 * script to close a tab when it was opened by script, so a tab without an
 * opener goes straight to the manual completion state. This avoids both a
 * misleading close button and browser warnings in the console.
 */
(function () {
    function logDeviceFlow(event, details) {
        if (typeof console === 'undefined' || typeof console.info !== 'function') {
            return;
        }

        // Keep browser diagnostics useful without leaking device codes,
        // tokens, user identifiers, redirect URIs, or authorization payloads.
        console.info('[Sufficit Identity][DeviceFlow]', event, details || {});
    }

    function canAttemptScriptClose() {
        try {
            return Boolean(window.opener && !window.opener.closed);
        } catch (_) {
            // A cross-origin or otherwise inaccessible opener is not a safe
            // signal that this tab may be closed by script.
            return false;
        }
    }

    function showManualCompletion(result, reason) {
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
            if (result.dataset.deviceCloseManualLogged !== 'true') {
                result.dataset.deviceCloseManualLogged = 'true';
                logDeviceFlow('manual-close-instructions-shown', {
                    reason: reason || 'close-blocked'
                });
            }
        } else {
            logDeviceFlow('manual-close-instructions-shown', {
                reason: reason || 'close-blocked'
            });
        }
    }

    function tryCloseWindow() {
        if (!canAttemptScriptClose()) {
            return false;
        }

        // Keep both close strategies: window.close() works in browsers that
        // honor the direct script-created context, while retargeting the
        // current context before closing is required by other browsers. They
        // are complementary, not interchangeable; removing either one can
        // regress a browser-specific device-flow scenario. The opener gate
        // above is equally important because manually opened tabs must not
        // invoke either method and trigger a blocked-close warning.
        logDeviceFlow('script-close-attempted', { strategy: 'direct' });
        try {
            window.close();
        } catch (_) {
            // Some browsers throw when script closure is disallowed.
        }

        if (window.closed === true) {
            logDeviceFlow('script-close-succeeded', { strategy: 'direct' });
            return true;
        }

        logDeviceFlow('script-close-attempted', { strategy: 'retargeted' });
        try {
            var currentWindow = window.open('', '_self');
            if (currentWindow) currentWindow.close();
        } catch (_) {
            // The manual completion message below remains the safe fallback.
        }

        var closed = window.closed === true;
        logDeviceFlow(closed ? 'script-close-succeeded' : 'script-close-blocked', {
            strategy: 'retargeted'
        });
        return closed;
    }

    function closeDeviceFlowTab(result) {
        // The actual close request remains reachable only from the button.
        if (result && result.dataset.deviceCloseAttempted === 'true') return;
        logDeviceFlow('close-requested', { source: 'user-gesture' });
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
            showManualCompletion(result, 'close-blocked');
        }, 250);
    }

    function initializeDeviceFlowClose() {
        var result = document.querySelector('[data-device-flow-result]');
        if (!result || result.dataset.deviceCloseInitialized === 'true') return;

        result.dataset.deviceCloseInitialized = 'true';

        var closeButton = document.querySelector('[data-device-flow-close]');
        if (!canAttemptScriptClose()) {
            logDeviceFlow('manual-close-required', { reason: 'tab-not-script-opened' });
            showManualCompletion(result, 'tab-not-script-opened');
            return;
        }

        logDeviceFlow('close-control-initialized', { scriptClosable: true });

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
 * Keeps the OAuth consent screen honest when the authorization response is
 * handed to an external protocol handler (for example vscode://). Browsers
 * can leave the current tab visible after launching that handler, so the
 * explicit submit gesture gets an immediate, accessible terminal state. The
 * form still performs a normal navigation and remains fully functional with
 * JavaScript disabled.
 */
(function () {
    function initializeConsentSubmit() {
        var form = document.querySelector('[data-consent-form]');
        if (!form || form.dataset.consentSubmitBound === 'true') return;

        form.dataset.consentSubmitBound = 'true';
        form.addEventListener('submit', function () {
            if (form.dataset.consentSubmitted === 'true') return;
            form.dataset.consentSubmitted = 'true';
            form.setAttribute('aria-busy', 'true');

            var completion = form.querySelector('[data-consent-submitted]');
            if (completion) completion.hidden = false;

            // The submitter and checked scopes are part of the form data. A
            // control disabled synchronously from this event is excluded by
            // the browser before the POST body is built, which drops both
            // `consent_decision` and `scope` and sends the user back to an
            // empty consent page. Defer the visual lock until after the
            // browser has captured the form data for navigation.
            window.setTimeout(function () {
                var controls = form.querySelectorAll('button, input[type="checkbox"]');
                for (var i = 0; i < controls.length; i++) {
                    controls[i].disabled = true;
                }
            }, 0);
        });
    }

    function subscribeToEnhancedLoads() {
        if (!window.Blazor || typeof window.Blazor.addEventListener !== 'function') {
            return false;
        }

        window.Blazor.addEventListener('enhancedload', initializeConsentSubmit);
        return true;
    }

    initializeConsentSubmit();
    document.addEventListener('DOMContentLoaded', initializeConsentSubmit, { once: true });
    window.addEventListener('load', initializeConsentSubmit, { once: true });
    if (!subscribeToEnhancedLoads()) {
        window.addEventListener('load', function () {
            initializeConsentSubmit();
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
