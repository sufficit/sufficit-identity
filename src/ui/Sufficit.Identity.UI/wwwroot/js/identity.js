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
 * Ends the browser side of an RFC 8628 device flow. A live `window.opener` at
 * initialization is the capability signal available to this page that it was
 * opened by script. Without that signal, show only the honest manual fallback.
 * Cross-Origin-Opener-Policy can sever the reference after a popup is opened,
 * so an eligible popup still runs every close strategy from the explicit
 * button gesture before keeping the control available as a fallback.
 */
(function () {
    var closeReportEndpoint = '/security/device-flow-close-report';
    var activeCloseStrategy = null;

    function reportDeviceFlow(event, details) {
        details = details || {};
        var historyLength = Number(window.history && window.history.length) || 0;
        var payload = JSON.stringify({
            event: event,
            strategy: details.strategy || null,
            reason: details.reason || null,
            hasOpener: canAttemptScriptClose(),
            historyLength: Math.min(100, Math.max(0, historyLength)),
            userActivation: Boolean(
                window.navigator
                && window.navigator.userActivation
                && window.navigator.userActivation.isActive),
            visibility: document.visibilityState || 'unknown',
            persisted: typeof details.persisted === 'boolean'
                ? details.persisted
                : null
        });

        try {
            if (window.navigator
                && typeof window.navigator.sendBeacon === 'function'
                && window.navigator.sendBeacon(
                    closeReportEndpoint,
                    new Blob([payload], { type: 'application/json' }))) {
                return;
            }
        } catch (_) {
            // The keepalive request below is the compatible fallback.
        }

        if (typeof window.fetch === 'function') {
            window.fetch(closeReportEndpoint, {
                method: 'POST',
                credentials: 'same-origin',
                cache: 'no-store',
                keepalive: true,
                headers: { 'content-type': 'application/json' },
                body: payload
            }).catch(function () {
                // Diagnostics must never interfere with the close action.
            });
        }
    }

    function logDeviceFlow(event, details) {
        if (typeof console !== 'undefined' && typeof console.info === 'function') {
            // Keep browser diagnostics useful without leaking device codes,
            // tokens, user identifiers, redirect URIs, or authorization payloads.
            console.info('[Sufficit Identity][DeviceFlow]', event, details || {});
        }

        reportDeviceFlow(event, details);
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

    function showManualCompletion(result, reason, keepCloseButton) {
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
            // A tab without a script-close capability must not advertise a
            // control that the browser will reject. An eligible popup keeps
            // the control available as a fallback if every close strategy is
            // blocked by the browser.
            button.hidden = keepCloseButton !== true;
            button.disabled = keepCloseButton !== true;
            if (keepCloseButton === true) {
                button.removeAttribute('aria-disabled');
            } else {
                button.setAttribute('aria-disabled', 'true');
            }
        }

        if (result) {
            result.removeAttribute('aria-busy');
            result.dataset.deviceCloseInProgress = 'false';
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

    function tryCloseWindow(result) {
        // Order matters. The direct close is now always the first operation
        // under the user's click; COOP can remove opener without removing the
        // browser's internal "script-opened" flag. The top-context and
        // retargeted forms remain browser-specific fallbacks.
        var strategies = [
            {
                name: 'direct',
                execute: function () { window.close(); }
            },
            {
                name: 'top',
                execute: function () { window.top.close(); }
            },
            {
                name: 'retargeted',
                execute: function () {
                    var currentWindow = window.open('', '_self');
                    if (currentWindow) currentWindow.close();
                }
            }
        ];
        var strategyIndex = 0;

        function attemptNextStrategy() {
            if (strategyIndex >= strategies.length) {
                logDeviceFlow('script-close-blocked', {
                    strategy: 'all',
                    reason: 'close-blocked'
                });
                showManualCompletion(result, 'close-blocked', true);
                return;
            }

            var strategy = strategies[strategyIndex++];
            activeCloseStrategy = strategy.name;
            logDeviceFlow('script-close-attempted', {
                strategy: strategy.name
            });

            try {
                strategy.execute();
            } catch (_) {
                logDeviceFlow('script-close-error', {
                    strategy: strategy.name,
                    reason: 'exception'
                });
                window.setTimeout(attemptNextStrategy, 0);
                return;
            }

            // Closing is asynchronous in Chromium/WebKit. If it succeeds this
            // callback never runs; when it does run, advance to the next
            // strategy instead of trusting a synchronous window.closed read.
            window.setTimeout(function () {
                if (window.closed === true) {
                    logDeviceFlow('script-close-succeeded', {
                        strategy: strategy.name
                    });
                    return;
                }

                logDeviceFlow('script-close-blocked', {
                    strategy: strategy.name,
                    reason: 'close-blocked'
                });
                attemptNextStrategy();
            }, 160);
        }

        attemptNextStrategy();
    }

    function closeDeviceFlowTab(result) {
        // The actual close request remains reachable only from the button.
        if (result && result.dataset.deviceCloseInProgress === 'true') return;
        logDeviceFlow('close-requested', { source: 'user-gesture' });
        if (result) {
            // Keep this marker for diagnostics, but only block concurrent
            // attempts. A blocked eligible popup may be tried again.
            result.dataset.deviceCloseAttempted = 'true';
            result.dataset.deviceCloseInProgress = 'true';
        }
        if (result) result.setAttribute('aria-busy', 'true');
        var button = document.querySelector('[data-device-flow-close]');
        if (button) button.disabled = true;

        tryCloseWindow(result);
    }

    function initializeDeviceFlowClose() {
        var result = document.querySelector('[data-device-flow-result]');
        if (!result || result.dataset.deviceCloseInitialized === 'true') return;

        result.dataset.deviceCloseInitialized = 'true';

        var closeButton = document.querySelector('[data-device-flow-close]');
        var scriptCloseAvailable = canAttemptScriptClose();
        if (!scriptCloseAvailable) {
            logDeviceFlow('manual-close-required', { reason: 'tab-not-script-opened' });
            showManualCompletion(result, 'tab-not-script-opened', false);
        } else {
            logDeviceFlow('close-control-initialized', { scriptClosable: true });
        }

        if (closeButton && closeButton.dataset.deviceCloseBound !== 'true') {
            closeButton.dataset.deviceCloseBound = 'true';
            closeButton.hidden = !scriptCloseAvailable;
            closeButton.disabled = !scriptCloseAvailable;
            if (scriptCloseAvailable) {
                closeButton.removeAttribute('aria-disabled');
            } else {
                closeButton.setAttribute('aria-disabled', 'true');
            }
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
    window.addEventListener('pagehide', function (event) {
        if (!activeCloseStrategy) return;
        logDeviceFlow('close-pagehide-observed', {
            strategy: activeCloseStrategy,
            persisted: Boolean(event.persisted)
        });
    });

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
        // F-8 (eval 2026-08-14): the provider display name reaches this
        // attribute from server configuration; building the box with
        // innerHTML re-interpreted it as HTML. The static skeleton is inert
        // markup and the name is injected as a text node, so no future
        // attribute value can become markup.
        var box = document.createElement('div');
        box.className = 'redirect-overlay-box';
        box.innerHTML =
            '<div class="spinner"></div>' +
            '<p class="redirect-overlay-hint">Você será redirecionado automaticamente.</p>';
        var caption = document.createElement('p');
        caption.textContent = 'Conectando a ' +
            (el.getAttribute('data-redirect-overlay') || '') + '…';
        box.insertBefore(caption, box.querySelector('.redirect-overlay-hint'));
        overlay.appendChild(box);
        document.body.appendChild(overlay);
    });
})();
