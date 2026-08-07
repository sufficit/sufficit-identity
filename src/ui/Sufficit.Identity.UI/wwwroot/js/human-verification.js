// Provider-neutral browser adapter. The response is copied into a hidden
// Blazor-bound field; the server still performs the authoritative validation.
(function () {
    'use strict';

    var widgets = new Map();
    var scriptPromises = new Map();

    function providerDefinition(provider, culture) {
        if (provider === 'GoogleRecaptchaV2') {
            return {
                key: 'google-recaptcha-v2',
                global: 'grecaptcha',
                url: 'https://www.google.com/recaptcha/api.js?render=explicit&hl=' +
                    encodeURIComponent(culture || 'pt-BR')
            };
        }

        if (provider === 'Turnstile') {
            return {
                key: 'cloudflare-turnstile',
                global: 'turnstile',
                url: 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'
            };
        }

        throw new Error('Unsupported human-verification provider: ' + provider);
    }

    function loadScript(definition) {
        function providerReady() {
            var api = window[definition.global];
            return api && typeof api.render === 'function';
        }

        if (providerReady()) return Promise.resolve();
        if (scriptPromises.has(definition.key)) return scriptPromises.get(definition.key);

        var promise = new Promise(function (resolve, reject) {
            var existing = document.querySelector('script[data-human-verification="' +
                definition.key + '"]');
            var script = existing || document.createElement('script');
            var completed = false;
            var readinessTimer;
            var readinessDeadline = Date.now() + 10000;

            function finish(error) {
                if (completed) return;
                completed = true;
                if (readinessTimer) clearTimeout(readinessTimer);
                if (error) reject(error);
                else resolve();
            }

            // Google creates window.grecaptcha before the localized runtime
            // installs grecaptcha.render. Resolving on the script load event
            // therefore races with recaptcha__*.js on fast/cached responses.
            function checkReady() {
                if (providerReady()) {
                    finish();
                } else if (Date.now() >= readinessDeadline) {
                    finish(new Error(
                        'Human-verification provider did not initialize.'));
                } else {
                    readinessTimer = setTimeout(checkReady, 50);
                }
            }

            script.addEventListener('error', function () {
                finish(new Error(
                    'Unable to load human-verification provider.'));
            }, { once: true });

            if (!existing) {
                script.src = definition.url;
                script.async = true;
                script.defer = true;
                script.dataset.humanVerification = definition.key;
                document.head.appendChild(script);
            }

            checkReady();
        });

        var trackedPromise = promise.catch(function (error) {
            scriptPromises.delete(definition.key);
            throw error;
        });
        scriptPromises.set(definition.key, trackedPromise);
        return trackedPromise;
    }

    function updateToken(inputId, token) {
        var input = document.getElementById(inputId);
        if (!input) return;
        input.value = token || '';
        input.dispatchEvent(new Event('change', { bubbles: true }));
    }

    async function render(widgetId, inputId, provider, siteKey, action, culture) {
        var container = document.getElementById(widgetId);
        if (!container || widgets.has(widgetId)) return;

        var definition = providerDefinition(provider, culture);
        try {
            await loadScript(definition);
            if (!document.getElementById(widgetId)) return;

            var callbacks = {
                sitekey: siteKey,
                // Google Cloud checkbox keys require an action even when they
                // are consumed through the legacy-compatible api.js/siteverify
                // flow. Classic v2 keys safely accept the same parameter, and
                // Turnstile also uses it to bind the challenge to the flow.
                action: action,
                callback: function (token) { updateToken(inputId, token); },
                'expired-callback': function () { updateToken(inputId, ''); },
                'error-callback': function () { updateToken(inputId, ''); }
            };

            var widget;
            if (provider === 'Turnstile') {
                callbacks.theme = 'auto';
                callbacks.size = 'flexible';
                widget = window.turnstile.render('#' + widgetId, callbacks);
            } else {
                callbacks.theme = 'light';
                widget = window.grecaptcha.render(widgetId, callbacks);
            }

            widgets.set(widgetId, { provider: provider, id: widget });
        } catch (error) {
            container.dataset.loadFailed = 'true';
            container.textContent = 'Não foi possível carregar a verificação de segurança.';
            console.warn('Human verification could not be initialized.', error);
        }
    }

    function reset(widgetId, inputId) {
        updateToken(inputId, '');
        var widget = widgets.get(widgetId);
        if (!widget) return;
        if (widget.provider === 'Turnstile') window.turnstile.reset(widget.id);
        else window.grecaptcha.reset(widget.id);
    }

    function remove(widgetId) {
        var widget = widgets.get(widgetId);
        if (!widget) return;
        if (widget.provider === 'Turnstile' && window.turnstile) {
            window.turnstile.remove(widget.id);
        }
        widgets.delete(widgetId);
    }

    window.sufficitHumanVerification = {
        render: render,
        reset: reset,
        remove: remove
    };
})();
