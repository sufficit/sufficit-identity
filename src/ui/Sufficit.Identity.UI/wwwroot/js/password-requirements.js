// Progressive guidance for both static POST forms and interactive registration.
// Read only the associated input. Never persist or transmit the password here;
// the server remains responsible for validation, including breach checks.
(function () {
    function updateGuidance() {
        document.querySelectorAll('[data-password-requirements]').forEach(function (guidance) {
            var input = document.getElementById(guidance.dataset.passwordRequirements);
            if (!input) return;
            var value = input.value;
            var minimum = Number(guidance.dataset.passwordMinimum);
            var maximum = Number(guidance.dataset.passwordMaximum) || Infinity;
            // Match ASP.NET Identity: ASCII categories and UTF-16 length/distinct
            // characters, including non-ASCII input in the symbol category.
            var satisfied = {
                length: value.length >= minimum && value.length <= maximum,
                uppercase: /[A-Z]/.test(value),
                lowercase: /[a-z]/.test(value),
                digit: /[0-9]/.test(value),
                symbol: /[^A-Za-z0-9]/.test(value),
                unique: new Set(value.split('')).size >= Number(guidance.dataset.passwordUnique)
            };
            var pending = 0;
            guidance.querySelectorAll('[data-password-rule]').forEach(function (rule) {
                var hidden = satisfied[rule.dataset.passwordRule] === true;
                if (rule.hidden !== hidden) rule.hidden = hidden;
                if (!hidden) pending++;
            });
            // Do not claim that the password was accepted before submission.
            var complete = pending === 0;
            if (guidance.hidden !== complete) guidance.hidden = complete;
            // A directly referenced hidden element still contributes its full
            // text to the accessible description. Detach only this guidance
            // when complete, preserving other field help/error descriptions.
            var descriptions = (input.getAttribute('aria-describedby') || '').split(/\s+/).filter(Boolean);
            var attached = descriptions.includes(guidance.id);
            if (complete && attached) {
                descriptions = descriptions.filter(function (id) { return id !== guidance.id; });
                if (descriptions.length) input.setAttribute('aria-describedby', descriptions.join(' '));
                else input.removeAttribute('aria-describedby');
            } else if (!complete && !attached) {
                descriptions.push(guidance.id);
                input.setAttribute('aria-describedby', descriptions.join(' '));
            }
        });
    }

    // Delegation survives enhanced navigation and interactive hydration. Input
    // covers typing, paste and autofill; change/focus cover password managers.
    ['input', 'change', 'focusin'].forEach(function (eventName) {
        document.addEventListener(eventName, function (event) {
            if (event.target instanceof HTMLInputElement) updateGuidance();
        });
    });
    document.addEventListener('reset', function () { setTimeout(updateGuidance, 0); });
    window.addEventListener('pageshow', updateGuidance);
    window.addEventListener('load', updateGuidance, { once: true });

    function initialize() {
        updateGuidance();
        // React to inserted/replaced form controls and server-cleared values.
        // We only write `hidden`, which is deliberately not observed.
        new MutationObserver(updateGuidance).observe(document.body, {
            childList: true, subtree: true, attributes: true, attributeFilter: ['value']
        });
    }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize, { once: true });
    } else {
        initialize();
    }
})();
