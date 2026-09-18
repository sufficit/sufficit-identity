// Immediate feedback for buttons whose work starts on the server.
//
// A Blazor Server button does nothing visible until the click has travelled to
// the circuit, the handler has run and the diff has come back. On a phone, on a
// slow link — or when the handler's first await opens a platform dialog, as the
// passkey ceremony does — that gap reads as a click that did not register, and
// people click again.
//
// This listens in the capture phase, so the class is on the element before
// Blazor is even told about the click. The component sets the same class when
// its own state catches up, so the two agree and the marking survives the
// re-render that follows.
(function () {
    'use strict';

    var BUSY_CLASS = 'is-busy';
    var ATTRIBUTE = 'data-instant-busy';

    document.addEventListener('click', function (event) {
        var target = event.target;
        if (!target || typeof target.closest !== 'function') {
            return;
        }

        var element = target.closest('[' + ATTRIBUTE + ']');
        if (!element || element.disabled || element.classList.contains(BUSY_CLASS)) {
            return;
        }

        element.classList.add(BUSY_CLASS);
        element.setAttribute('aria-busy', 'true');
    }, true);

    // A ceremony can end without navigating — the user dismisses the platform
    // dialog, or the server answers with an error. The component clears its own
    // state, but a page restored from the back/forward cache never re-renders,
    // so the mark is cleared here as well.
    window.addEventListener('pageshow', function (event) {
        if (!event.persisted) {
            return;
        }

        document.querySelectorAll('.' + BUSY_CLASS).forEach(function (element) {
            element.classList.remove(BUSY_CLASS);
            element.removeAttribute('aria-busy');
        });
    });
})();
