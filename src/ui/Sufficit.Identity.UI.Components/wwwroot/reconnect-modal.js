// Reload button of ReconnectModal. A module file rather than an inline
// handler: the CSP allows scripts from 'self' only.
document.addEventListener("click", (event) => {
    if (event.target instanceof Element && event.target.closest("[data-reconnect-reload]")) {
        location.reload();
    }
});
