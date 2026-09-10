// The external launcher stays on its first document while it owns the same-origin popup.
(function () {
    var root = document.querySelector('[data-device-launcher]');
    if (!root) return;
    var link = root.querySelector('[data-device-launch]');
    var popup = null;
    var completed = false;
    function show(name, visible) {
        root.querySelector('[data-device-' + name + ']').hidden = !visible;
    }
    link.addEventListener('click', function (event) {
        event.preventDefault();
        if (completed) return;
        if (popup && !popup.closed) { popup.focus(); return; }
        // A real click is required when the browser blocks unsolicited popups.
        popup = window.open(link.href, '_blank', 'popup,width=560,height=780,resizable=yes,scrollbars=yes');
        show('blocked', !popup);
        show('manual', !popup);
        show('waiting', Boolean(popup));
    });
    function onMessage(event) {
        if (event.origin !== window.location.origin || !popup || event.source !== popup) return;
        var data = event.data;
        if (!data || data.type !== 'sufficit-auth-complete' || data.flow !== 'device') return;
        if (data.result !== 'approved' && data.result !== 'denied') return;
        completed = true;
        window.removeEventListener('message', onMessage);
        show('waiting', false);
        show('complete', data.result === 'approved');
        show('denied', data.result === 'denied');
        link.hidden = true;
        // UI completion never supplies tokens or authenticates the application.
        // Device-token polling remains the authority at the client.
        popup.close();
        window.setTimeout(function () { window.close(); }, 200);
    }
    window.addEventListener('message', onMessage);
    // Preserve the popup when the launcher is manually closed: authorization can still finish.
    window.addEventListener('pagehide', function () { window.removeEventListener('message', onMessage); });
})();
