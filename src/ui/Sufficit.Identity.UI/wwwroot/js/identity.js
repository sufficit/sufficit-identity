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
