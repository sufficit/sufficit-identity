// The dialog host closes on Escape (a document capture listener), on a click
// on its backdrop and on its header button, without asking. For a token shown
// once that loses the value for good, so those gestures are taken here first
// — window capture runs before both the host's listener and Blazor's event
// delegation — and handed to the component, which asks before closing.
export function guard(root, component) {
    const dialog = root.closest('.sui-dialog');
    const overlay = root.closest('.sui-dialog-overlay');

    function intercept(event) {
        event.preventDefault();
        event.stopImmediatePropagation();
        void component.invokeMethodAsync('RequestClose');
    }

    function onKeyDown(event) {
        if (event.key === 'Escape' && root.isConnected) intercept(event);
    }

    function onClick(event) {
        if (!root.isConnected) return;
        const close = dialog?.querySelector('.sui-dialog__close');
        if (event.target === overlay || (close && close.contains(event.target))) intercept(event);
    }

    window.addEventListener('keydown', onKeyDown, true);
    window.addEventListener('click', onClick, true);
    return {
        dispose() {
            window.removeEventListener('keydown', onKeyDown, true);
            window.removeEventListener('click', onClick, true);
        },
    };
}
