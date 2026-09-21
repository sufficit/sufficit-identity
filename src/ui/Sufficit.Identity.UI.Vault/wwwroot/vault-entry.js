// Clipboard values stay in the authenticated form; never log, persist or auto-submit them.
export async function readClipboard() {
    if (!globalThis.isSecureContext || !navigator.clipboard?.readText) return null;
    try {
        const value = await navigator.clipboard.readText();
        return value.length > 0 && value.length <= 16384 ? value : null;
    } catch {
        return null; // Native paste remains available when permission/activation is missing.
    }
}
