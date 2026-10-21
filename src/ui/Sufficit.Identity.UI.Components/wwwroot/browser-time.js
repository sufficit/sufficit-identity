// The browser's own time zone, so instants render in the reader's clock
// rather than the server's. IANA name plus the current offset as a fallback
// for hosts without that zone in their database.
export function timeZone() {
    let name = null;
    try {
        name = Intl.DateTimeFormat().resolvedOptions().timeZone || null;
    } catch {
        name = null;
    }
    return { name, offsetMinutes: -new Date().getTimezoneOffset() };
}
