namespace Sufficit.Identity.Application.Diagnostics;

/// <summary>
/// Neutralizes caller-supplied text before it reaches a log entry.
/// </summary>
/// <remarks>
/// Structured sinks escape values on their own, but plain-text sinks (console,
/// rolling files) write them verbatim: a route id, client id or header holding
/// a line break could forge an extra, trusted-looking log line. Every log
/// argument that comes from a request must pass through <see cref="Sanitize"/>.
/// </remarks>
public static class LogValue
{
    public static string? Sanitize(string? value) => value?
        .Replace("\r", string.Empty, StringComparison.Ordinal)
        .Replace("\n", string.Empty, StringComparison.Ordinal)
        .Replace("\u0085", string.Empty, StringComparison.Ordinal)
        .Replace("\u2028", string.Empty, StringComparison.Ordinal)
        .Replace("\u2029", string.Empty, StringComparison.Ordinal);
}
