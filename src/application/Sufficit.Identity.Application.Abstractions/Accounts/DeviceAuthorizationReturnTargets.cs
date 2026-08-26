namespace Sufficit.Identity.Application.Accounts;

/// <summary>
/// Native callbacks that may be exposed by the public device-authorization UI.
/// The callback carries no code or token; it only brings the polling client back
/// to the foreground after the server-side grant is complete.
/// </summary>
public static class DeviceAuthorizationReturnTargets
{
    public const string Genius = "sufficit-genius://auth-complete";
    public const string GeniusFull = "sufficit-aigenius://auth-complete";

    public static string? Normalize(string? candidate)
    {
        if (string.Equals(candidate, Genius, StringComparison.Ordinal))
            return Genius;
        if (string.Equals(candidate, GeniusFull, StringComparison.Ordinal))
            return GeniusFull;
        return null;
    }
}
