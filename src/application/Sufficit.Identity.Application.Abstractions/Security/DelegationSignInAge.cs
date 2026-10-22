namespace Sufficit.Identity.Application.Security;

/// <summary>
/// How old a user's sign-in may be for an application to delegate a
/// credential on the user's behalf (token exchange into a delegated
/// credential). The deployment sets a default; each delegating application
/// may set its own value in its client settings, within the same bounds.
/// </summary>
public static class DelegationSignInAge
{
    /// <summary>Client setting holding the application's own limit, in whole hours.</summary>
    public const string ClientSetting = "sufficit:delegation_max_auth_age_hours";

    public const int MinimumHours = 1;

    /// <summary>One week: a longer window would let a stolen session keep minting credentials.</summary>
    public const int MaximumHours = 24 * 7;

    /// <summary>The application's own limit, or null when it follows the deployment default.</summary>
    public static int? Read(IReadOnlyDictionary<string, string> settings) =>
        settings.TryGetValue(ClientSetting, out var value)
        && int.TryParse(value, System.Globalization.NumberStyles.None,
            System.Globalization.CultureInfo.InvariantCulture, out var hours)
        && hours is >= MinimumHours and <= MaximumHours
            ? hours
            : null;
}
