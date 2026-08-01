namespace Sufficit.Identity.UI;

/// <summary>
/// Controls how the Register and Login pages handle the username field.
///
/// Default values match Sufficit's policy: emails only (no separate username).
/// Read from the "Sufficit:Identity:Register" configuration section.
/// </summary>
public sealed class RegisterConfiguration
{
    /// <summary>
    /// Whether the /account/register page is accessible at all.
    /// Default: <c>true</c>.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// If <c>true</c>, the Register form displays a separate UserName field
    /// (legacy behavior). If <c>false</c> (default), the email is used as
    /// the username and no username field is shown.
    /// </summary>
    public bool RequireUsername { get; set; } = false;
}
