namespace Sufficit.Identity.Application.Security;

/// <summary>
/// Property keys stamped on an OpenIddict application created through Dynamic
/// Client Registration. They live in a shared assembly because the STS writes
/// them and the management surface reads them: a self-registered client is
/// otherwise indistinguishable from one an operator created by hand.
/// </summary>
public static class DynamicClientRegistrationProperties
{
    public const string Origin = "identity:client:origin";

    /// <summary>Value of <see cref="Origin"/> for self-registered clients.</summary>
    public const string OriginValue = "dcr";

    public const string RegisteredAt = "identity:client:registered-at";

    /// <summary>True when the registration carried no initial access token and
    /// was therefore restricted to the interactive sign-in profile.</summary>
    public const string Anonymous = "identity:client:dcr-anonymous";

    public const string RemoteAddress = "identity:client:dcr-remote-address";

    public const string UserAgent = "identity:client:dcr-user-agent";
}
