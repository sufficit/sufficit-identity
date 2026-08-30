using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

/// <summary>
/// OIDC Back-Channel Logout 1.0 — distribution of a signed <c>logout_token</c>
/// to every RP with an active session when a user signs out (item 3.2 [L1]).
/// OpenIddict 7.6 only CONSUMES logout_tokens; it does NOT generate them, so
/// the STS hand-builds the JWT (<c>Logout.LogoutTokenGenerator</c>) and fans it
/// out (<c>Logout.BackchannelLogoutDistributor</c>). The discovery handler
/// advertises <c>backchannel_logout_supported=true</c> only when this is
/// enabled, so clients know the STS will notify them on logout.
/// </summary>
/// <remarks>
/// The capability is enabled by default. It remains a no-op for clients that
/// do not register a <c>backchannel_logout_uri</c>.
/// </remarks>
public sealed class BackchannelLogoutOptions
{
    /// <summary>
    /// Master switch. When <c>true</c>, the STS distributes a
    /// <c>logout_token</c> to every RP with an active authorization on user
    /// sign-out, and advertises <c>backchannel_logout_supported=true</c> in
    /// discovery. Default <c>true</c>.
    /// </summary>
    public bool Enabled { get; init; } = true;
}
/// <summary>
/// OIDC Front-Channel Logout 1.0 — renders each RP's registered
/// <c>frontchannel_logout_uri</c> in an iframe after local sign-out.
/// </summary>
/// <remarks>
/// The capability is enabled by default. The OP issues a cryptographically
/// random <c>sid</c> in its session cookie and ID Tokens, allowing RPs to
/// request session-specific logout.
/// </remarks>
public sealed class FrontchannelLogoutOptions
{
    /// <summary>
    /// Master switch. When <c>true</c>, the OP prepares a one-time iframe page
    /// for registered RP logout URIs and advertises front-channel support.
    /// Default <c>true</c>.
    /// </summary>
    public bool Enabled { get; init; } = true;
}
