using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

/// <summary>
/// OAuth 2.1-aligned PKCE policy for authorization-code clients.
/// </summary>
public sealed class PkceOptions
{
    /// <summary>
    /// Require PKCE for every authorization-code request. Disable only during
    /// a controlled migration of confidential legacy clients.
    /// </summary>
    public bool RequireForAllClients { get; init; } = true;

    /// <summary>
    /// Permit the legacy <c>plain</c> challenge method. Disabled by default;
    /// clients must use <c>S256</c>.
    /// </summary>
    public bool AllowPlainCodeChallengeMethod { get; init; } = false;
}
/// <summary>
/// Pushed Authorization Request (PAR, RFC 9126) policy. The PAR endpoint
/// (<c>connect/par</c>) is always registered; these options control whether
/// PAR is *required* of all clients (defense in depth — protects
/// authorization requests from URL/tamper exposure) and the lifetime of the
/// resulting <c>request_uri</c> outside the FAPI 2.0 boundary.
/// </summary>
/// <remarks>
/// Per-client PAR requirement is enforced by OpenIddict's own
/// <c>Requirements.Features.PushedAuthorizationRequests</c> flag on the
/// application. Setting <see cref="RequireForAllClients"/> to true is the
/// global equivalent and supersedes the per-client flag for every client.
/// </remarks>
public sealed class ParOptions
{
    /// <summary>
    /// Require PAR for every authorization request. Default <c>false</c> to
    /// preserve backward compatibility with existing non-PAR clients; flip to
    /// <c>true</c> only once every client has been migrated to push its
    /// authorization request. When true, the <c>request_uri</c> parameter is
    /// the only way to start an authorization flow.
    /// </summary>
    public bool RequireForAllClients { get; init; } = false;

    /// <summary>
    /// Lifetime of a pushed <c>request_uri</c>, in seconds, for non-FAPI
    /// clients. Null (default) = OpenIddict's built-in default (60s). FAPI 2.0
    /// clients are governed separately by
    /// <see cref="Fapi2Options.PushedAuthorizationRequestLifetimeSeconds"/>
    /// (which must be &lt; 600s per the profile). Values here must be 1..599
    /// to match the RFC 9126 range.
    /// </summary>
    public int? RequestUriLifetimeSeconds { get; init; } = null;
}
