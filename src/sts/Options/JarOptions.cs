using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

/// <summary>
/// JWT-Secured Authorization Request (JAR, RFC 9101) options. When enabled,
/// the STS accepts a signed <c>request</c> parameter (a JWT whose payload
/// carries the authorization request parameters) and validates it against the
/// client's registered signing keys before merging its claims.
/// </summary>
/// <remarks>
/// <b>Opt-in (default <see cref="Enabled"/>=<c>false</c>).</b> JAR is
/// independent of FAPI 2.0 but is a prerequisite of the FAPI 2.0 Security
/// Profile for clients that need signed authorization requests (as an
/// alternative or complement to PAR — a request object can be pushed via PAR).
/// </remarks>
public sealed class JarOptions
{
    /// <summary>
    /// Master switch. When <c>true</c>, the authorization and PAR endpoints
    /// accept a signed <c>request</c> parameter. Default <c>false</c>.
    /// </summary>
    public bool Enabled { get; init; } = false;

    /// <summary>
    /// Signing algorithms accepted in request objects. Defaults to the FAPI
    /// 2.0 baseline (<c>PS256</c>, <c>ES256</c>). A request object signed with
    /// any other algorithm is rejected.
    /// </summary>
    public HashSet<string> AllowedSigningAlgorithms { get; init; } = new(StringComparer.Ordinal)
    {
        "PS256",
        "ES256",
    };

    /// <summary>
    /// Maximum lifetime of a request object, in seconds. A request object
    /// without an <c>exp</c> claim is rejected; one older than this (counted
    /// from its <c>iat</c>, or <c>nbf</c> when present) is rejected. Default
    /// 120 (2 minutes). RFC 9101 recommends a short lifetime.
    /// </summary>
    public int MaxLifetimeSeconds { get; init; } = 120;

    /// <summary>Required RFC 9101 request-object media type.</summary>
    public string RequiredTokenType { get; init; } = "oauth-authz-req+jwt";

    /// <summary>Maximum remote JWKS response size. Responses are streamed and
    /// rejected once this bound is crossed.</summary>
    public int RemoteJwksMaxBytes { get; init; } = 65_536;

    /// <summary>Per-request timeout for a registered remote JWKS URI.</summary>
    public int RemoteJwksTimeoutSeconds { get; init; } = 3;

    /// <summary>Fresh-cache lifetime for remote key sets.</summary>
    public int RemoteJwksCacheSeconds { get; init; } = 300;

    /// <summary>Additional bounded interval during which an already-known kid
    /// may be used if the remote endpoint is temporarily unavailable.</summary>
    public int RemoteJwksStaleSeconds { get; init; } = 900;

    /// <summary>Maximum number of registered JWKS URIs retained in process.</summary>
    public int RemoteJwksMaxCacheEntries { get; init; } = 256;
}
