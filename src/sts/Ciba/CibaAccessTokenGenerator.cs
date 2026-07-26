using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Sufficit.Identity.STS.Ciba;

/// <summary>
/// Generates self-contained JWT access tokens for the CIBA poll handler
/// (RFC 9126), because OpenIddict 7.6 forbids <c>SignIn</c> from the
/// unregistered <c>/connect/ciba/token</c> endpoint.
/// </summary>
/// <remarks>
/// <b>Why hand-built.</b> OpenIddict's endpoint set and flow set are fixed
/// enums with no extension point for CIBA (verified: no
/// <c>SetCustomEndpoint</c>, no <c>AllowCustomFlow</c>, no
/// <c>AcceptUnknownGrantTypes</c>). The dedicated <c>/connect/ciba/token</c>
/// bypasses the grant-type validation that would reject CIBA on
/// <c>/connect/token</c>, but <c>SignIn</c> only works on registered
/// endpoints. So the token is emitted manually, mirroring the
/// <see cref="Logout.LogoutTokenGenerator"/> pattern.
///
/// <para><b>Signing key.</b> Reuses the STS signing key (production X.509
/// certificate via <c>ResolveLogoutSigningCredentials</c>, or an ephemeral
/// ECDSA P-256 key in dev/test) — the SAME key OpenIddict signs access tokens
/// with, so resource servers validate the CIBA token against the STS JWKS at
/// <c>.well-known/openid-configuration/jwks</c>.</para>
///
/// <para><b>Limitation (documented).</b> A hand-built JWT is NOT an OpenIddict
/// reference token: it is invisible to <c>/connect/introspect</c> and
/// <c>/connect/revocation</c>, and OpenIddict's token storage does not track
/// it. Clients that validate the JWT locally against JWKS are unaffected. For
/// a CIBA client that needs introspection/revocation, insert a row into the
/// OpenIddict tokens table via <c>IOpenIddictTokenManager.CreateAsync</c> —
/// deferred until a concrete requirement materializes (CIBA is a new grant,
/// no legacy clients depend on it yet). Portable: depends only on
/// <c>Microsoft.IdentityModel.JsonWebTokens</c>, survives a move off OpenIddict.</para>
/// </remarks>
public sealed class CibaAccessTokenGenerator
{
    private readonly JsonWebTokenHandler _tokenHandler = new();
    private readonly SigningCredentials _signingCredentials;
    private readonly string _issuer;
    private readonly TimeProvider _timeProvider;
    private readonly int _accessTokenLifetimeMinutes;

    public CibaAccessTokenGenerator(
        SigningCredentials signingCredentials,
        string issuer,
        int accessTokenLifetimeMinutes,
        TimeProvider? timeProvider = null)
    {
        _signingCredentials = signingCredentials ?? throw new ArgumentNullException(nameof(signingCredentials));
        _issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
        _accessTokenLifetimeMinutes = accessTokenLifetimeMinutes;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Builds a signed JWT access token for the approved CIBA subject.
    /// </summary>
    /// <param name="subject">The user's <c>sub</c>.</param>
    /// <param name="audience">The resource/audience the token is for (the CIBA
    /// client that initiated the request).</param>
    /// <param name="scopes">The granted scopes (space-joined into the
    /// <c>scope</c> claim).</param>
    /// <param name="clientId">The client_id that initiated the CIBA request
    /// (the <c>azp</c> / authorized party claim).</param>
    /// <param name="extraClaims">Optional additional claims (name, email, role,
    /// cnf for DPoP, etc.) to embed.</param>
    public string Generate(
        string subject,
        string audience,
        IReadOnlyCollection<string> scopes,
        string clientId,
        IEnumerable<Claim>? extraClaims = null)
    {
        var now = _timeProvider.GetUtcNow();
        var expires = now.AddMinutes(_accessTokenLifetimeMinutes);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Iss, _issuer),
            new(JwtRegisteredClaimNames.Sub, subject),
            new(JwtRegisteredClaimNames.Aud, audience),
            new(JwtRegisteredClaimNames.Iat,
                EpochTime.GetIntDate(now.DateTime).ToString(),
                ClaimValueTypes.Integer64),
            new(JwtRegisteredClaimNames.Exp,
                EpochTime.GetIntDate(expires.DateTime).ToString(),
                ClaimValueTypes.Integer64),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new("client_id", clientId),
            new("scope", string.Join(' ', scopes)),
            new("token_type", "Bearer"),
        };

        if (extraClaims is not null)
        {
            foreach (var claim in extraClaims)
            {
                claims.Add(claim);
            }
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = _issuer,
            Audience = audience,
            IssuedAt = now.DateTime,
            Expires = expires.DateTime,
            SigningCredentials = _signingCredentials,
            TokenType = "at+jwt", // RFC 9068 §2.1 access-token type header
            Claims = claims.ToDictionary(c => c.Type, c => (object)c.Value),
        };

        return _tokenHandler.CreateToken(descriptor);
    }
}
