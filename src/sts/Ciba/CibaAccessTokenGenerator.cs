using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using static OpenIddict.Abstractions.OpenIddictConstants;

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
/// <para><b>Token tracking.</b> The controller creates the matching OpenIddict
/// token entry and persists this JWT as its payload. That keeps introspection
/// and revocation available while resource servers can still validate the JWT
/// locally against JWKS. Portable: generation itself depends only on
/// <c>Microsoft.IdentityModel.JsonWebTokens</c>.</para>
/// </remarks>
public sealed class CibaAccessTokenGenerator
{
    private readonly JsonWebTokenHandler _tokenHandler = new();
    private readonly SigningCredentials _signingCredentials;
    private readonly string _issuer;
    private readonly TimeProvider _timeProvider;
    private readonly int _accessTokenLifetimeMinutes;

    public TimeSpan AccessTokenLifetime =>
        TimeSpan.FromMinutes(_accessTokenLifetimeMinutes);

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
    /// <param name="audiences">The resource/audience values derived from the
    /// granted scopes.</param>
    /// <param name="scopes">The granted scopes (space-joined into the
    /// <c>scope</c> claim).</param>
    /// <param name="clientId">The client_id that initiated the CIBA request
    /// (the <c>azp</c> / authorized party claim).</param>
    /// <param name="extraClaims">Optional additional claims (name, email, role,
    /// cnf for DPoP, etc.) to embed.</param>
    public string Generate(
        string subject,
        IReadOnlyCollection<string> audiences,
        IReadOnlyCollection<string> scopes,
        string clientId,
        string tokenId,
        IEnumerable<Claim>? extraClaims = null)
    {
        var now = _timeProvider.GetUtcNow();
        var expires = now.AddMinutes(_accessTokenLifetimeMinutes);

        if (audiences.Count == 0)
        {
            throw new ArgumentException(
                "At least one token audience is required.", nameof(audiences));
        }

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Iss, _issuer),
            new(JwtRegisteredClaimNames.Sub, subject),
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
            new(Claims.Private.TokenId, tokenId),
        };

        foreach (var audience in audiences)
        {
            claims.Add(new Claim(JwtRegisteredClaimNames.Aud, audience));
        }

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
            IssuedAt = now.DateTime,
            Expires = expires.DateTime,
            SigningCredentials = _signingCredentials,
            TokenType = "at+jwt", // RFC 9068 §2.1 access-token type header
            // SecurityTokenDescriptor.Claims is a dictionary, but JWT claims
            // are a multimap. Collapsing repeated claims (notably role) loses
            // authorization data for users with more than one role. Preserve
            // repeated values as JSON arrays so every granted role survives.
            Claims = claims
                .GroupBy(c => c.Type, StringComparer.Ordinal)
                .ToDictionary(
                    group => group.Key,
                    group => group.Count() == 1
                        ? (object)group.First().Value
                        : group.Select(c => c.Value).ToArray(),
                    StringComparer.Ordinal),
        };

        return _tokenHandler.CreateToken(descriptor);
    }
}
