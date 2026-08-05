using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Sufficit.Identity.STS.Logout;

/// <summary>
/// Generates OIDC Back-Channel Logout 1.0 <c>logout_token</c> JWTs (RFC:
/// https://openid.net/specs/openid-connect-backchannel-1_0.html).
/// </summary>
/// <remarks>
/// OpenIddict 7.6 only CONSUMES logout_tokens (its <c>RedeemLogoutTokenEntry</c>
/// handler invalidates a token entry when one is presented) — it does NOT
/// generate them. This class hand-builds the JWT per the spec, signed with the
/// same key family the STS uses for access tokens (resolved by the DI wiring:
/// production signing certificate in Development a generated ECDSA P-256 key).
/// Deliberately portable: depends only on
/// <c>Microsoft.IdentityModel.JsonWebTokens</c> (transitively available via
/// OpenIddict.AspNetCore), NOT on OpenIddict internals — so it survives a
/// future move off OpenIddict.
/// </remarks>
public sealed class LogoutTokenGenerator
{
    /// <summary>
    /// The <c>events</c> claim URI that identifies a back-channel logout token
    /// (OIDC Back-Channel Logout 1.0 §2.4). RP validators check for exactly
    /// this member.
    /// </summary>
    public const string BackchannelLogoutEventUri =
        "http://schemas.openid.net/event/backchannel-logout";

    /// <summary>
    /// The JWT <c>typ</c> header for a logout token (OIDC Back-Channel Logout
    /// 1.0 §2.4). RPs MUST reject tokens whose typ is not exactly this value.
    /// </summary>
    public const string LogoutTokenType = "logout+jwt";

    private readonly JsonWebTokenHandler _tokenHandler = new();
    private readonly SigningCredentials _signingCredentials;
    private readonly string _issuer;
    private readonly TimeProvider _timeProvider;

    /// <param name="signingCredentials">Credentials used to sign the logout
    /// token. In production, reuse the STS signing certificate; in tests, a
    /// throwaway ECDSA key is fine (the RP validating the token must trust the
    /// STS JWKS regardless).</param>
    /// <param name="issuer">The STS issuer URI (<c>iss</c> claim).</param>
    /// <param name="timeProvider">Clock for <c>iat</c>; defaults to
    /// <see cref="TimeProvider.System"/> when null.</param>
    public LogoutTokenGenerator(
        SigningCredentials signingCredentials,
        string issuer,
        TimeProvider? timeProvider = null)
    {
        _signingCredentials = signingCredentials ?? throw new ArgumentNullException(nameof(signingCredentials));
        _issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Builds a signed <c>logout_token</c> for a single RP.
    /// </summary>
    /// <param name="subject">The user's <c>sub</c> (subject identifier). May be
    /// null when only a session-level logout is intended (spec allows sub OR sid
    /// to be present, though sub is strongly recommended).</param>
    /// <param name="sessionId">The <c>sid</c> (session identifier), when the STS
    /// tracks one. May be null.</param>
    /// <param name="audience">The RP's <c>client_id</c>, used as the
    /// <c>aud</c> claim exactly as in an ID Token.</param>
    /// <remarks>
    /// Per OIDC Back-Channel Logout 1.0 §2.4, the token MUST contain:
    /// <c>iss</c>, <c>aud</c>, <c>iat</c>, <c>jti</c>, <c>events</c> (with the
    /// backchannel-logout member), and AT LEAST ONE of <c>sub</c>/<c>sid</c>.
    /// It MUST NOT contain a <c>nonce</c>. We always emit <c>jti</c> as a fresh
    /// GUID so RPs can dedupe replays of the same logout.
    /// </remarks>
    public string Generate(string? subject, string? sessionId, string audience)
    {
        if (string.IsNullOrWhiteSpace(audience))
            throw new ArgumentException("Audience (RP client_id) is required.", nameof(audience));
        if (string.IsNullOrWhiteSpace(subject) && string.IsNullOrWhiteSpace(sessionId))
            throw new ArgumentException(
                "At least one of subject (sub) or sessionId (sid) must be provided " +
                "(OIDC Back-Channel Logout 1.0 §2.4).");

        var now = _timeProvider.GetUtcNow();
        var claims = new Dictionary<string, object>
        {
            // jti: unique per token so the RP can reject replays.
            [JwtRegisteredClaimNames.Jti] = Guid.NewGuid().ToString("N"),
            // events: the single member that identifies this as a back-channel
            // logout token. RPs MUST verify this is present and non-empty.
            // Keep it as a nested dictionary so it is emitted as a JSON object,
            // never as a JSON-looking string.
            ["events"] = new Dictionary<string, object>
            {
                [BackchannelLogoutEventUri] = new Dictionary<string, object>(),
            },
        };

        if (!string.IsNullOrWhiteSpace(subject))
        {
            claims[JwtRegisteredClaimNames.Sub] = subject;
        }

        if (!string.IsNullOrWhiteSpace(sessionId))
        {
            claims["sid"] = sessionId;
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = _issuer,
            Audience = audience,
            IssuedAt = now.DateTime,
            // A short expiry bounds replay acceptance at RPs that retain jti
            // only for the token lifetime. The spec allows exp and requires RPs
            // to validate it when present.
            Expires = now.AddMinutes(2).DateTime,
            SigningCredentials = _signingCredentials,
            // typ header: RPs MUST reject logout tokens whose typ != "logout+jwt".
            TokenType = LogoutTokenType,
            Claims = claims,
        };

        return _tokenHandler.CreateToken(descriptor);
    }
}
