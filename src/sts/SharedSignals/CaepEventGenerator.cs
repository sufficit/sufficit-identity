using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Sufficit.Identity.STS.SharedSignals;

/// <summary>Generates explicitly typed, signed SSF/CAEP Security Event Tokens.</summary>
public sealed class CaepEventGenerator
{
    public const string SecurityEventTokenType = "secevent+jwt";
    public const string SessionRevokedEventType =
        "https://schemas.openid.net/secevent/caep/event-type/session-revoked";

    private readonly JsonWebTokenHandler _handler = new()
    {
        // SSF forbids exp. IdentityModel otherwise injects a default exp when
        // the descriptor intentionally leaves it unset.
        SetDefaultTimesOnTokenCreation = false,
    };
    private readonly SigningCredentials _signingCredentials;
    private readonly string _issuer;
    private readonly TimeProvider _timeProvider;

    public CaepEventGenerator(
        SigningCredentials signingCredentials,
        string issuer,
        TimeProvider? timeProvider = null)
    {
        _signingCredentials = signingCredentials ??
            throw new ArgumentNullException(nameof(signingCredentials));
        _issuer = string.IsNullOrWhiteSpace(issuer)
            ? throw new ArgumentException("Issuer is required.", nameof(issuer))
            : new Uri(issuer, UriKind.Absolute).AbsoluteUri;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public string GenerateSessionRevoked(
        string subject,
        string? sessionId,
        string audience,
        string? transactionId = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);
        ArgumentException.ThrowIfNullOrWhiteSpace(audience);

        var now = _timeProvider.GetUtcNow();
        var subjectIdentifier = string.IsNullOrWhiteSpace(sessionId)
            ? (object)new Dictionary<string, object>
            {
                ["format"] = "iss_sub",
                ["iss"] = _issuer,
                ["sub"] = subject,
            }
            : new Dictionary<string, object>
            {
                ["format"] = "complex",
                ["user"] = new Dictionary<string, object>
                {
                    ["format"] = "iss_sub",
                    ["iss"] = _issuer,
                    ["sub"] = subject,
                },
                ["session"] = new Dictionary<string, object>
                {
                    ["format"] = "opaque",
                    ["id"] = sessionId,
                },
            };

        var claims = new Dictionary<string, object>
        {
            [JwtRegisteredClaimNames.Jti] = Guid.NewGuid().ToString("N"),
            ["txn"] = string.IsNullOrWhiteSpace(transactionId)
                ? Guid.NewGuid().ToString("N")
                : transactionId,
            ["sub_id"] = subjectIdentifier,
            ["events"] = new Dictionary<string, object>
            {
                [SessionRevokedEventType] = new Dictionary<string, object>
                {
                    ["event_timestamp"] = now.ToUnixTimeSeconds(),
                },
            },
        };

        // SSF explicitly prohibits both `sub` and `exp` on its SET profile.
        return _handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = _issuer,
            Audience = audience,
            IssuedAt = now.UtcDateTime,
            SigningCredentials = _signingCredentials,
            TokenType = SecurityEventTokenType,
            Claims = claims,
        });
    }
}
