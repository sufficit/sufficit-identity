using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;

namespace Sufficit.Identity.STS.Jarm;

/// <summary>
/// Creates signed JWT authorization responses for JARM. The JWT carries every
/// response parameter produced by OpenIddict, while issuer, audience and
/// expiry are protected as registered JWT claims.
/// </summary>
public sealed class JarmResponseGenerator
{
    public const string ResponseTokenType = "oauth-authz-resp+jwt";

    private readonly JsonWebTokenHandler _handler = new();
    private readonly SigningCredentials _signingCredentials;
    private readonly string _issuer;
    private readonly TimeSpan _lifetime;
    private readonly TimeProvider _timeProvider;

    public JarmResponseGenerator(
        SigningCredentials signingCredentials,
        string issuer,
        TimeSpan lifetime,
        TimeProvider? timeProvider = null)
    {
        _signingCredentials = signingCredentials ??
            throw new ArgumentNullException(nameof(signingCredentials));
        _issuer = string.IsNullOrWhiteSpace(issuer)
            ? throw new ArgumentException("Issuer is required.", nameof(issuer))
            : new Uri(issuer, UriKind.Absolute).AbsoluteUri;
        _lifetime = lifetime > TimeSpan.Zero && lifetime <= TimeSpan.FromMinutes(10)
            ? lifetime
            : throw new ArgumentOutOfRangeException(
                nameof(lifetime), "JARM lifetime must be between 1 second and 10 minutes.");
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public string Generate(OpenIddictResponse response, string audience)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentException.ThrowIfNullOrWhiteSpace(audience);

        var claims = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach (var (name, parameter) in response.GetParameters())
        {
            // These are emitted by SecurityTokenDescriptor and must never be
            // accepted from the mutable protocol response.
            if (name is "iss" or "aud" or "exp" or "iat" or "nbf")
            {
                continue;
            }

            if (parameter.GetRawValue() is { } value)
            {
                claims[name] = value;
            }
        }

        var now = _timeProvider.GetUtcNow();
        return _handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = _issuer,
            Audience = audience,
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = now.Add(_lifetime).UtcDateTime,
            SigningCredentials = _signingCredentials,
            TokenType = ResponseTokenType,
            Claims = claims,
        });
    }
}
