using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;

namespace Sufficit.Identity.STS.Ciba;

public sealed record CibaClientAuthentication(bool Succeeded, string? ClientId);

/// <summary>
/// Authenticates a client at the CIBA initiation endpoint with a signed JWT
/// assertion (RFC 7523, <c>private_key_jwt</c>). The initiation endpoint is not
/// an OpenIddict endpoint, so it cannot use the token endpoint's client
/// authentication; this keeps the rules and the signing keys the same as the
/// rest of the server (the client's registered <c>jwks</c> or
/// <c>jwks_uri</c>).
/// </summary>
public interface ICibaClientAuthenticator
{
    Task<CibaClientAuthentication> AuthenticateAssertionAsync(
        string? requestedClientId,
        string? assertionType,
        string? assertion,
        string endpointUrl,
        CancellationToken cancellationToken);
}

internal sealed class CibaClientAuthenticator(
    IOpenIddictApplicationManager applications,
    Jar.IJarSigningKeyResolver signingKeys,
    Dpop.IDpopReplayCache replayCache,
    SufficitIdentityOptions options,
    ILogger<CibaClientAuthenticator> logger) : ICibaClientAuthenticator
{
    public const string JwtBearerAssertionType =
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    /// <summary>Upper bound between issuance and expiry of an assertion.</summary>
    internal const int MaxAssertionLifetimeSeconds = 300;

    private static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(30);

    public async Task<CibaClientAuthentication> AuthenticateAssertionAsync(
        string? requestedClientId,
        string? assertionType,
        string? assertion,
        string endpointUrl,
        CancellationToken cancellationToken)
    {
        if (!string.Equals(assertionType, JwtBearerAssertionType, StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(assertion))
        {
            return Failed(null, "unsupported_assertion_type");
        }

        JsonWebToken jwt;
        try
        {
            jwt = new JsonWebToken(assertion);
        }
        catch (ArgumentException)
        {
            return Failed(null, "malformed_assertion");
        }

        // RFC 7523 §3: iss and sub both name the client.
        var clientId = jwt.Issuer;
        if (string.IsNullOrWhiteSpace(clientId)
            || !string.Equals(jwt.Subject, clientId, StringComparison.Ordinal)
            || (!string.IsNullOrEmpty(requestedClientId)
                && !string.Equals(requestedClientId, clientId, StringComparison.Ordinal)))
        {
            return Failed(clientId, "client_mismatch");
        }

        var application = await applications.FindByClientIdAsync(clientId, cancellationToken);
        if (application is null)
        {
            return Failed(clientId, "client_unknown");
        }

        IReadOnlyList<SecurityKey> keys;
        try
        {
            keys = await signingKeys.ResolveAsync(application, jwt.Kid, cancellationToken);
        }
        catch (Exception exception) when (exception is HttpRequestException
            or InvalidOperationException or System.Text.Json.JsonException or TaskCanceledException)
        {
            logger.LogWarning(exception,
                "CIBA client assertion: signing keys could not be resolved for client {ClientId}.",
                clientId);
            return Failed(clientId, "signing_keys_unavailable");
        }

        // Only asymmetric keys: a shared-secret JWT would be client_secret_jwt,
        // which this endpoint does not offer.
        keys = keys.Where(key => key is not SymmetricSecurityKey
                && !(key is JsonWebKey json && json.Kty == JsonWebAlgorithmsKeyTypes.Octet))
            .ToArray();
        if (keys.Count == 0)
        {
            return Failed(clientId, "signing_key_not_found");
        }

        var validation = await new JsonWebTokenHandler().ValidateTokenAsync(assertion,
            new TokenValidationParameters
            {
                ValidIssuer = clientId,
                ValidAudiences = Audiences(endpointUrl),
                IssuerSigningKeys = keys,
                RequireSignedTokens = true,
                RequireExpirationTime = true,
                ValidateLifetime = true,
                ClockSkew = ClockSkew,
            });
        if (!validation.IsValid)
        {
            return Failed(clientId, "invalid_assertion");
        }

        var now = DateTime.UtcNow;
        var issuedAt = jwt.IssuedAt == DateTime.MinValue ? now : jwt.IssuedAt;
        if (string.IsNullOrWhiteSpace(jwt.Id)
            || (jwt.ValidTo - issuedAt).TotalSeconds > MaxAssertionLifetimeSeconds)
        {
            return Failed(clientId, "assertion_lifetime_or_jti");
        }

        // Marked only after the signature validated, so unauthenticated
        // requests cannot reserve a client's jti values.
        if (replayCache.IsReplay(
                $"ciba-client-assertion:{clientId}:{jwt.Id}",
                jwt.ValidTo - now + ClockSkew))
        {
            return Failed(clientId, "assertion_replayed");
        }

        return new CibaClientAuthentication(true, clientId);
    }

    /// <summary>
    /// The issuer identifier (CIBA Core 1.0 §7.1) and the endpoint URL
    /// (RFC 7523 §3) are both accepted as the audience.
    /// </summary>
    private IEnumerable<string> Audiences(string endpointUrl)
    {
        var values = new List<string> { endpointUrl };
        if (!string.IsNullOrWhiteSpace(options.Issuer))
        {
            var issuer = options.Issuer.TrimEnd('/');
            values.Add(issuer);
            values.Add(issuer + "/");
            values.Add(issuer + "/bc-authorize");
        }

        return values.Distinct(StringComparer.Ordinal);
    }

    private CibaClientAuthentication Failed(string? clientId, string reason)
    {
        logger.LogInformation(
            "CIBA client assertion rejected for client {ClientId}: {Reason}.",
            clientId ?? "<unknown>",
            reason);
        return new CibaClientAuthentication(false, clientId);
    }
}
