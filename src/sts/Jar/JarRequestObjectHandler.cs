using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;
using Sufficit.Identity.STS.Dpop;

namespace Sufficit.Identity.STS.Jar;

/// <summary>
/// Extracts and validates an RFC 9101 JWT-Secured Authorization Request
/// (<c>request</c> parameter) at the authorization and PAR endpoints. When the
/// request object is valid, its claims replace the matching query/form
/// parameters on the OpenIddict request so downstream validation operates
/// exclusively on the signed, tamper-proof parameter set.
/// </summary>
/// <remarks>
/// Implemented from scratch because OpenIddict 7.6 does not parse/validate
/// signed request objects (its <c>RequestToken</c> machinery is PAR-specific).
/// The handler runs early in <c>ExtractAuthorizationRequest</c> /
/// <c>ExtractPushedAuthorizationRequest</c>, before OpenIddict's own parameter
/// validation, so the merged parameters are indistinguishable from a plain
/// query-string request to the rest of the pipeline.
/// </remarks>
internal static class JarRequestObjectHandler
{
    /// <summary>
    /// Extracts and merges a signed <c>request</c> parameter at the
    /// authorization endpoint. Runs before validation.
    /// </summary>
    public sealed class ExtractAuthorizationRequestObject(
        IOpenIddictApplicationManager applications,
        IJarSigningKeyResolver signingKeys,
        SufficitIdentityOptions rootOptions,
        IDpopReplayCache replayCache)
        : IOpenIddictServerHandler<ExtractAuthorizationRequestContext>
    {
        public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
            OpenIddictServerHandlerDescriptor
                .CreateBuilder<ExtractAuthorizationRequestContext>()
                .UseScopedHandler<ExtractAuthorizationRequestObject>()
                .SetOrder(Authentication.ExtractAuthorizationRequest.Descriptor.Order + 100)
                .SetType(OpenIddictServerHandlerType.Custom)
                .Build();

        public async ValueTask HandleAsync(ExtractAuthorizationRequestContext context)
        {
            await JarExtractor.TryMergeAsync(
                context.Transaction.Request!,
                applications,
                signingKeys,
                rootOptions.Jar,
                rootOptions.Issuer,
                replayCache,
                context.Logger,
                (msg, desc) => context.Reject(Errors.InvalidRequest, msg, desc),
                CancellationToken.None);
        }
    }

    /// <summary>
    /// Extracts and merges a signed <c>request</c> parameter at the PAR
    /// endpoint (a request object can be pushed via PAR per RFC 9126 §2.1).
    /// </summary>
    public sealed class ExtractPushedAuthorizationRequestObject(
        IOpenIddictApplicationManager applications,
        IJarSigningKeyResolver signingKeys,
        SufficitIdentityOptions rootOptions,
        IDpopReplayCache replayCache)
        : IOpenIddictServerHandler<ExtractPushedAuthorizationRequestContext>
    {
        public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
            OpenIddictServerHandlerDescriptor
                .CreateBuilder<ExtractPushedAuthorizationRequestContext>()
                .UseScopedHandler<ExtractPushedAuthorizationRequestObject>()
                .SetOrder(Authentication.ExtractPushedAuthorizationRequest.Descriptor.Order + 100)
                .SetType(OpenIddictServerHandlerType.Custom)
                .Build();

        public async ValueTask HandleAsync(ExtractPushedAuthorizationRequestContext context)
        {
            await JarExtractor.TryMergeAsync(
                context.Transaction.Request!,
                applications,
                signingKeys,
                rootOptions.Jar,
                rootOptions.Issuer,
                replayCache,
                context.Logger,
                (msg, desc) => context.Reject(Errors.InvalidRequest, msg, desc),
                CancellationToken.None);
        }
    }
}

/// <summary>
/// Core JAR extraction logic, shared by both endpoint hooks.
/// </summary>
internal static class JarExtractor
{
    /// <summary>
    /// If the request carries a <c>request</c> parameter, validates the signed
    /// JWT and merges its payload claims into <paramref name="request"/>,
    /// removing the <c>request</c> parameter afterwards. Returns silently when
    /// no request object is present (JAR is optional). On validation failure,
    /// invokes <paramref name="reject"/> and leaves the request unchanged.
    /// </summary>
    public static async Task TryMergeAsync(
        OpenIddictRequest request,
        IOpenIddictApplicationManager applications,
        IJarSigningKeyResolver signingKeyResolver,
        JarOptions options,
        string? issuer,
        IDpopReplayCache replayCache,
        Microsoft.Extensions.Logging.ILogger logger,
        Action<string, string?> reject,
        CancellationToken cancellationToken)
    {
        var requestObject = (string?)request.GetParameter(OpenIddictConstants.Parameters.Request);
        if (string.IsNullOrWhiteSpace(requestObject))
        {
            return;
        }

        // 1. Parse the JWT without validating yet (need the alg/kid to resolve keys).
        JsonWebToken jwt;
        try
        {
            jwt = new JsonWebToken(requestObject);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex,
                "JAR: request parameter is not a parseable JWT.");
            reject("The request parameter is not a valid JWT.", null);
            return;
        }

        if (!string.Equals(
            jwt.Typ,
            options.RequiredTokenType,
            StringComparison.Ordinal))
        {
            reject(
                $"The request object typ must be '{options.RequiredTokenType}'.",
                null);
            return;
        }

        if (!jwt.TryGetPayloadValue("iat", out long issuedAtUnix)
            || issuedAtUnix <= 0
            || !jwt.TryGetPayloadValue("exp", out long expiresAtUnix)
            || expiresAtUnix <= issuedAtUnix
            || !jwt.TryGetPayloadValue("jti", out string? requestId)
            || string.IsNullOrWhiteSpace(requestId))
        {
            reject(
                "The request object must contain valid iat, exp and jti claims.",
                null);
            return;
        }

        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(issuedAtUnix);
        var expiresAt = DateTimeOffset.FromUnixTimeSeconds(expiresAtUnix);
        var nowOffset = DateTimeOffset.UtcNow;
        if (issuedAt > nowOffset.AddSeconds(30)
            || expiresAt - issuedAt > TimeSpan.FromSeconds(
                Math.Clamp(options.MaxLifetimeSeconds, 1, 600)))
        {
            reject("The request object lifetime is outside the allowed window.", null);
            return;
        }

        // 2. Algorithm allowlist (RFC 9101 §6 + FAPI 2.0 baseline).
        if (!options.AllowedSigningAlgorithms.Contains(jwt.Alg))
        {
            reject(
                $"The request object signing algorithm '{jwt.Alg}' is not allowed.",
                $"Allowed: {string.Join(", ", options.AllowedSigningAlgorithms.OrderBy(a => a))}");
            return;
        }

        // 3. client_id must be present in the request object and match the
        // outer request's client_id (or provide one when the outer request has none).
        if (!jwt.TryGetPayloadValue("client_id", out string? jarClientId) ||
            string.IsNullOrWhiteSpace(jarClientId))
        {
            reject("The request object must contain a client_id claim.", null);
            return;
        }

        if (!string.IsNullOrWhiteSpace(request.ClientId) &&
            !string.Equals(request.ClientId, jarClientId, StringComparison.Ordinal))
        {
            reject(
                "The client_id in the request object does not match the request.",
                null);
            return;
        }

        // 4. Resolve the client and its signing keys (jwks / jwks_uri).
        var application = await applications.FindByClientIdAsync(
            jarClientId!, cancellationToken);
        if (application is null)
        {
            reject("Unknown client.", null);
            return;
        }

        IReadOnlyList<SecurityKey> signingKeys;
        try
        {
            signingKeys = await signingKeyResolver.ResolveAsync(
                application,
                jwt.Kid,
                cancellationToken);
        }
        catch (Exception exception) when (
            exception is HttpRequestException
                or InvalidOperationException
                or JsonException
                or TaskCanceledException)
        {
            logger.LogWarning(
                exception,
                "JAR: registered signing-key metadata could not be resolved for client {ClientId}.",
                jarClientId);
            reject(
                "The client's registered request-object signing keys are unavailable or invalid.",
                null);
            return;
        }
        if (signingKeys.Count == 0)
        {
            reject(
                "No matching signing key found for the request object.",
                "Register jwks or jwks_uri on the client.");
            return;
        }

        // 5. Validate signature + standard claims (iss must equal client_id,
        // aud must equal the issuer, exp required and bounded).
        var now = DateTime.UtcNow;
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jarClientId,
            ValidateAudience = true,
            ValidAudience = issuer,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            IssuerSigningKeys = signingKeys,
            ClockSkew = TimeSpan.FromSeconds(30),
        };

        var handler = new JsonWebTokenHandler();
        var result = await handler.ValidateTokenAsync(requestObject, validationParameters);
        if (!result.IsValid)
        {
            logger.LogWarning(result.Exception,
                "JAR: request object validation failed for client {ClientId}.", jarClientId);
            reject("The request object failed validation.", result.Exception?.Message);
            return;
        }

        // 6. Enforce a short max lifetime (exp bound) beyond JWT lifetime validation.
        if ((now - issuedAt.UtcDateTime).TotalSeconds > options.MaxLifetimeSeconds)
        {
            reject("The request object has expired.", null);
            return;
        }

        // Mark replay only after issuer/key/signature/lifetime validation so
        // anonymous garbage cannot reserve another client's jti namespace.
        var replayLifetime = expiresAt - nowOffset;
        if (replayLifetime <= TimeSpan.Zero
            || replayCache.IsReplay(
                $"jar:{jarClientId}:{requestId}",
                replayLifetime + TimeSpan.FromSeconds(30)))
        {
            reject("The request object has already been used.", null);
            return;
        }

        // 7. Replace the complete outer parameter set. RFC 9101 requires all
        // authorization parameters used with a Request Object to be carried
        // by that object. Keeping an outer parameter merely because the JWT
        // omitted it would make an unsigned scope/resource/prompt extension
        // influence the request.
        using var payload = JsonDocument.Parse(
            Base64UrlEncoder.Decode(jwt.EncodedPayload));
        if (!TryReplaceWithSignedParameters(
                request,
                payload.RootElement,
                jarClientId!,
                out var replacementError))
        {
            reject(replacementError!, null);
            return;
        }
    }

    internal static bool TryReplaceWithSignedParameters(
        OpenIddictRequest request,
        JsonElement payload,
        string clientId,
        out string? error)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);

        if (payload.ValueKind is not JsonValueKind.Object)
        {
            error = "The request object payload must be a JSON object.";
            return false;
        }

        var names = new HashSet<string>(StringComparer.Ordinal);
        var signedParameters = new List<(string Name, JsonElement Value)>();
        foreach (var parameter in payload.EnumerateObject())
        {
            if (!names.Add(parameter.Name))
            {
                error = $"The request object contains duplicate parameter '{parameter.Name}'.";
                return false;
            }

            // JWT validation claims are not OAuth authorization parameters.
            if (parameter.Name is "iss" or "aud" or "exp" or "iat" or "nbf"
                or "jti" or "client_id")
            {
                continue;
            }

            // A Request Object cannot recursively select another request
            // carrier. Allowing this would reintroduce an unsigned/remote
            // parameter source after the signed payload was validated.
            if (parameter.Name is OpenIddictConstants.Parameters.Request
                or OpenIddictConstants.Parameters.RequestUri)
            {
                error = "A request object cannot contain request or request_uri.";
                return false;
            }

            signedParameters.Add((parameter.Name, parameter.Value.Clone()));
        }

        foreach (var name in request.GetParameters()
                     .Select(parameter => parameter.Key)
                     .ToArray())
        {
            request.RemoveParameter(name);
        }

        request.ClientId = clientId;
        foreach (var parameter in signedParameters)
        {
            request.SetParameter(parameter.Name, parameter.Value);
        }

        error = null;
        return true;
    }

}
