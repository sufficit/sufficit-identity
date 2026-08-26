using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using OpenIddict.Abstractions;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.STS.Integrations;
using Sufficit.Identity.Vault;
using static OpenIddict.Abstractions.OpenIddictConstants;
using WebBase64UrlTextEncoder = Microsoft.AspNetCore.WebUtilities.Base64UrlTextEncoder;

namespace Sufficit.Identity.STS.Controllers;

/// <summary>
/// Subject-bound OAuth broker for the optional third-party integrations a
/// native client may connect on the user's behalf. The bearer token selects
/// the Vault owner; browser callbacks carry only a short-lived, encrypted
/// ticket and never an Identity or provider token in their URL.
/// </summary>
[ApiController]
[Route("api/integrations/oauth")]
public sealed class IntegrationOAuthController(
    IntegrationOAuthProviderRegistry providers,
    IVaultNamedSecretStore secrets,
    IDataProtectionProvider dataProtection,
    IHttpClientFactory httpClients,
    IClientNativeReturnUriResolver nativeReturnUris,
    IOpenIddictApplicationManager applications) : ControllerBase
{
    private const string McpPolicy = "sufficit-identity-mcp";
    private const string HttpClientName = "identity-integration-oauth";
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly ITimeLimitedDataProtector tickets = dataProtection
        .CreateProtector("Sufficit.Identity.IntegrationOAuth.v1")
        .ToTimeLimitedDataProtector();

    [Authorize(Policy = McpPolicy)]
    [HttpGet("{provider}/status")]
    public async Task<IActionResult> Status(
        string provider,
        CancellationToken cancellationToken)
    {
        var definition = providers.Find(provider);
        if (definition is null) return NotFound();
        var token = await ReadTokenAsync(
            Subject(),
            definition.Id,
            cancellationToken);
        var connected = token is not null
            && IntegrationOAuthProtocol.HasRequiredScopes(
                definition.Scopes,
                token.Scope);
        return Ok(new IntegrationOAuthStatus(
            definition.Id,
            definition.Available,
            connected,
            token?.ExpiresAtUtc));
    }

    [Authorize(Policy = McpPolicy)]
    [HttpPost("{provider}/authorize")]
    public async Task<IActionResult> Authorize(
        string provider,
        [FromQuery(Name = "return_uri")] string? returnUri,
        CancellationToken cancellationToken)
    {
        var definition = providers.Find(provider);
        if (definition is null) return NotFound();
        if (!definition.Available)
        {
            return Conflict(new
            {
                error = "provider_unavailable",
                message = $"{definition.DisplayName} ainda não possui autorização central configurada.",
            });
        }

        var subject = Subject();
        var nonce = WebBase64UrlTextEncoder.Encode(RandomNumberGenerator.GetBytes(24));
        var callbackUri = AbsoluteCallback(definition.Id);

        // Where the browser goes when the provider is done is registration
        // data belonging to the calling client, never a value this server
        // knows in advance (RFC 8252, section 8.1).
        var nativeReturnUri = await nativeReturnUris.ResolveAsync(
            CallerClientId(),
            returnUri,
            cancellationToken);
        if (nativeReturnUri is null)
        {
            return BadRequest(new
            {
                error = "return_uri_not_registered",
                message =
                    "O cliente chamador não possui um retorno nativo registrado para esta operação.",
            });
        }

        var pending = definition.RegistrationEndpoint is null
            ? new PendingIntegrationOAuth(
                definition.Id,
                nativeReturnUri,
                callbackUri,
                CodeVerifier: null,
                ClientId: null,
                ClientSecret: null)
            : await RegisterDynamicClientAsync(
                definition,
                callbackUri,
                nativeReturnUri,
                await CallerDisplayNameAsync(cancellationToken),
                cancellationToken);
        await secrets.PutAsync(
            PendingName(nonce),
            JsonSerializer.Serialize(pending, Json),
            subject,
            PersonalContext(subject),
            DateTime.UtcNow.AddMinutes(15),
            cancellationToken);
        var ticket = Protect(new IntegrationOAuthTicket(
            subject,
            definition.Id,
            nonce,
            nativeReturnUri));

        var authorizationUrl = definition.Scheme is not null
            ? QueryHelpers.AddQueryString(
                Absolute($"/api/integrations/oauth/{definition.Id}/start"),
                "ticket",
                ticket)
            : BuildDynamicAuthorizationUrl(definition, pending, ticket);
        return Ok(new IntegrationOAuthAuthorization(authorizationUrl));
    }

    [AllowAnonymous]
    [HttpGet("{provider}/start")]
    public async Task<IActionResult> Start(
        string provider,
        [FromQuery] string ticket,
        CancellationToken cancellationToken)
    {
        var definition = providers.Find(provider);
        if (definition?.Available != true || definition.Scheme is null)
            return NotFound();
        IntegrationOAuthTicket flow;
        try
        {
            flow = Unprotect(ticket, definition.Id);
        }
        catch (Exception exception) when (exception is CryptographicException or FormatException)
        {
            return BadRequest("Authorization request expired.");
        }
        var pending = await ReadPendingAsync(flow, cancellationToken);
        if (pending is null) return BadRequest("Authorization request expired.");

        var callback = QueryHelpers.AddQueryString(
            pending.CallbackUri,
            "ticket",
            ticket);
        OAuthChallengeProperties properties = definition.Id == "google-workspace"
            ? new GoogleChallengeProperties
            {
                RedirectUri = callback,
                Scope = definition.Scopes.ToArray(),
                AccessType = "offline",
                Prompt = "consent",
                IncludeGrantedScopes = true,
            }
            : new OAuthChallengeProperties
            {
                RedirectUri = callback,
                Scope = definition.Scopes.ToArray(),
            };
        properties.Items["LoginProvider"] = definition.Scheme;
        return Challenge(properties, definition.Scheme);
    }

    [AllowAnonymous]
    [HttpGet("callback/{provider}")]
    public async Task<IActionResult> Callback(
        string provider,
        [FromQuery] string? ticket,
        [FromQuery] string? state,
        [FromQuery] string? code,
        [FromQuery] string? error,
        CancellationToken cancellationToken)
    {
        var definition = providers.Find(provider);
        if (definition is null) return NotFound();
        IntegrationOAuthTicket flow;
        try
        {
            flow = Unprotect(ticket ?? state ?? string.Empty, definition.Id);
        }
        catch (Exception exception) when (exception is CryptographicException or FormatException)
        {
            // Nothing here is trustworthy: an unreadable ticket names no
            // client, so there is no registered callback to send the browser
            // to and inventing one would be an open redirect.
            return BadRequest(new
            {
                error = "authorization_expired",
                message = "A autorização expirou. Reinicie a conexão pelo aplicativo.",
            });
        }

        var pending = await ReadPendingAsync(flow, cancellationToken);
        if (pending is null)
            return Redirect(ReturnLocation(flow.ReturnUri, definition.Id, "expired"));
        if (!string.IsNullOrWhiteSpace(error))
        {
            await DeletePendingAsync(flow, cancellationToken);
            return Redirect(ReturnLocation(pending.ReturnUri, definition.Id, "cancelled"));
        }

        try
        {
            IntegrationOAuthToken token;
            if (definition.Scheme is not null)
            {
                var authentication = await HttpContext.AuthenticateAsync(
                    IdentityConstants.ExternalScheme);
                if (!authentication.Succeeded || authentication.Properties is null)
                    return Redirect(ReturnLocation(pending.ReturnUri, definition.Id, "failed"));
                authentication.Properties.Items.TryGetValue(
                    "LoginProvider",
                    out var loginProvider);
                if (!string.Equals(
                        loginProvider,
                        definition.Scheme,
                        StringComparison.Ordinal))
                    return Redirect(ReturnLocation(pending.ReturnUri, definition.Id, "failed"));
                token = FromAuthenticationProperties(authentication.Properties);
            }
            else
            {
                if (string.IsNullOrWhiteSpace(code))
                    return Redirect(ReturnLocation(pending.ReturnUri, definition.Id, "failed"));
                token = await ExchangeCodeAsync(
                    definition,
                    pending,
                    code,
                    cancellationToken);
            }

            await SaveTokenAsync(flow.Subject, definition.Id, token, cancellationToken);
            await DeletePendingAsync(flow, cancellationToken);
            return Redirect(ReturnLocation(pending.ReturnUri, definition.Id, "connected"));
        }
        catch (HttpRequestException)
        {
            return Redirect(ReturnLocation(pending.ReturnUri, definition.Id, "failed"));
        }
        catch (Exception exception) when (exception is InvalidOperationException or JsonException)
        {
            return Redirect(ReturnLocation(pending.ReturnUri, definition.Id, "failed"));
        }
        finally
        {
            if (definition.Scheme is not null)
                await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);
        }
    }

    [Authorize(Policy = McpPolicy)]
    [HttpGet("{provider}/access")]
    public async Task<IActionResult> Access(
        string provider,
        CancellationToken cancellationToken)
    {
        var definition = providers.Find(provider);
        if (definition is null) return NotFound();
        if (!definition.Available)
            return Conflict(new { error = "provider_unavailable" });

        var subject = Subject();
        var token = await ReadTokenAsync(subject, definition.Id, cancellationToken);
        if (token is null
            || !IntegrationOAuthProtocol.HasRequiredScopes(
                definition.Scopes,
                token.Scope))
            return Conflict(new { error = "authorization_required" });
        if (token.ExpiresAtUtc is { } expiration
            && expiration <= DateTimeOffset.UtcNow.AddMinutes(2))
        {
            if (string.IsNullOrWhiteSpace(token.RefreshToken))
                return Conflict(new { error = "authorization_expired" });
            token = await RefreshAsync(definition, token, cancellationToken);
            await SaveTokenAsync(subject, definition.Id, token, cancellationToken);
        }

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Authorization"] = $"{token.TokenType ?? "Bearer"} {token.AccessToken}",
        };
        if (!string.IsNullOrWhiteSpace(definition.ProjectId))
            headers["X-Goog-User-Project"] = definition.ProjectId;
        return Ok(new IntegrationOAuthAccess(headers, token.ExpiresAtUtc));
    }

    [Authorize(Policy = McpPolicy)]
    [HttpDelete("{provider}")]
    public async Task<IActionResult> Disconnect(
        string provider,
        CancellationToken cancellationToken)
    {
        var definition = providers.Find(provider);
        if (definition is null) return NotFound();
        await secrets.DeleteAsync(
            TokenName(definition.Id),
            PersonalContext(Subject()),
            cancellationToken);
        return NoContent();
    }

    private async Task<PendingIntegrationOAuth> RegisterDynamicClientAsync(
        IntegrationOAuthProvider provider,
        string callbackUri,
        string returnUri,
        string clientName,
        CancellationToken cancellationToken)
    {
        using var response = await httpClients.CreateClient(HttpClientName)
            .PostAsJsonAsync(
                provider.RegistrationEndpoint,
                IntegrationOAuthProtocol.DynamicRegistration(
                    provider,
                    callbackUri,
                    clientName),
                cancellationToken);
        response.EnsureSuccessStatusCode();
        var payload = await response.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: cancellationToken);
        var clientId = RequiredString(payload, "client_id");
        var clientSecret = String(payload, "client_secret");
        var verifier = WebBase64UrlTextEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        return new PendingIntegrationOAuth(
            provider.Id,
            returnUri,
            callbackUri,
            verifier,
            clientId,
            clientSecret);
    }

    private static string BuildDynamicAuthorizationUrl(
        IntegrationOAuthProvider provider,
        PendingIntegrationOAuth pending,
        string ticket)
    {
        var challenge = WebBase64UrlTextEncoder.Encode(
            SHA256.HashData(Encoding.ASCII.GetBytes(pending.CodeVerifier!)));
        return QueryHelpers.AddQueryString(
            provider.AuthorizationEndpoint.ToString(),
            new Dictionary<string, string?>
            {
                ["client_id"] = pending.ClientId,
                ["redirect_uri"] = pending.CallbackUri,
                ["response_type"] = "code",
                ["scope"] = string.Join(' ', provider.Scopes),
                ["state"] = ticket,
                ["code_challenge"] = challenge,
                ["code_challenge_method"] = "S256",
            });
    }

    private async Task<IntegrationOAuthToken> ExchangeCodeAsync(
        IntegrationOAuthProvider provider,
        PendingIntegrationOAuth pending,
        string code,
        CancellationToken cancellationToken)
    {
        var fields = IntegrationOAuthProtocol.AuthorizationCodeFields(
            provider,
            code,
            pending.CallbackUri,
            pending.ClientId!,
            pending.ClientSecret,
            pending.CodeVerifier!);
        return await RequestTokenAsync(
            provider,
            fields,
            pending.ClientId,
            pending.ClientSecret,
            previousRefreshToken: null,
            previousScope: null,
            cancellationToken);
    }

    private async Task<IntegrationOAuthToken> RefreshAsync(
        IntegrationOAuthProvider provider,
        IntegrationOAuthToken token,
        CancellationToken cancellationToken)
    {
        var clientId = token.ClientId ?? provider.ClientId;
        var clientSecret = token.ClientSecret ?? provider.ClientSecret;
        if (string.IsNullOrWhiteSpace(clientId)
            || (provider.Scheme is not null && string.IsNullOrWhiteSpace(clientSecret)))
            throw new InvalidOperationException("OAuth client is unavailable for refresh.");
        var fields = IntegrationOAuthProtocol.RefreshFields(
            provider,
            token.RefreshToken!,
            clientId,
            clientSecret);
        return await RequestTokenAsync(
            provider,
            fields,
            token.ClientId,
            token.ClientSecret,
            token.RefreshToken,
            token.Scope,
            cancellationToken);
    }

    private async Task<IntegrationOAuthToken> RequestTokenAsync(
        IntegrationOAuthProvider provider,
        Dictionary<string, string> fields,
        string? dynamicClientId,
        string? dynamicClientSecret,
        string? previousRefreshToken,
        string? previousScope,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, provider.TokenEndpoint)
        {
            Content = new FormUrlEncodedContent(fields),
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        using var response = await httpClients.CreateClient(HttpClientName)
            .SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
        var payload = await response.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: cancellationToken);
        return FromTokenPayload(
            payload,
            dynamicClientId,
            dynamicClientSecret,
            previousRefreshToken,
            previousScope);
    }

    private static IntegrationOAuthToken FromAuthenticationProperties(
        AuthenticationProperties properties)
    {
        var accessToken = properties.GetTokenValue("access_token")
            ?? throw new InvalidOperationException("Provider returned no access token.");
        DateTimeOffset? expiresAt = null;
        if (DateTimeOffset.TryParse(
                properties.GetTokenValue("expires_at"),
                out var parsedExpiration))
            expiresAt = parsedExpiration;
        return new IntegrationOAuthToken(
            accessToken,
            properties.GetTokenValue("refresh_token"),
            properties.GetTokenValue("token_type") ?? "Bearer",
            expiresAt,
            properties.GetTokenValue("scope"),
            ClientId: null,
            ClientSecret: null);
    }

    private static IntegrationOAuthToken FromTokenPayload(
        JsonElement payload,
        string? clientId,
        string? clientSecret,
        string? previousRefreshToken,
        string? previousScope)
    {
        var accessToken = RequiredString(payload, "access_token");
        var refreshToken = String(payload, "refresh_token") ?? previousRefreshToken;
        DateTimeOffset? expiresAt = null;
        if (payload.TryGetProperty("expires_in", out var expires)
            && expires.TryGetInt64(out var seconds))
            expiresAt = DateTimeOffset.UtcNow.AddSeconds(seconds);
        return new IntegrationOAuthToken(
            accessToken,
            refreshToken,
            String(payload, "token_type") ?? "Bearer",
            expiresAt,
            String(payload, "scope") ?? previousScope,
            clientId,
            clientSecret);
    }

    private async Task<PendingIntegrationOAuth?> ReadPendingAsync(
        IntegrationOAuthTicket flow,
        CancellationToken cancellationToken)
    {
        var value = await secrets.GetSecretAsync(
            PendingName(flow.Nonce),
            PersonalContext(flow.Subject),
            cancellationToken);
        return value is null
            ? null
            : JsonSerializer.Deserialize<PendingIntegrationOAuth>(value, Json);
    }

    private async Task DeletePendingAsync(
        IntegrationOAuthTicket flow,
        CancellationToken cancellationToken) =>
        await secrets.DeleteAsync(
            PendingName(flow.Nonce),
            PersonalContext(flow.Subject),
            cancellationToken);

    private async Task<IntegrationOAuthToken?> ReadTokenAsync(
        string subject,
        string provider,
        CancellationToken cancellationToken)
    {
        var value = await secrets.GetSecretAsync(
            TokenName(provider),
            PersonalContext(subject),
            cancellationToken);
        return value is null
            ? null
            : JsonSerializer.Deserialize<IntegrationOAuthToken>(value, Json);
    }

    private async Task SaveTokenAsync(
        string subject,
        string provider,
        IntegrationOAuthToken token,
        CancellationToken cancellationToken) =>
        await secrets.PutAsync(
            TokenName(provider),
            JsonSerializer.Serialize(token, Json),
            subject,
            PersonalContext(subject),
            expiresAtUtc: null,
            cancellationToken);

    private string Protect(IntegrationOAuthTicket ticket) => tickets.Protect(
        JsonSerializer.Serialize(ticket, Json),
        TimeSpan.FromMinutes(15));

    private IntegrationOAuthTicket Unprotect(string value, string provider)
    {
        var ticket = JsonSerializer.Deserialize<IntegrationOAuthTicket>(
            tickets.Unprotect(value),
            Json) ?? throw new CryptographicException("Invalid OAuth ticket.");
        if (!string.Equals(ticket.Provider, provider, StringComparison.Ordinal))
            throw new CryptographicException("OAuth provider mismatch.");
        return ticket;
    }

    private string AbsoluteCallback(string provider) =>
        Absolute($"/api/integrations/oauth/callback/{provider}");

    private string Absolute(string path) =>
        $"{Request.Scheme}://{Request.Host}{Request.PathBase}{path}";

    /// <summary>
    /// Builds the redirect back to the client. The callback was resolved
    /// against the client registration when the flow started and has been
    /// held in server-side state ever since, so it is used as stored.
    /// </summary>
    private static string ReturnLocation(
        string returnUri,
        string provider,
        string status) =>
        QueryHelpers.AddQueryString(
            returnUri,
            new Dictionary<string, string?>
            {
                ["integration"] = provider,
                ["status"] = status,
            });

    private string Subject() => User.FindFirst("sub")?.Value
        ?? throw new InvalidOperationException(
            "The authenticated integration caller has no subject.");

    /// <summary>
    /// The client the presented access token was issued to. OpenIddict records
    /// it as the token's authorized presenter; the plain claim is accepted as
    /// a fallback for tokens shaped by other validation stacks.
    /// </summary>
    private string? CallerClientId() =>
        User.GetClaim(Claims.ClientId)
        ?? User.GetPresenters().FirstOrDefault();

    /// <summary>
    /// Display name of the calling client, used on the provider's consent
    /// screen. Falls back to the client identifier so a client that registered
    /// without a display name still names itself rather than this server.
    /// </summary>
    private async Task<string> CallerDisplayNameAsync(
        CancellationToken cancellationToken)
    {
        var clientId = CallerClientId();
        if (string.IsNullOrWhiteSpace(clientId))
        {
            throw new InvalidOperationException(
                "The authenticated integration caller has no client identifier.");
        }

        var application = await applications.FindByClientIdAsync(
            clientId,
            cancellationToken);
        var displayName = application is null
            ? null
            : await applications.GetDisplayNameAsync(application, cancellationToken);
        return string.IsNullOrWhiteSpace(displayName) ? clientId : displayName;
    }

    private static string PersonalContext(string subject) =>
        VaultBackedSecretStore.NormalizeContextId(
            "user-" + subject.ToLowerInvariant());

    private static string PendingName(string nonce) =>
        $"integrations/oauth/pending/{nonce.ToLowerInvariant()}";

    private static string TokenName(string provider) =>
        $"integrations/oauth/tokens/{provider}";

    private static string RequiredString(JsonElement value, string property) =>
        String(value, property)
        ?? throw new InvalidOperationException(
            $"OAuth response is missing {property}.");

    private static string? String(JsonElement value, string property) =>
        value.TryGetProperty(property, out var node)
            && node.ValueKind == JsonValueKind.String
            && !string.IsNullOrWhiteSpace(node.GetString())
                ? node.GetString()
                : null;
}

public sealed record IntegrationOAuthStatus(
    string Provider,
    bool Available,
    bool Connected,
    DateTimeOffset? ExpiresAtUtc);

public sealed record IntegrationOAuthAuthorization(string AuthorizationUrl);

public sealed record IntegrationOAuthAccess(
    IReadOnlyDictionary<string, string> Headers,
    DateTimeOffset? ExpiresAtUtc);

internal sealed record IntegrationOAuthTicket(
    string Subject,
    string Provider,
    string Nonce,
    // Carried in the encrypted ticket as well as in the pending record so the
    // browser can still be sent home when the pending record has expired but
    // the ticket itself is intact.
    string ReturnUri);

internal sealed record PendingIntegrationOAuth(
    string Provider,
    string ReturnUri,
    string CallbackUri,
    string? CodeVerifier,
    string? ClientId,
    string? ClientSecret);

internal sealed record IntegrationOAuthToken(
    string AccessToken,
    string? RefreshToken,
    string? TokenType,
    DateTimeOffset? ExpiresAtUtc,
    string? Scope,
    string? ClientId,
    string? ClientSecret);
