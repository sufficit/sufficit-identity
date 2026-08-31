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

public sealed partial class IntegrationOAuthController
{
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
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        if (!response.IsSuccessStatusCode)
            throw new IntegrationOAuthTokenRequestException(
                IntegrationOAuthProviderFailure.Parse(response.StatusCode, body));
        var payload = JsonSerializer.Deserialize<JsonElement>(body);
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
