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
public sealed partial class IntegrationOAuthController(
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
            try
            {
                token = await RefreshAsync(definition, token, cancellationToken);
                await SaveTokenAsync(subject, definition.Id, token, cancellationToken);
            }
            catch (IntegrationOAuthTokenRequestException exception)
                when (exception.Failure.RequiresReauthorization)
            {
                await secrets.DeleteAsync(
                    TokenName(definition.Id),
                    PersonalContext(subject),
                    cancellationToken);
                return Conflict(new { error = "authorization_expired" });
            }
            catch (IntegrationOAuthTokenRequestException)
            {
                return StatusCode(
                    (int)System.Net.HttpStatusCode.BadGateway,
                    new { error = "provider_temporarily_unavailable" });
            }
            catch (Exception exception)
                when (exception is HttpRequestException or JsonException or InvalidOperationException)
            {
                return StatusCode(
                    (int)System.Net.HttpStatusCode.BadGateway,
                    new { error = "provider_temporarily_unavailable" });
            }
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
