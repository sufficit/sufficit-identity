using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using Sufficit.Identity.Application.Accounts;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS;

/// <summary>
/// Creates and reads an encrypted, expiring projection of a validated device
/// transaction. This lets the authenticated Blazor page explain the client and
/// requested scopes without exposing those details from an enumerable
/// anonymous user-code lookup endpoint.
/// </summary>
public sealed class OpenIddictDeviceAuthorizationContextService :
    IDeviceAuthorizationContextService
{
    public const string TicketParameterName = "device_context";

    private static readonly TimeSpan TicketLifetime = TimeSpan.FromMinutes(10);

    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IOpenIddictTokenManager _tokenManager;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOptionsMonitor<OpenIddictServerOptions> _serverOptions;
    private readonly ITimeLimitedDataProtector _protector;

    public OpenIddictDeviceAuthorizationContextService(
        IHttpContextAccessor httpContextAccessor,
        IOpenIddictTokenManager tokenManager,
        IOpenIddictApplicationManager applicationManager,
        IOptionsMonitor<OpenIddictServerOptions> serverOptions,
        IDataProtectionProvider dataProtectionProvider)
    {
        _httpContextAccessor = httpContextAccessor;
        _tokenManager = tokenManager;
        _applicationManager = applicationManager;
        _serverOptions = serverOptions;
        _protector = dataProtectionProvider
            .CreateProtector("Sufficit.Identity.DeviceAuthorizationContext.v2")
            .ToTimeLimitedDataProtector();
    }

    public async Task<string?> CreateTicketAsync(
        string? userCode,
        ClaimsPrincipal authorizationPrincipal,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(userCode))
        {
            return null;
        }

        var normalized = NormalizeUserCode(userCode);
        var token = await _tokenManager.FindByReferenceIdAsync(
            normalized,
            cancellationToken);
        if (token is null
            || !await _tokenManager.HasStatusAsync(
                token,
                Statuses.Valid,
                cancellationToken)
            || !await _tokenManager.HasTypeAsync(
                token,
                TokenTypeIdentifiers.Private.UserCode,
                cancellationToken))
        {
            return null;
        }

        var applicationId = await _tokenManager.GetApplicationIdAsync(
            token,
            cancellationToken);
        var application = applicationId is null
            ? null
            : await _applicationManager.FindByIdAsync(
                applicationId,
                cancellationToken);
        if (application is null)
        {
            return null;
        }

        var clientId = await _applicationManager.GetClientIdAsync(
            application,
            cancellationToken);
        if (string.IsNullOrWhiteSpace(clientId))
        {
            return null;
        }

        var displayName = await _applicationManager.GetDisplayNameAsync(
            application,
            cancellationToken) ?? clientId;
        var scopes = authorizationPrincipal.GetScopes()
            .Where(scope => !string.IsNullOrWhiteSpace(scope))
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var accessTokenLifetime = authorizationPrincipal.GetAccessTokenLifetime()
            ?? await GetApplicationAccessTokenLifetimeAsync(
                application,
                cancellationToken)
            ?? _serverOptions.CurrentValue.AccessTokenLifetime;

        var payload = JsonSerializer.Serialize(new DeviceAuthorizationTicket(
            normalized,
            clientId,
            displayName,
            scopes,
            accessTokenLifetime?.Ticks,
            scopes.Contains(Scopes.OfflineAccess, StringComparer.Ordinal)));
        return _protector.Protect(payload, TicketLifetime);
    }

    public Task<DeviceAuthorizationContext> GetCurrentAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var context = _httpContextAccessor.HttpContext;
        var protectedTicket = context?.Request.Query[TicketParameterName]
            .ToString();
        if (string.IsNullOrWhiteSpace(protectedTicket))
        {
            return Task.FromResult(Invalid());
        }

        try
        {
            var payload = _protector.Unprotect(protectedTicket);
            var ticket = JsonSerializer.Deserialize<DeviceAuthorizationTicket>(
                payload);
            if (ticket is null
                || string.IsNullOrWhiteSpace(ticket.UserCode)
                || string.IsNullOrWhiteSpace(ticket.ClientId)
                || string.IsNullOrWhiteSpace(ticket.ClientDisplayName))
            {
                return Task.FromResult(Invalid());
            }

            var rawCode = context!.Request.Query["user_code"].ToString();
            if (string.IsNullOrWhiteSpace(rawCode))
            {
                rawCode = context.Request.Query["code"].ToString();
            }

            if (string.IsNullOrWhiteSpace(rawCode)
                || !string.Equals(
                    NormalizeUserCode(rawCode),
                    ticket.UserCode,
                    StringComparison.Ordinal))
            {
                return Task.FromResult(Invalid());
            }

            return Task.FromResult(new DeviceAuthorizationContext(
                true,
                ticket.ClientId,
                ticket.ClientDisplayName,
                ticket.RequestedScopes ?? [],
                ticket.AccessTokenLifetimeTicks is { } ticks
                    ? TimeSpan.FromTicks(ticks)
                    : null,
                ticket.AllowsRefreshAccess));
        }
        catch (Exception exception) when (exception is CryptographicException
            or JsonException)
        {
            return Task.FromResult(Invalid());
        }
    }

    private static DeviceAuthorizationContext Invalid() =>
        new(false, null, null, [], null, false);

    private async Task<TimeSpan?> GetApplicationAccessTokenLifetimeAsync(
        object application,
        CancellationToken cancellationToken)
    {
        var settings = await _applicationManager.GetSettingsAsync(
            application,
            cancellationToken);
        return settings.TryGetValue(
                Settings.TokenLifetimes.AccessToken,
                out var value)
            && TimeSpan.TryParse(
                value,
                CultureInfo.InvariantCulture,
                out var lifetime)
                ? lifetime
                : null;
    }

    private static string NormalizeUserCode(string code) =>
        code.Trim().ToUpperInvariant().Replace("-", string.Empty)
            .Replace(" ", string.Empty);

    private sealed record DeviceAuthorizationTicket(
        string UserCode,
        string ClientId,
        string ClientDisplayName,
        string[] RequestedScopes,
        long? AccessTokenLifetimeTicks,
        bool AllowsRefreshAccess);
}
