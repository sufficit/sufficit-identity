using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using Sufficit.Identity.Application.Accounts;

namespace Sufficit.Identity.STS;

/// <summary>
/// Projects the current OpenIddict transaction into the neutral consent
/// contract consumed by the UI.
/// </summary>
public sealed class OpenIddictAuthorizationConsentService(
    IHttpContextAccessor httpContextAccessor,
    IOpenIddictApplicationManager applicationManager,
    ILogger<OpenIddictAuthorizationConsentService> logger)
    : IAuthorizationConsentService
{
    public async Task<AuthorizationConsentContext> GetCurrentAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var httpContext = httpContextAccessor.HttpContext;
        if (httpContext is null)
        {
            return Invalid();
        }

        IEnumerable<KeyValuePair<string, Microsoft.Extensions.Primitives.StringValues>>
            parameters = httpContext.Request.Query;
        if (httpContext.Request.HasFormContentType)
        {
            parameters = await httpContext.Request.ReadFormAsync(
                cancellationToken);
        }

        var lookup = parameters
            .GroupBy(parameter =>
                parameter.Key,
                StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                group => group.Key,
                group => group
                    .SelectMany(parameter => parameter.Value)
                    .ToArray(),
                StringComparer.OrdinalIgnoreCase);
        if (!lookup.TryGetValue("client_id", out var clientIds)
            || string.IsNullOrWhiteSpace(clientIds.FirstOrDefault()))
        {
            logger.LogWarning(
                "Consent presentation reached without a client_id.");
            return Invalid();
        }

        var clientId = clientIds[0]!;
        var application = await applicationManager.FindByClientIdAsync(
            clientId,
            cancellationToken);
        var displayName = application is null
            ? clientId
            : await applicationManager.GetDisplayNameAsync(
                application,
                cancellationToken) ?? clientId;
        var scopes = lookup.TryGetValue("scope", out var scopeValues)
            ? scopeValues
                .SelectMany(value => (value ?? string.Empty).Split(
                    ' ',
                    StringSplitOptions.RemoveEmptyEntries))
                .Distinct(StringComparer.Ordinal)
                .ToArray()
            : [];
        var passthrough = lookup
            .Where(pair => !string.Equals(
                pair.Key,
                "scope",
                StringComparison.OrdinalIgnoreCase))
            .SelectMany(pair => pair.Value.Select(value =>
                new AuthorizationConsentParameter(
                    pair.Key,
                    value ?? string.Empty)))
            .ToArray();

        return new AuthorizationConsentContext(
            true,
            clientId,
            displayName,
            scopes,
            passthrough);
    }

    private static AuthorizationConsentContext Invalid() =>
        new(false, null, null, [], []);
}
