using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Clients;

/// <summary>
/// Canonical application boundary for OAuth/OIDC client administration.
/// Embedded UI and HTTP controllers are adapters over this contract.
/// </summary>
public interface IClientManagementService
{
    Task<IReadOnlyList<ManagementClientSummary>> ListAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementClientDetail> GetByIdAsync(
        string id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementClientDetail> GetByClientIdAsync(
        string clientId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementClientDetail> CreateAsync(
        CreateManagementClientCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task DeleteAsync(
        string clientId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}

public sealed record ManagementClientSummary(
    string Id,
    string ClientId,
    string? DisplayName,
    string? Type);

public sealed record ManagementClientDetail(
    string Id,
    string ClientId,
    string? DisplayName,
    string? Type,
    string? ConsentType,
    IReadOnlyList<string> Permissions,
    IReadOnlyList<string> Requirements,
    IReadOnlyList<string> RedirectUris,
    IReadOnlyList<string> PostLogoutRedirectUris);

public sealed record CreateManagementClientCommand(
    string ClientId,
    string? ClientSecret,
    string? DisplayName,
    string? ConsentType,
    bool RequirePar,
    IReadOnlyList<string> GrantTypes,
    IReadOnlyList<string> Scopes,
    IReadOnlyList<string> RedirectUris);

internal sealed class ClientManagementService(
    IOpenIddictApplicationManager applications,
    AppDbContext database,
    IManagementAuthorizationEvaluator authorization,
    ILogger<ClientManagementService> logger) : IClientManagementService
{
    public async Task<IReadOnlyList<ManagementClientSummary>> ListAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        await DemandAsync(
            context,
            ManagementCapabilities.ClientsRead,
            new ManagementResource(ManagementResourceTypes.ClientCollection),
            cancellationToken);

        var result = new List<ManagementClientSummary>();

        await foreach (var application in applications.ListAsync(
            cancellationToken: cancellationToken))
        {
            result.Add(new ManagementClientSummary(
                Id: (string)(await applications.GetIdAsync(
                    application,
                    cancellationToken))!,
                ClientId: (string)(await applications.GetClientIdAsync(
                    application,
                    cancellationToken))!,
                DisplayName: (string?)await applications.GetDisplayNameAsync(
                    application,
                    cancellationToken),
                Type: (string?)await applications.GetClientTypeAsync(
                    application,
                    cancellationToken)));
        }

        return result
            .OrderBy(client => client.DisplayName ?? client.ClientId,
                StringComparer.OrdinalIgnoreCase)
            .ThenBy(client => client.ClientId, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public async Task<ManagementClientDetail> GetByIdAsync(
        string id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);

        await DemandAsync(
            context,
            ManagementCapabilities.ClientsRead,
            new ManagementResource(ManagementResourceTypes.Client, id),
            cancellationToken);

        var application = await applications.FindByIdAsync(id, cancellationToken);
        if (application is null)
        {
            throw new ManagementNotFoundException(
                "client_not_found",
                "The OAuth client was not found.");
        }

        return await ToDetailAsync(application, cancellationToken);
    }

    public async Task<ManagementClientDetail> GetByClientIdAsync(
        string clientId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);

        await DemandAsync(
            context,
            ManagementCapabilities.ClientsRead,
            new ManagementResource(ManagementResourceTypes.Client, clientId),
            cancellationToken);

        var application = await applications.FindByClientIdAsync(
            clientId,
            cancellationToken);
        if (application is null)
        {
            throw new ManagementNotFoundException(
                "client_not_found",
                $"Client '{clientId}' was not found.");
        }

        return await ToDetailAsync(application, cancellationToken);
    }

    public async Task<ManagementClientDetail> CreateAsync(
        CreateManagementClientCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        var clientId = command.ClientId?.Trim() ?? string.Empty;
        var resource = new ManagementResource(
            ManagementResourceTypes.Client,
            clientId);
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.ClientsCreate,
            resource,
            cancellationToken);

        try
        {
            ValidateClientId(clientId);
            var redirectUris = ValidateRedirectUris(command.RedirectUris);
            var consentType = NormalizeConsentType(command.ConsentType)
                ?? OpenIddictConstants.ConsentTypes.Explicit;

            if (await applications.FindByClientIdAsync(
                    clientId,
                    cancellationToken) is not null)
            {
                await TryWriteAuditAsync(
                    context,
                    ManagementCapabilities.ClientsCreate,
                    resource,
                    decision,
                    "conflict",
                    "client_already_exists",
                    cancellationToken);
                throw new ManagementConflictException(
                    "client_already_exists",
                    $"Client '{clientId}' already exists.");
            }

            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                ClientSecret = string.IsNullOrEmpty(command.ClientSecret)
                    ? null
                    : command.ClientSecret,
                DisplayName = NullIfWhiteSpace(command.DisplayName),
                ConsentType = consentType,
                ClientType = string.IsNullOrEmpty(command.ClientSecret)
                    ? OpenIddictConstants.ClientTypes.Public
                    : OpenIddictConstants.ClientTypes.Confidential,
            };

            foreach (var grantType in NormalizeGrantTypes(command.GrantTypes))
            {
                descriptor.Permissions.Add(grantType);
            }

            foreach (var scope in NormalizeScopes(command.Scopes))
            {
                descriptor.Permissions.Add(scope);
            }

            foreach (var redirectUri in redirectUris)
            {
                descriptor.RedirectUris.Add(redirectUri);
            }

            if (descriptor.Permissions.Contains(
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode)
                && descriptor.ClientType == OpenIddictConstants.ClientTypes.Public)
            {
                descriptor.Requirements.Add(
                    OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange);
            }

            if (command.RequirePar)
            {
                descriptor.Requirements.Add(
                    OpenIddictConstants.Requirements.Features.PushedAuthorizationRequests);
            }

            await using var transaction = await database.Database
                .BeginTransactionAsync(cancellationToken);

            var application = await applications.CreateAsync(
                descriptor,
                cancellationToken);
            var detail = await ToDetailAsync(application, cancellationToken);

            database.ManagementAuditEvents.Add(ManagementAuditEventFactory.Create(
                context,
                ManagementCapabilities.ClientsCreate,
                new ManagementResource(
                    ManagementResourceTypes.Client,
                    detail.ClientId),
                decision,
                "succeeded"));
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            return detail;
        }
        catch (ManagementValidationException exception)
        {
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.ClientsCreate,
                resource,
                decision,
                "rejected",
                exception.ReasonCode,
                cancellationToken);
            throw;
        }
        catch (ManagementConflictException)
        {
            throw;
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "OAuth client creation failed. ClientId={ClientId} CorrelationId={CorrelationId}",
                clientId,
                context.CorrelationId);
            throw;
        }
    }

    public async Task DeleteAsync(
        string clientId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);

        var resource = new ManagementResource(
            ManagementResourceTypes.Client,
            clientId);
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.ClientsDelete,
            resource,
            cancellationToken);

        var application = await applications.FindByClientIdAsync(
            clientId,
            cancellationToken);
        if (application is null)
        {
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.ClientsDelete,
                resource,
                decision,
                "not-found",
                "client_not_found",
                cancellationToken);
            throw new ManagementNotFoundException(
                "client_not_found",
                $"Client '{clientId}' was not found.");
        }

        try
        {
            await using var transaction = await database.Database
                .BeginTransactionAsync(cancellationToken);

            await applications.DeleteAsync(application, cancellationToken);
            database.ManagementAuditEvents.Add(ManagementAuditEventFactory.Create(
                context,
                ManagementCapabilities.ClientsDelete,
                resource,
                decision,
                "succeeded"));
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "OAuth client deletion failed. ClientId={ClientId} CorrelationId={CorrelationId}",
                clientId,
                context.CorrelationId);
            throw;
        }
    }

    private async Task<ManagementAuthorizationDecision> DemandAsync(
        ManagementRequestContext context,
        string capability,
        ManagementResource resource,
        CancellationToken cancellationToken)
    {
        var decision = await authorization.EvaluateAsync(
            context.Operator,
            capability,
            resource,
            cancellationToken);

        if (decision.IsAllowed)
        {
            return decision;
        }

        await TryWriteAuditAsync(
            context,
            capability,
            resource,
            decision,
            "denied",
            decision.ReasonCode,
            cancellationToken);
        throw new ManagementAccessException(decision);
    }

    private async Task TryWriteAuditAsync(
        ManagementRequestContext context,
        string capability,
        ManagementResource resource,
        ManagementAuthorizationDecision decision,
        string operationOutcome,
        string? reasonCode,
        CancellationToken cancellationToken)
    {
        try
        {
            database.ManagementAuditEvents.Add(ManagementAuditEventFactory.Create(
                context,
                capability,
                resource,
                decision,
                operationOutcome,
                reasonCode));
            await database.SaveChangesAsync(cancellationToken);
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "Unable to persist management audit event. Capability={Capability} CorrelationId={CorrelationId}",
                capability,
                context.CorrelationId);
        }
    }

    private async Task<ManagementClientDetail> ToDetailAsync(
        object application,
        CancellationToken cancellationToken)
    {
        var permissions = await applications.GetPermissionsAsync(
            application,
            cancellationToken);
        var requirements = await applications.GetRequirementsAsync(
            application,
            cancellationToken);
        var redirectUris = await applications.GetRedirectUrisAsync(
            application,
            cancellationToken);
        var postLogoutRedirectUris =
            await applications.GetPostLogoutRedirectUrisAsync(
                application,
                cancellationToken);

        return new ManagementClientDetail(
            Id: (string)(await applications.GetIdAsync(
                application,
                cancellationToken))!,
            ClientId: (string)(await applications.GetClientIdAsync(
                application,
                cancellationToken))!,
            DisplayName: (string?)await applications.GetDisplayNameAsync(
                application,
                cancellationToken),
            Type: (string?)await applications.GetClientTypeAsync(
                application,
                cancellationToken),
            ConsentType: (string?)await applications.GetConsentTypeAsync(
                application,
                cancellationToken),
            Permissions: permissions.Order(StringComparer.Ordinal).ToArray(),
            Requirements: requirements.Order(StringComparer.Ordinal).ToArray(),
            RedirectUris: redirectUris
                .Order(StringComparer.Ordinal)
                .ToArray(),
            PostLogoutRedirectUris: postLogoutRedirectUris
                .Order(StringComparer.Ordinal)
                .ToArray());
    }

    private static void ValidateClientId(string clientId)
    {
        if (string.IsNullOrWhiteSpace(clientId))
        {
            throw new ManagementValidationException(
                "client_id_required",
                "client_id is required.",
                "clientId");
        }

        if (clientId.Length > IdentityDatabaseSchema.OpenIddictClientIdLength)
        {
            throw new ManagementValidationException(
                "client_id_too_long",
                $"client_id cannot exceed {IdentityDatabaseSchema.OpenIddictClientIdLength} characters.",
                "clientId");
        }
    }

    private static IReadOnlyList<Uri> ValidateRedirectUris(
        IReadOnlyList<string>? values)
    {
        var result = new List<Uri>();

        foreach (var raw in values ?? [])
        {
            if (string.IsNullOrWhiteSpace(raw))
            {
                continue;
            }

            if (!Uri.TryCreate(raw.Trim(), UriKind.Absolute, out var redirect))
            {
                throw new ManagementValidationException(
                    "redirect_uri_invalid",
                    $"redirect_uri must be an absolute URI: {raw}",
                    "redirectUris");
            }

            if (redirect.Fragment.Length > 0)
            {
                throw new ManagementValidationException(
                    "redirect_uri_fragment",
                    $"redirect_uri cannot contain a fragment: {redirect}",
                    "redirectUris");
            }

            var isLoopback = redirect.IsLoopback
                || string.Equals(
                    redirect.Host,
                    "localhost",
                    StringComparison.OrdinalIgnoreCase);
            if (!string.Equals(
                    redirect.Scheme,
                    Uri.UriSchemeHttps,
                    StringComparison.OrdinalIgnoreCase)
                && !isLoopback)
            {
                throw new ManagementValidationException(
                    "redirect_uri_https_required",
                    "redirect_uri must use https (http is only allowed for " +
                    $"loopback): {redirect}",
                    "redirectUris");
            }

            result.Add(redirect);
        }

        return result
            .DistinctBy(uri => uri.AbsoluteUri, StringComparer.Ordinal)
            .ToArray();
    }

    private static IReadOnlyList<string> NormalizeGrantTypes(
        IReadOnlyList<string>? values) =>
        (values ?? [])
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim())
            .Select(value => value switch
            {
                "authorization_code" =>
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                "client_credentials" =>
                    OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                "refresh_token" =>
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                "password" =>
                    OpenIddictConstants.Permissions.GrantTypes.Password,
                "implicit" =>
                    OpenIddictConstants.Permissions.GrantTypes.Implicit,
                _ => value
            })
            .Distinct(StringComparer.Ordinal)
            .ToArray();

    private static IReadOnlyList<string> NormalizeScopes(
        IReadOnlyList<string>? values) =>
        (values ?? [])
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim())
            .Select(value => value.StartsWith(
                    OpenIddictConstants.Permissions.Prefixes.Scope,
                    StringComparison.Ordinal)
                ? value
                : OpenIddictConstants.Permissions.Prefixes.Scope + value)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

    private static string? NormalizeConsentType(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        return raw switch
        {
            var value when string.Equals(
                    value,
                    "explicit",
                    StringComparison.OrdinalIgnoreCase)
                || string.Equals(
                    value,
                    OpenIddictConstants.ConsentTypes.Explicit,
                    StringComparison.OrdinalIgnoreCase)
                => OpenIddictConstants.ConsentTypes.Explicit,
            var value when string.Equals(
                    value,
                    "implicit",
                    StringComparison.OrdinalIgnoreCase)
                || string.Equals(
                    value,
                    OpenIddictConstants.ConsentTypes.Implicit,
                    StringComparison.OrdinalIgnoreCase)
                => OpenIddictConstants.ConsentTypes.Implicit,
            var value when string.Equals(
                    value,
                    "external",
                    StringComparison.OrdinalIgnoreCase)
                || string.Equals(
                    value,
                    OpenIddictConstants.ConsentTypes.External,
                    StringComparison.OrdinalIgnoreCase)
                => OpenIddictConstants.ConsentTypes.External,
            var value when string.Equals(
                    value,
                    "systematic",
                    StringComparison.OrdinalIgnoreCase)
                || string.Equals(
                    value,
                    OpenIddictConstants.ConsentTypes.Systematic,
                    StringComparison.OrdinalIgnoreCase)
                => OpenIddictConstants.ConsentTypes.Systematic,
            _ => throw new ManagementValidationException(
                "consent_type_invalid",
                $"Unknown consent type: '{raw}'. Valid values: explicit, " +
                "implicit, external, systematic.",
                "consentType")
        };
    }

    private static string? NullIfWhiteSpace(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
