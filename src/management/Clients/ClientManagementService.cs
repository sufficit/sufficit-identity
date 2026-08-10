#if !APPLICATION_CONTRACTS
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Provisioning;
#endif
using System.Globalization;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Clients;

#if APPLICATION_CONTRACTS

/// <summary>
/// Canonical application boundary for OAuth/OIDC client administration.
/// Embedded UI and HTTP controllers are adapters over this contract.
/// </summary>
public interface IClientManagementService
{
    Task<IReadOnlyList<ManagementClientSummary>> ListAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Queries the application catalog with bounded paging. The default
    /// adapter keeps older embedders source-compatible; the server
    /// implementation overrides it with a database query.
    /// </summary>
    async Task<ManagementClientPage> SearchAsync(
        ManagementClientQuery query,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);
        var all = await ListAsync(context, cancellationToken);
        var search = query.Search?.Trim();
        var type = string.IsNullOrWhiteSpace(query.Type)
            ? "all"
            : query.Type.Trim().ToLowerInvariant();
        var filtered = all
            .Where(client => type == "all"
                || string.Equals(client.Type, type, StringComparison.OrdinalIgnoreCase))
            .Where(client => string.IsNullOrWhiteSpace(search)
                || client.ClientId.Contains(search, StringComparison.OrdinalIgnoreCase)
                || (client.DisplayName?.Contains(search,
                    StringComparison.OrdinalIgnoreCase) ?? false))
            .ToArray();
        if (query.Page < 1 || query.PageSize is < 1 or > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(query.PageSize),
                "Page must be positive and pageSize must be between 1 and 100.");
        }

        var page = (Page: query.Page, PageSize: query.PageSize);
        return new ManagementClientPage(
            filtered.Skip((page.Page - 1) * page.PageSize).Take(page.PageSize).ToArray(),
            filtered.Length,
            page.Page,
            page.PageSize);
    }

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

    Task<ManagementClientDetail> UpdateAsync(
        UpdateManagementClientCommand command,
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
    string? Type,
    string? Status = null,
    string? Origin = null);

public sealed record ManagementClientQuery(
    string? Search = null,
    string? Type = null,
    string? Grant = null,
    string? Scope = null,
    string? Origin = null,
    string? Status = null,
    int Page = 1,
    int PageSize = 25);

public sealed record ManagementClientPage(
    IReadOnlyList<ManagementClientSummary> Items,
    int TotalCount,
    int Page,
    int PageSize)
{
    public int PageCount =>
        TotalCount is 0 ? 0 : (int)Math.Ceiling(TotalCount / (double)PageSize);
}

public sealed record ManagementClientDetail(
    string Id,
    string ClientId,
    string? DisplayName,
    string? Type,
    string? ConsentType,
    IReadOnlyList<string> Permissions,
    IReadOnlyList<string> Requirements,
    IReadOnlyList<string> RedirectUris,
    IReadOnlyList<string> PostLogoutRedirectUris,
    string? FrontchannelLogoutUri = null,
    bool FrontchannelLogoutSessionRequired = false,
    string? BackchannelLogoutUri = null,
    bool BackchannelLogoutSessionRequired = false,
    string? Version = null,
    bool IsManifestManaged = false,
    string? JwksUri = null,
    int? AccessTokenLifetimeMinutes = null,
    int? IdentityTokenLifetimeMinutes = null,
    int? RefreshTokenLifetimeDays = null);

public sealed record CreateManagementClientCommand(
    string ClientId,
    string? ClientSecret,
    string? DisplayName,
    string? ConsentType,
    bool RequirePar,
    IReadOnlyList<string> GrantTypes,
    IReadOnlyList<string> Scopes,
    IReadOnlyList<string> RedirectUris,
    IReadOnlyList<string>? PostLogoutRedirectUris = null,
    string? FrontchannelLogoutUri = null,
    bool FrontchannelLogoutSessionRequired = false,
    string? BackchannelLogoutUri = null,
    bool BackchannelLogoutSessionRequired = false,
    string? JwksUri = null,
    int? AccessTokenLifetimeMinutes = null,
    int? IdentityTokenLifetimeMinutes = null,
    int? RefreshTokenLifetimeDays = null);

public sealed record UpdateManagementClientCommand(
    string ClientId,
    string? DisplayName,
    string? ConsentType,
    bool RequirePar,
    IReadOnlyList<string> GrantTypes,
    IReadOnlyList<string> Scopes,
    IReadOnlyList<string> RedirectUris,
    IReadOnlyList<string>? PostLogoutRedirectUris = null,
    string? FrontchannelLogoutUri = null,
    bool FrontchannelLogoutSessionRequired = false,
    string? BackchannelLogoutUri = null,
    bool BackchannelLogoutSessionRequired = false,
    string? ExpectedVersion = null,
    string? JwksUri = null,
    int? AccessTokenLifetimeMinutes = null,
    int? IdentityTokenLifetimeMinutes = null,
    int? RefreshTokenLifetimeDays = null,
    bool ClearAccessTokenLifetime = false,
    bool ClearIdentityTokenLifetime = false,
    bool ClearRefreshTokenLifetime = false);

#else

internal sealed class ClientManagementService(
    IOpenIddictApplicationManager applications,
    IOpenIddictApplicationCache<OpenIddictEntityFrameworkCoreApplication>
        applicationCache,
    AppDbContext database,
    IManagementAuthorizationEvaluator authorization,
    IReservedScopePolicy reservedScopePolicy,
    IClientDefinitionValidator clientDefinitionValidator,
    ILogger<ClientManagementService> logger) : IClientManagementService
{
    private const int MinimumAccessTokenLifetimeMinutes = 1;
    private const int MaximumAccessTokenLifetimeMinutes = 24 * 60;
    private const int MinimumIdentityTokenLifetimeMinutes = 1;
    private const int MaximumIdentityTokenLifetimeMinutes = 120;
    private const int MinimumRefreshTokenLifetimeDays = 1;
    private const int MaximumRefreshTokenLifetimeDays = 365;

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

    public async Task<ManagementClientPage> SearchAsync(
        ManagementClientQuery query,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);
        await DemandAsync(
            context,
            ManagementCapabilities.ClientsRead,
            new ManagementResource(ManagementResourceTypes.ClientCollection),
            cancellationToken);

        var normalized = NormalizeSearchQuery(query);
        var applicationsQuery = database.Set<OpenIddictEntityFrameworkCoreApplication>()
            .AsNoTracking();

        var search = normalized.Search;
        if (!string.IsNullOrWhiteSpace(search))
        {
            applicationsQuery = applicationsQuery.Where(application =>
                (application.ClientId != null &&
                 application.ClientId!.Contains(search)) ||
                (application.DisplayName != null &&
                 application.DisplayName.Contains(search)));
        }

        if (normalized.Type is not "all")
        {
            applicationsQuery = applicationsQuery.Where(application =>
                application.ClientType == normalized.Type);
        }

        if (normalized.Grant is not "all")
        {
            var permission = $"\"gt:{normalized.Grant}\"";
            applicationsQuery = applicationsQuery.Where(application =>
                application.Permissions != null &&
                application.Permissions.Contains(permission));
        }

        if (normalized.Scope is not "all")
        {
            var permission = $"\"scp:{normalized.Scope}\"";
            applicationsQuery = applicationsQuery.Where(application =>
                application.Permissions != null &&
                application.Permissions.Contains(permission));
        }

        if (normalized.Origin is "manifest")
        {
            applicationsQuery = applicationsQuery.Where(application =>
                application.Properties != null &&
                application.Properties.Contains(
                    OpenIddictManifestProvisioner.SchemaVersionProperty));
        }
        else if (normalized.Origin is "manual")
        {
            applicationsQuery = applicationsQuery.Where(application =>
                application.Properties == null ||
                !application.Properties.Contains(
                    OpenIddictManifestProvisioner.SchemaVersionProperty));
        }

        var totalCount = await applicationsQuery.CountAsync(cancellationToken);
        var rows = await applicationsQuery
            .OrderBy(application => application.DisplayName ?? application.ClientId)
            .ThenBy(application => application.ClientId)
            .Skip((normalized.Page - 1) * normalized.PageSize)
            .Take(normalized.PageSize)
            .ToArrayAsync(cancellationToken);

        var items = rows
            .Select(application => new ManagementClientSummary(
                application.Id ?? string.Empty,
                application.ClientId ?? string.Empty,
                application.DisplayName,
                application.ClientType,
                null,
                IsManifestManaged(application.Properties) ? "manifest" : "manual"))
            .ToArray();

        return new ManagementClientPage(
            items,
            totalCount,
            normalized.Page,
            normalized.PageSize);
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
            var redirectUris = ValidateRedirectUris(
                command.RedirectUris,
                "redirectUris");
            var postLogoutRedirectUris = ValidateRedirectUris(
                command.PostLogoutRedirectUris,
                "postLogoutRedirectUris");
            var frontchannelLogoutUri = ValidateLogoutUri(
                command.FrontchannelLogoutUri,
                "frontchannelLogoutUri");
            var backchannelLogoutUri = ValidateLogoutUri(
                command.BackchannelLogoutUri,
                "backchannelLogoutUri");
            var jwksUri = ValidateJwksUri(command.JwksUri);
            ValidateTokenLifetimes(
                command.AccessTokenLifetimeMinutes,
                command.IdentityTokenLifetimeMinutes,
                command.RefreshTokenLifetimeDays);

            if (command.FrontchannelLogoutSessionRequired &&
                frontchannelLogoutUri is null)
            {
                throw new ManagementValidationException(
                    "frontchannel_logout_uri_required",
                    "frontchannelLogoutUri is required when session-specific front-channel logout is requested.",
                    "frontchannelLogoutUri");
            }

            if (command.BackchannelLogoutSessionRequired &&
                backchannelLogoutUri is null)
            {
                throw new ManagementValidationException(
                    "backchannel_logout_uri_required",
                    "backchannelLogoutUri is required when session-specific back-channel logout is requested.",
                    "backchannelLogoutUri");
            }

            if (frontchannelLogoutUri is not null &&
                !redirectUris.Any(redirect => SameOrigin(redirect, frontchannelLogoutUri)))
            {
                throw new ManagementValidationException(
                    "frontchannel_logout_origin_mismatch",
                    "frontchannelLogoutUri must use the same scheme, host and port as a redirect URI.",
                    "frontchannelLogoutUri");
            }
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

            var grantTypes = NormalizeGrantTypes(command.GrantTypes);

            // Finding #8: reject insecure grant types (password, implicit) for
            // new client registrations. They are outside the current OAuth 2.1
            // draft baseline, but remain runtime-compatible for existing clients
            // when the explicit legacy feature flag is enabled. The provisioning
            // path already enforces this policy; the management API must not be
            // a weaker parallel path.
            var insecureGrants = grantTypes.Where(g =>
                g == OpenIddictConstants.Permissions.GrantTypes.Password
                || g == OpenIddictConstants.Permissions.GrantTypes.Implicit);
            if (insecureGrants.Any())
            {
                throw new ManagementValidationException(
                    "insecure_grant_type",
                    "Password and implicit grant types are outside the current " +
                    "OAuth 2.1 draft baseline and cannot be assigned to new " +
                    "clients by policy.",
                    "grantTypes");
            }

            foreach (var grantType in grantTypes)
            {
                descriptor.Permissions.Add(grantType);
            }
            AddDerivedProtocolPermissions(descriptor, grantTypes);

            var normalizedScopes = NormalizeScopes(command.Scopes);
            var definitionValidation = clientDefinitionValidator.Validate(
                new ClientDefinitionRequest(
                    ClientDefinitionSource.Management,
                    clientId,
                    string.IsNullOrEmpty(command.ClientSecret)
                        ? OpenIddictConstants.ClientTypes.Public
                        : OpenIddictConstants.ClientTypes.Confidential,
                    grantTypes,
                    normalizedScopes,
                    redirectUris,
                    RequirePkce: clientDefinitionValidator
                        .RequiresProofKeyForCodeExchange(grantTypes),
                    HasClientSecret: !string.IsNullOrEmpty(command.ClientSecret)));
            if (!definitionValidation.IsValid)
            {
                var issue = definitionValidation.Issues[0];
                throw new ManagementValidationException(
                    issue.Code,
                    issue.Message,
                    issue.Field);
            }

            // H2/M3 fix (eval): reject API-protection scopes (management, SCIM,
            // custom privileged APIs) at the client-create boundary. Without
            // this, an operator with identity.clients.create could mint a
            // client_credentials client carrying identity.management and
            // defeat the transport policy. Reserved scopes are provisioned via
            // bootstrap, not the runtime CRUD path.
            var requestedScopeNames = normalizedScopes
                .Select(s => s.StartsWith(
                    OpenIddictConstants.Permissions.Prefixes.Scope,
                    StringComparison.Ordinal)
                    ? s[OpenIddictConstants.Permissions.Prefixes.Scope.Length..]
                    : s);
            var forbidden = requestedScopeNames.FirstOrDefault(reservedScopePolicy.IsReserved);
            if (forbidden is not null)
            {
                throw new ManagementValidationException(
                    "scope_reserved",
                    $"O scope '{forbidden}' protege uma superfície administrativa e não pode ser atribuído a um cliente pela API de gerenciamento.",
                    "scopes");
            }

            foreach (var scope in normalizedScopes)
            {
                descriptor.Permissions.Add(scope);
            }

            foreach (var redirectUri in redirectUris)
            {
                descriptor.RedirectUris.Add(redirectUri);
            }

            foreach (var postLogoutRedirectUri in postLogoutRedirectUris)
            {
                descriptor.PostLogoutRedirectUris.Add(postLogoutRedirectUri);
            }

            AddLogoutSettings(
                descriptor.Settings,
                frontchannelLogoutUri,
                command.FrontchannelLogoutSessionRequired,
                backchannelLogoutUri,
                command.BackchannelLogoutSessionRequired);
            if (jwksUri is not null)
            {
                descriptor.Settings["jwks_uri"] = jwksUri.AbsoluteUri;
            }
            ApplyTokenLifetimes(
                descriptor,
                command.AccessTokenLifetimeMinutes,
                command.IdentityTokenLifetimeMinutes,
                command.RefreshTokenLifetimeDays);

            if (clientDefinitionValidator.RequiresProofKeyForCodeExchange(
                    grantTypes))
            {
                descriptor.Requirements.Add(
                    OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange);
            }

            if (command.RequirePar)
            {
                descriptor.Permissions.Add(
                    OpenIddictConstants.Permissions.Endpoints.PushedAuthorization);
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
        catch (ManagementConflictException exception)
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

            if (application is not OpenIddictEntityFrameworkCoreApplication entity)
            {
                throw new InvalidOperationException(
                    "The configured OpenIddict application entity is unsupported.");
            }

            var applicationId = entity.Id;
            // OpenIddict's EF bulk-delete query joins each dependent table
            // back to itself through the application navigation. MariaDB
            // rejects that shape with error 1093, so delete by the mapped
            // shadow foreign keys in dependency order and invalidate the
            // same application cache entry the manager would invalidate.
            await database.Set<OpenIddictEntityFrameworkCoreToken>()
                .Where(token =>
                    EF.Property<string?>(token, "ApplicationId") ==
                    applicationId)
                .ExecuteDeleteAsync(cancellationToken);
            await database.Set<OpenIddictEntityFrameworkCoreAuthorization>()
                .Where(authorization =>
                    EF.Property<string?>(authorization, "ApplicationId") ==
                    applicationId)
                .ExecuteDeleteAsync(cancellationToken);
            var deleted = await database
                .Set<OpenIddictEntityFrameworkCoreApplication>()
                .Where(candidate =>
                    candidate.Id == applicationId
                    && candidate.ConcurrencyToken == entity.ConcurrencyToken)
                .ExecuteDeleteAsync(cancellationToken);
            if (deleted != 1)
            {
                throw new DbUpdateConcurrencyException(
                    $"Client '{clientId}' changed before it could be deleted.");
            }

            await applicationCache.RemoveAsync(entity, cancellationToken);
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

    public async Task<ManagementClientDetail> UpdateAsync(
        UpdateManagementClientCommand command,
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
            ManagementCapabilities.ClientsUpdate,
            resource,
            cancellationToken);

        var application = await applications.FindByClientIdAsync(
            clientId,
            cancellationToken);
        if (application is null)
        {
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.ClientsUpdate,
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
            if (application is not OpenIddictEntityFrameworkCoreApplication entity)
            {
                throw new InvalidOperationException(
                    "The configured OpenIddict application entity is unsupported.");
            }

            if (string.IsNullOrWhiteSpace(command.ExpectedVersion))
            {
                throw new ManagementValidationException(
                    "client_version_required",
                    "Recarregue a aplicação antes de salvar para confirmar a versão atual.",
                    "expectedVersion");
            }

            if (!string.Equals(
                    command.ExpectedVersion,
                    entity.ConcurrencyToken,
                    StringComparison.Ordinal))
            {
                throw new ManagementConflictException(
                    "client_changed",
                    "O cliente foi alterado por outra operação. Recarregue os dados antes de salvar.");
            }

            var descriptor = new OpenIddictApplicationDescriptor();
            await applications.PopulateAsync(
                descriptor,
                application,
                cancellationToken);

            if (descriptor.Properties.ContainsKey(
                    OpenIddictManifestProvisioner.SchemaVersionProperty))
            {
                throw new ManagementConflictException(
                    "client_manifest_managed",
                    "Este cliente é gerenciado por manifesto declarativo. Altere o manifesto e aplique o provisionamento.");
            }

            var redirectUris = ValidateRedirectUris(
                command.RedirectUris,
                "redirectUris");
            var postLogoutRedirectUris = ValidateRedirectUris(
                command.PostLogoutRedirectUris,
                "postLogoutRedirectUris");
            var frontchannelLogoutUri = ValidateLogoutUri(
                command.FrontchannelLogoutUri,
                "frontchannelLogoutUri");
            var backchannelLogoutUri = ValidateLogoutUri(
                command.BackchannelLogoutUri,
                "backchannelLogoutUri");
            var jwksUri = ValidateJwksUri(command.JwksUri);
            ValidateTokenLifetimes(
                command.AccessTokenLifetimeMinutes,
                command.IdentityTokenLifetimeMinutes,
                command.RefreshTokenLifetimeDays);

            ValidateLogoutConfiguration(
                redirectUris,
                frontchannelLogoutUri,
                command.FrontchannelLogoutSessionRequired,
                backchannelLogoutUri,
                command.BackchannelLogoutSessionRequired);

            var consentType = NormalizeConsentType(command.ConsentType)
                ?? OpenIddictConstants.ConsentTypes.Explicit;
            var grantTypes = NormalizeGrantTypes(command.GrantTypes);
            if (grantTypes.Any(grant =>
                    grant == OpenIddictConstants.Permissions.GrantTypes.Password ||
                    grant == OpenIddictConstants.Permissions.GrantTypes.Implicit))
            {
                throw new ManagementValidationException(
                    "insecure_grant_type",
                    "Password and implicit grant types are outside the current " +
                    "OAuth 2.1 draft baseline and cannot be assigned to new " +
                    "clients by policy.",
                    "grantTypes");
            }

            var normalizedScopes = NormalizeScopes(command.Scopes);
            var clientType = descriptor.ClientType
                ?? OpenIddictConstants.ClientTypes.Public;
            var definitionValidation = clientDefinitionValidator.Validate(
                new ClientDefinitionRequest(
                    ClientDefinitionSource.Management,
                    clientId,
                    clientType,
                    grantTypes,
                    normalizedScopes,
                    redirectUris,
                    RequirePkce: clientDefinitionValidator
                        .RequiresProofKeyForCodeExchange(grantTypes),
                    HasClientSecret: clientType == OpenIddictConstants.ClientTypes.Confidential));
            if (!definitionValidation.IsValid)
            {
                var issue = definitionValidation.Issues[0];
                throw new ManagementValidationException(
                    issue.Code,
                    issue.Message,
                    issue.Field);
            }

            var forbidden = normalizedScopes
                .Select(scope => scope.StartsWith(
                    OpenIddictConstants.Permissions.Prefixes.Scope,
                    StringComparison.Ordinal)
                    ? scope[OpenIddictConstants.Permissions.Prefixes.Scope.Length..]
                    : scope)
                .FirstOrDefault(reservedScopePolicy.IsReserved);
            if (forbidden is not null)
            {
                throw new ManagementValidationException(
                    "scope_reserved",
                    $"O scope '{forbidden}' protege uma superfície administrativa e não pode ser atribuído a um cliente pela API de gerenciamento.",
                    "scopes");
            }

            descriptor.DisplayName = NullIfWhiteSpace(command.DisplayName);
            descriptor.ConsentType = consentType;
            RemoveManagedPermissions(descriptor);
            descriptor.Requirements.Remove(
                OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange);
            descriptor.Requirements.Remove(
                OpenIddictConstants.Requirements.Features.PushedAuthorizationRequests);
            descriptor.RedirectUris.Clear();
            descriptor.PostLogoutRedirectUris.Clear();
            foreach (var grantType in grantTypes)
            {
                descriptor.Permissions.Add(grantType);
            }
            AddDerivedProtocolPermissions(descriptor, grantTypes);
            foreach (var scope in normalizedScopes)
            {
                descriptor.Permissions.Add(scope);
            }
            foreach (var uri in redirectUris)
            {
                descriptor.RedirectUris.Add(uri);
            }
            foreach (var uri in postLogoutRedirectUris)
            {
                descriptor.PostLogoutRedirectUris.Add(uri);
            }

            descriptor.Settings.Remove("frontchannel_logout_uri");
            descriptor.Settings.Remove("frontchannel_logout_session_required");
            descriptor.Settings.Remove("backchannel_logout_uri");
            descriptor.Settings.Remove("backchannel_logout_session_required");
            AddLogoutSettings(
                descriptor.Settings,
                frontchannelLogoutUri,
                command.FrontchannelLogoutSessionRequired,
                backchannelLogoutUri,
                command.BackchannelLogoutSessionRequired);
            // Null means the caller did not manage this metadata (keeps older
            // API/UI clients source-compatible). An explicit empty value
            // removes it; a non-empty value replaces it after validation.
            if (command.JwksUri is not null)
            {
                descriptor.Settings.Remove("jwks_uri");
                if (jwksUri is not null)
                {
                    descriptor.Settings["jwks_uri"] = jwksUri.AbsoluteUri;
                }
            }
            ApplyTokenLifetimes(
                descriptor,
                command.AccessTokenLifetimeMinutes,
                command.IdentityTokenLifetimeMinutes,
                command.RefreshTokenLifetimeDays,
                command.ClearAccessTokenLifetime,
                command.ClearIdentityTokenLifetime,
                command.ClearRefreshTokenLifetime);

            if (clientDefinitionValidator.RequiresProofKeyForCodeExchange(
                    grantTypes))
            {
                descriptor.Requirements.Add(
                    OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange);
            }
            if (command.RequirePar)
            {
                descriptor.Permissions.Add(
                    OpenIddictConstants.Permissions.Endpoints.PushedAuthorization);
                descriptor.Requirements.Add(
                    OpenIddictConstants.Requirements.Features.PushedAuthorizationRequests);
            }

            await using var transaction = await database.Database
                .BeginTransactionAsync(cancellationToken);
            await applications.UpdateAsync(
                application,
                descriptor,
                cancellationToken);
            var detail = await ToDetailAsync(application, cancellationToken);
            database.ManagementAuditEvents.Add(ManagementAuditEventFactory.Create(
                context,
                ManagementCapabilities.ClientsUpdate,
                resource,
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
                ManagementCapabilities.ClientsUpdate,
                resource,
                decision,
                "rejected",
                exception.ReasonCode,
                cancellationToken);
            throw;
        }
        catch (ManagementConflictException exception)
        {
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.ClientsUpdate,
                resource,
                decision,
                "rejected",
                exception.ReasonCode,
                cancellationToken);
            throw;
        }
        catch (DbUpdateConcurrencyException exception)
        {
            logger.LogWarning(
                exception,
                "OAuth client update lost a concurrency race. ClientId={ClientId} CorrelationId={CorrelationId}",
                clientId,
                context.CorrelationId);
            throw new ManagementConflictException(
                "client_changed",
                "O cliente foi alterado por outra operação. Recarregue os dados antes de salvar.");
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "OAuth client update failed. ClientId={ClientId} CorrelationId={CorrelationId}",
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
        var settings = await applications.GetSettingsAsync(
            application,
            cancellationToken);

        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(
            descriptor,
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
                .ToArray(),
            FrontchannelLogoutUri: GetSetting(
                settings,
                "frontchannel_logout_uri"),
            FrontchannelLogoutSessionRequired: GetBooleanSetting(
                settings,
                "frontchannel_logout_session_required"),
            BackchannelLogoutUri: GetSetting(
                settings,
                "backchannel_logout_uri"),
            BackchannelLogoutSessionRequired: GetBooleanSetting(
                settings,
                "backchannel_logout_session_required"),
            Version: (application as OpenIddictEntityFrameworkCoreApplication)
                ?.ConcurrencyToken,
            IsManifestManaged: descriptor.Properties.ContainsKey(
                OpenIddictManifestProvisioner.SchemaVersionProperty),
            JwksUri: GetSetting(settings, "jwks_uri"),
            AccessTokenLifetimeMinutes: GetLifetimeMinutes(
                settings,
                OpenIddictConstants.Settings.TokenLifetimes.AccessToken),
            IdentityTokenLifetimeMinutes: GetLifetimeMinutes(
                settings,
                OpenIddictConstants.Settings.TokenLifetimes.IdentityToken),
            RefreshTokenLifetimeDays: GetLifetimeDays(
                settings,
                OpenIddictConstants.Settings.TokenLifetimes.RefreshToken));
    }

    private static void ValidateTokenLifetimes(
        int? accessTokenLifetimeMinutes,
        int? identityTokenLifetimeMinutes,
        int? refreshTokenLifetimeDays)
    {
        ValidateLifetime(
            accessTokenLifetimeMinutes,
            MinimumAccessTokenLifetimeMinutes,
            MaximumAccessTokenLifetimeMinutes,
            "accessTokenLifetimeMinutes",
            "access_token_lifetime_invalid",
            "Access token lifetime must be between 1 minute and 24 hours.");
        ValidateLifetime(
            identityTokenLifetimeMinutes,
            MinimumIdentityTokenLifetimeMinutes,
            MaximumIdentityTokenLifetimeMinutes,
            "identityTokenLifetimeMinutes",
            "identity_token_lifetime_invalid",
            "Identity token lifetime must be between 1 and 120 minutes.");
        ValidateLifetime(
            refreshTokenLifetimeDays,
            MinimumRefreshTokenLifetimeDays,
            MaximumRefreshTokenLifetimeDays,
            "refreshTokenLifetimeDays",
            "refresh_token_lifetime_invalid",
            "Refresh token lifetime must be between 1 and 365 days.");
    }

    private static void ValidateLifetime(
        int? value,
        int minimum,
        int maximum,
        string field,
        string reasonCode,
        string message)
    {
        if (value is not null && (value < minimum || value > maximum))
        {
            throw new ManagementValidationException(reasonCode, message, field);
        }
    }

    private static void ApplyTokenLifetimes(
        OpenIddictApplicationDescriptor descriptor,
        int? accessTokenLifetimeMinutes,
        int? identityTokenLifetimeMinutes,
        int? refreshTokenLifetimeDays,
        bool clearAccessTokenLifetime = false,
        bool clearIdentityTokenLifetime = false,
        bool clearRefreshTokenLifetime = false)
    {
        // A clear flag explicitly removes an override. Without it, null means
        // the caller did not manage that field, preserving older clients.
        if (clearAccessTokenLifetime)
        {
            descriptor.SetAccessTokenLifetime(null);
        }
        else if (accessTokenLifetimeMinutes is { } access)
        {
            descriptor.SetAccessTokenLifetime(TimeSpan.FromMinutes(access));
        }
        if (clearIdentityTokenLifetime)
        {
            descriptor.SetIdentityTokenLifetime(null);
        }
        else if (identityTokenLifetimeMinutes is { } identity)
        {
            descriptor.SetIdentityTokenLifetime(TimeSpan.FromMinutes(identity));
        }
        if (clearRefreshTokenLifetime)
        {
            descriptor.SetRefreshTokenLifetime(null);
        }
        else if (refreshTokenLifetimeDays is { } refresh)
        {
            descriptor.SetRefreshTokenLifetime(TimeSpan.FromDays(refresh));
        }
    }

    private static int? GetLifetimeMinutes(
        IReadOnlyDictionary<string, string> settings,
        string key)
    {
        if (!settings.TryGetValue(key, out var value)
            || !TimeSpan.TryParse(value, CultureInfo.InvariantCulture, out var lifetime)
            || lifetime <= TimeSpan.Zero)
        {
            return null;
        }

        var minutes = (int)Math.Round(lifetime.TotalMinutes,
            MidpointRounding.AwayFromZero);
        return minutes > 0 ? minutes : null;
    }

    private static int? GetLifetimeDays(
        IReadOnlyDictionary<string, string> settings,
        string key)
    {
        if (!settings.TryGetValue(key, out var value)
            || !TimeSpan.TryParse(value, CultureInfo.InvariantCulture, out var lifetime)
            || lifetime <= TimeSpan.Zero)
        {
            return null;
        }

        var days = (int)Math.Round(lifetime.TotalDays,
            MidpointRounding.AwayFromZero);
        return days > 0 ? days : null;
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
        IReadOnlyList<string>? values,
        string field)
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
                    $"{field} must contain only absolute URIs: {raw}",
                    field);
            }

            if (redirect.Fragment.Length > 0)
            {
                throw new ManagementValidationException(
                    "redirect_uri_fragment",
                    $"{field} cannot contain a fragment: {redirect}",
                    field);
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
                    $"{field} must use https (http is only allowed for loopback): {redirect}",
                    field);
            }

            result.Add(redirect);
        }

        return result
            .DistinctBy(uri => uri.AbsoluteUri, StringComparer.Ordinal)
            .ToArray();
    }

    private static Uri? ValidateLogoutUri(string? value, string field)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return ValidateRedirectUris([value], field)[0];
    }

    private static Uri? ValidateJwksUri(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        if (!Uri.TryCreate(value.Trim(), UriKind.Absolute, out var uri)
            || !PublicHttpsUriPolicy.IsAllowed(uri))
        {
            throw new ManagementValidationException(
                "jwks_uri_invalid",
                "jwksUri must be a public absolute HTTPS URI without user-info or fragment.",
                "jwksUri");
        }

        return uri;
    }

    private static bool SameOrigin(Uri left, Uri right) =>
        string.Equals(left.Scheme, right.Scheme, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(left.Host, right.Host, StringComparison.OrdinalIgnoreCase) &&
        left.Port == right.Port;

    private static void AddLogoutSettings(
        IDictionary<string, string> settings,
        Uri? frontchannelLogoutUri,
        bool frontchannelSessionRequired,
        Uri? backchannelLogoutUri,
        bool backchannelSessionRequired)
    {
        if (frontchannelLogoutUri is not null)
        {
            settings["frontchannel_logout_uri"] = frontchannelLogoutUri.AbsoluteUri;
            settings["frontchannel_logout_session_required"] =
                frontchannelSessionRequired ? "true" : "false";
        }

        if (backchannelLogoutUri is not null)
        {
            settings["backchannel_logout_uri"] = backchannelLogoutUri.AbsoluteUri;
            settings["backchannel_logout_session_required"] =
                backchannelSessionRequired ? "true" : "false";
        }
    }

    private static void ValidateLogoutConfiguration(
        IReadOnlyList<Uri> redirectUris,
        Uri? frontchannelLogoutUri,
        bool frontchannelSessionRequired,
        Uri? backchannelLogoutUri,
        bool backchannelSessionRequired)
    {
        if (frontchannelSessionRequired && frontchannelLogoutUri is null)
        {
            throw new ManagementValidationException(
                "frontchannel_logout_uri_required",
                "frontchannelLogoutUri is required when session-specific front-channel logout is requested.",
                "frontchannelLogoutUri");
        }
        if (backchannelSessionRequired && backchannelLogoutUri is null)
        {
            throw new ManagementValidationException(
                "backchannel_logout_uri_required",
                "backchannelLogoutUri is required when session-specific back-channel logout is requested.",
                "backchannelLogoutUri");
        }
        if (frontchannelLogoutUri is not null &&
            !redirectUris.Any(redirect => SameOrigin(redirect, frontchannelLogoutUri)))
        {
            throw new ManagementValidationException(
                "frontchannel_logout_origin_mismatch",
                "frontchannelLogoutUri must use the same scheme, host and port as a redirect URI.",
                "frontchannelLogoutUri");
        }
    }

    private static string? GetSetting(
        System.Collections.Immutable.ImmutableDictionary<string, string> settings,
        string key) =>
        settings.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : null;

    private static bool GetBooleanSetting(
        System.Collections.Immutable.ImmutableDictionary<string, string> settings,
        string key) =>
        settings.TryGetValue(key, out var value) &&
        bool.TryParse(value, out var result) &&
        result;

    private static (string? Search, string Type, string Grant, string Scope,
        string Origin, string Status, int Page, int PageSize)
        NormalizeSearchQuery(ManagementClientQuery query)
    {
        if (query.Page < 1 || query.PageSize is < 1 or > 100)
        {
            throw new ManagementValidationException(
                "client_query_paging_invalid",
                "page deve ser positivo e pageSize deve estar entre 1 e 100.",
                "pageSize");
        }

        static string Normalize(string? value) =>
            string.IsNullOrWhiteSpace(value) ? "all" : value.Trim().ToLowerInvariant();

        var type = Normalize(query.Type);
        if (type is not ("all" or "public" or "confidential"))
        {
            throw new ManagementValidationException(
                "client_query_type_invalid",
                "type deve ser all, public ou confidential.",
                "type");
        }

        var grant = Normalize(query.Grant);
        var scope = Normalize(query.Scope);
        var origin = Normalize(query.Origin);
        if (origin is not ("all" or "manual" or "manifest"))
        {
            throw new ManagementValidationException(
                "client_query_origin_invalid",
                "origin deve ser all, manual ou manifest.",
                "origin");
        }

        var status = Normalize(query.Status);
        if (status is not ("all" or "active"))
        {
            throw new ManagementValidationException(
                "client_query_status_invalid",
                "status deve ser all ou active até que o ciclo de ativação seja habilitado.",
                "status");
        }

        return (string.IsNullOrWhiteSpace(query.Search) ? null : query.Search.Trim(),
            type, grant, scope, origin, status, query.Page, query.PageSize);
    }

    private static bool IsManifestManaged(string? properties) =>
        properties?.Contains(
            OpenIddictManifestProvisioner.SchemaVersionProperty,
            StringComparison.Ordinal) is true;

    private static IReadOnlyList<string> NormalizeGrantTypes(
        IReadOnlyList<string>? values) =>
        (values ?? [])
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim())
            .Select(value => value switch
            {
                "authorization_code" =>
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode =>
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                "client_credentials" =>
                    OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                OpenIddictConstants.Permissions.GrantTypes.ClientCredentials =>
                    OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                "refresh_token" =>
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken =>
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                "device_code" =>
                    OpenIddictConstants.Permissions.GrantTypes.DeviceCode,
                OpenIddictConstants.GrantTypes.DeviceCode =>
                    OpenIddictConstants.Permissions.GrantTypes.DeviceCode,
                OpenIddictConstants.Permissions.GrantTypes.DeviceCode =>
                    OpenIddictConstants.Permissions.GrantTypes.DeviceCode,
                OpenIddictConstants.GrantTypes.TokenExchange =>
                    OpenIddictConstants.Permissions.GrantTypes.TokenExchange,
                OpenIddictConstants.Permissions.GrantTypes.TokenExchange =>
                    OpenIddictConstants.Permissions.GrantTypes.TokenExchange,
                "password" =>
                    OpenIddictConstants.Permissions.GrantTypes.Password,
                OpenIddictConstants.Permissions.GrantTypes.Password =>
                    OpenIddictConstants.Permissions.GrantTypes.Password,
                "implicit" =>
                    OpenIddictConstants.Permissions.GrantTypes.Implicit,
                OpenIddictConstants.Permissions.GrantTypes.Implicit =>
                    OpenIddictConstants.Permissions.GrantTypes.Implicit,
                _ => throw new ManagementValidationException(
                    "unsupported_grant_type",
                    $"Grant type '{value}' is not supported by the Management API.",
                    "grantTypes")
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

    private static void AddDerivedProtocolPermissions(
        OpenIddictApplicationDescriptor descriptor,
        IReadOnlyCollection<string> grantTypes)
    {
        if (grantTypes.Contains(
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                StringComparer.Ordinal)
            || grantTypes.Contains(
                OpenIddictConstants.Permissions.GrantTypes.Implicit,
                StringComparer.Ordinal))
        {
            descriptor.Permissions.Add(
                OpenIddictConstants.Permissions.Endpoints.Authorization);
        }

        if (grantTypes.Contains(
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                StringComparer.Ordinal)
            || grantTypes.Contains(
                OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                StringComparer.Ordinal)
            || grantTypes.Contains(
                OpenIddictConstants.Permissions.GrantTypes.Password,
                StringComparer.Ordinal)
            || grantTypes.Contains(
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                StringComparer.Ordinal)
            || grantTypes.Contains(
                OpenIddictConstants.Permissions.GrantTypes.DeviceCode,
                StringComparer.Ordinal))
        {
            descriptor.Permissions.Add(
                OpenIddictConstants.Permissions.Endpoints.Token);
        }

        if (grantTypes.Contains(
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                StringComparer.Ordinal))
        {
            descriptor.Permissions.Add(
                OpenIddictConstants.Permissions.ResponseTypes.Code);
        }

        if (grantTypes.Contains(
                OpenIddictConstants.Permissions.GrantTypes.DeviceCode,
                StringComparer.Ordinal))
        {
            descriptor.Permissions.Add(
                OpenIddictConstants.Permissions.Endpoints.DeviceAuthorization);
        }
    }

    private static void RemoveManagedPermissions(
        OpenIddictApplicationDescriptor descriptor)
    {
        // Keep protocol capabilities that this editor does not model (for
        // example introspection or custom endpoints). Only remove values that
        // are derived from the editable grants/scopes, otherwise a routine
        // display-name/redirect edit could silently weaken or broaden a client.
        var managed = descriptor.Permissions
            .Where(permission =>
                permission.StartsWith(
                    "gt:",
                    StringComparison.Ordinal)
                || permission.StartsWith(
                    OpenIddictConstants.Permissions.Prefixes.Scope,
                    StringComparison.Ordinal)
                || permission == OpenIddictConstants.Permissions.Endpoints.Authorization
                || permission == OpenIddictConstants.Permissions.Endpoints.Token
                || permission == OpenIddictConstants.Permissions.Endpoints.DeviceAuthorization
                || permission == OpenIddictConstants.Permissions.Endpoints.PushedAuthorization
                || permission == OpenIddictConstants.Permissions.ResponseTypes.Code)
            .ToArray();

        foreach (var permission in managed)
        {
            descriptor.Permissions.Remove(permission);
        }
    }

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
#endif
