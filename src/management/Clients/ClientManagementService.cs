#if !APPLICATION_CONTRACTS
using System.Data;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Provisioning;
#endif
using System.Globalization;
using Sufficit.Identity.Application.Accounts;
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

    Task<RotateManagementClientSecretResult> RotateSecretAsync(
        RotateManagementClientSecretCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementClientCredentialsOverview> GetCredentialsAsync(
        string clientId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(new ManagementClientCredentialsOverview(
            clientId,
            [],
            [],
            0));

    Task<CreateManagementClientCredentialResult> CreateCredentialAsync(
        CreateManagementClientCredentialCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default) =>
        throw new NotSupportedException(
            "This client management adapter does not support multiple credentials.");

    Task<ManagementClientCredentialsOverview> RevokeCredentialAsync(
        RevokeManagementClientCredentialCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default) =>
        throw new NotSupportedException(
            "This client management adapter does not support credential revocation.");

    Task<ManagementClientCredentialsOverview> RegisterTlsCertificateAsync(
        RegisterManagementClientTlsCertificateCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default) =>
        throw new NotSupportedException(
            "This client management adapter does not support TLS client certificates.");

    Task<ManagementClientCredentialsOverview> RevokeTlsCertificateAsync(
        RevokeManagementClientTlsCertificateCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default) =>
        throw new NotSupportedException(
            "This client management adapter does not support TLS client certificates.");

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
    string? Origin = null,
    /// <summary>Provenance of a self-registered (DCR) client. Carried on the
    /// summary so the registrations console lists them without a detail
    /// round-trip per row.</summary>
    DateTimeOffset? RegisteredAtUtc = null,
    bool RegisteredAnonymously = false,
    string? RegisteredFromAddress = null,
    string? RegisteredUserAgent = null);

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
    int? RefreshTokenLifetimeDays = null,
    int GlobalAccessTokenLifetimeMinutes = 60,
    int GlobalIdentityTokenLifetimeMinutes = 20,
    double GlobalRefreshTokenLifetimeDays = 14,
    /// <summary>"manual", "manifest" or "dcr".</summary>
    string Origin = "manual",
    /// <summary>Provenance of a self-registered (DCR) client: when it appeared,
    /// whether it registered without an initial access token, and where the
    /// call came from. Null for clients an operator created.</summary>
    DateTimeOffset? RegisteredAtUtc = null,
    bool RegisteredAnonymously = false,
    string? RegisteredFromAddress = null,
    string? RegisteredUserAgent = null,
    bool HasClientSecret = false,
    string? JwksJson = null,
    IReadOnlyList<string>? AuthenticationMethods = null,
    int ActiveCredentialCount = 0,
    /// <summary>Native callbacks registered under the <c>native_return_uris</c>
    /// extension metadata (RFC 7591, section 2).</summary>
    IReadOnlyList<string>? NativeReturnUris = null,
    /// <summary>Web destination registered under the
    /// <c>device_close_fallback_url</c> extension metadata — where the
    /// browser tab that approved this client's device flow goes when script
    /// cannot close it.</summary>
    string? DeviceCloseFallbackUrl = null);

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
    int? RefreshTokenLifetimeDays = null,
    string? JwksJson = null,
    IReadOnlyList<string>? NativeReturnUris = null,
    string? DeviceCloseFallbackUrl = null);

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
    bool ClearRefreshTokenLifetime = false,
    string? JwksJson = null,
    IReadOnlyList<string>? NativeReturnUris = null,
    string? DeviceCloseFallbackUrl = null);

public sealed record RotateManagementClientSecretCommand(
    string ClientId,
    string? ExpectedVersion,
    bool Generate,
    string? ClientSecret = null);

public sealed record RotateManagementClientSecretResult(
    ManagementClientDetail Client,
    string OneTimeSecret,
    bool Generated);

public sealed record ManagementClientCredentialSummary(
    Guid? Id,
    string Label,
    string Kind,
    string SecretHint,
    string Status,
    bool IsPrimary,
    DateTimeOffset? CreatedAtUtc = null,
    DateTimeOffset? NotBeforeUtc = null,
    DateTimeOffset? ExpiresAtUtc = null,
    DateTimeOffset? RevokedAtUtc = null,
    string? Version = null);

public sealed record ManagementClientCredentialsOverview(
    string ClientId,
    IReadOnlyList<string> AuthenticationMethods,
    IReadOnlyList<ManagementClientCredentialSummary> Credentials,
    int MaximumActiveAdditionalSharedSecrets,
    string? PublicJwksJson = null,
    IReadOnlyList<ManagementClientTlsCertificateSummary>? TlsCertificates = null,
    bool MtlsRuntimeEnabled = false,
    bool PkiAuthenticationEnabled = false,
    int MaximumTlsCertificates = 10,
    string? ClientVersion = null);

public sealed record ManagementClientTlsCertificateSummary(
    string KeyId,
    string AuthenticationMethod,
    string Subject,
    string Issuer,
    string Sha256Thumbprint,
    DateTimeOffset NotBeforeUtc,
    DateTimeOffset ExpiresAtUtc,
    string Status,
    bool IsCertificateAuthority = false);

public sealed record CreateManagementClientCredentialCommand(
    string ClientId,
    string? ExpectedClientVersion,
    string? Label,
    bool Generate,
    string? ClientSecret = null,
    DateTimeOffset? NotBeforeUtc = null,
    DateTimeOffset? ExpiresAtUtc = null);

public sealed record CreateManagementClientCredentialResult(
    ManagementClientCredentialsOverview Overview,
    string OneTimeSecret,
    bool Generated,
    bool CreatedAsPrimary);

public sealed record RevokeManagementClientCredentialCommand(
    string ClientId,
    Guid CredentialId,
    string? ExpectedCredentialVersion,
    string? Reason = null);

public sealed record RegisterManagementClientTlsCertificateCommand(
    string ClientId,
    string? ExpectedClientVersion,
    string? KeyId,
    string AuthenticationMethod,
    string CertificatePem);

public sealed record RevokeManagementClientTlsCertificateCommand(
    string ClientId,
    string? ExpectedClientVersion,
    string KeyId);

#else

internal sealed class ClientManagementService(
    IOpenIddictApplicationManager applications,
    IOpenIddictApplicationCache<OpenIddictEntityFrameworkCoreApplication>
        applicationCache,
    AppDbContext database,
    IReservedScopePolicy reservedScopePolicy,
    IClientDefinitionValidator clientDefinitionValidator,
    IConfiguration configuration,
    ManagementOperationGuard guard,
    ClientCredentialRegistry credentials,
    ILogger<ClientManagementService> logger) : IClientManagementService
{
    // Credential and mTLS certificate lifecycle lives in its own type; these
    // stay on the interface so controllers and the embedded UI are unaffected
    // by the split.
    public Task<ManagementClientCredentialsOverview> GetCredentialsAsync(
        string clientId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default) =>
        credentials.GetCredentialsAsync(clientId, context, cancellationToken);

    public Task<CreateManagementClientCredentialResult> CreateCredentialAsync(
        CreateManagementClientCredentialCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default) =>
        credentials.CreateCredentialAsync(command, context, cancellationToken);

    public Task<ManagementClientCredentialsOverview> RevokeCredentialAsync(
        RevokeManagementClientCredentialCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default) =>
        credentials.RevokeCredentialAsync(command, context, cancellationToken);

    public Task<ManagementClientCredentialsOverview> RegisterTlsCertificateAsync(
        RegisterManagementClientTlsCertificateCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default) =>
        credentials.RegisterTlsCertificateAsync(command, context, cancellationToken);

    public Task<ManagementClientCredentialsOverview> RevokeTlsCertificateAsync(
        RevokeManagementClientTlsCertificateCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default) =>
        credentials.RevokeTlsCertificateAsync(command, context, cancellationToken);


    public async Task<IReadOnlyList<ManagementClientSummary>> ListAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        await guard.DemandAsync(
            context,
            ManagementCapabilities.ClientsRead,
            new ManagementResource(ManagementResourceTypes.ClientCollection),
            cancellationToken,
            auditDenial: true);

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
        await guard.DemandAsync(
            context,
            ManagementCapabilities.ClientsRead,
            new ManagementResource(ManagementResourceTypes.ClientCollection),
            cancellationToken,
            auditDenial: true);

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
        else if (normalized.Origin is "dcr")
        {
            applicationsQuery = applicationsQuery.Where(application =>
                application.Properties != null &&
                application.Properties.Contains(
                    DynamicClientRegistrationProperties.Origin));
        }
        else if (normalized.Origin is "manual")
        {
            // "Manual" means neither provisioned by a manifest nor
            // self-registered: what an operator created by hand.
            applicationsQuery = applicationsQuery.Where(application =>
                (application.Properties == null
                    || !application.Properties.Contains(
                        OpenIddictManifestProvisioner.SchemaVersionProperty))
                && (application.Properties == null
                    || !application.Properties.Contains(
                        DynamicClientRegistrationProperties.Origin)));
        }

        var totalCount = await applicationsQuery.CountAsync(cancellationToken);
        var rows = await applicationsQuery
            .OrderBy(application => application.DisplayName ?? application.ClientId)
            .ThenBy(application => application.ClientId)
            .Skip((normalized.Page - 1) * normalized.PageSize)
            .Take(normalized.PageSize)
            .ToArrayAsync(cancellationToken);

        var items = rows
            .Select(application =>
            {
                var registration = ReadRegistrationProvenance(
                    application.Properties);
                return new ManagementClientSummary(
                    application.Id ?? string.Empty,
                    application.ClientId ?? string.Empty,
                    application.DisplayName,
                    application.ClientType,
                    null,
                    ResolveOrigin(application.Properties),
                    registration.RegisteredAtUtc,
                    registration.Anonymous,
                    registration.RemoteAddress,
                    registration.UserAgent);
            })
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

        await guard.DemandAsync(
            context,
            ManagementCapabilities.ClientsRead,
            new ManagementResource(ManagementResourceTypes.Client, id),
            cancellationToken,
            auditDenial: true);

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

        await guard.DemandAsync(
            context,
            ManagementCapabilities.ClientsRead,
            new ManagementResource(ManagementResourceTypes.Client, clientId),
            cancellationToken,
            auditDenial: true);

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
        var decision = await guard.DemandAsync(
            context,
            ManagementCapabilities.ClientsCreate,
            resource,
            cancellationToken,
            auditDenial: true);

        try
        {
            ClientCredentialPolicy.ValidateClientId(clientId);
            var redirectUris = ClientUriPolicy.ValidateRedirectUris(
                command.RedirectUris,
                "redirectUris");
            var postLogoutRedirectUris = ClientUriPolicy.ValidateRedirectUris(
                command.PostLogoutRedirectUris,
                "postLogoutRedirectUris");
            var nativeReturnUris = ClientUriPolicy.ValidateNativeReturnUris(
                command.NativeReturnUris,
                "nativeReturnUris");
            var deviceCloseFallbackUrl = ClientUriPolicy.ValidateDeviceCloseFallback(
                command.DeviceCloseFallbackUrl,
                "deviceCloseFallbackUrl");
            var frontchannelLogoutUri = ClientUriPolicy.ValidateLogoutUri(
                command.FrontchannelLogoutUri,
                "frontchannelLogoutUri");
            var backchannelLogoutUri = ClientUriPolicy.ValidateLogoutUri(
                command.BackchannelLogoutUri,
                "backchannelLogoutUri");
            var jwksUri = ClientJwksPolicy.ValidateJwksUri(command.JwksUri);
            var publicJwks = ClientJwksPolicy.ValidatePublicJwks(command.JwksJson);
            ClientTokenLifetimePolicy.ValidateTokenLifetimes(
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
                !redirectUris.Any(redirect => ClientUriPolicy.SameOrigin(redirect, frontchannelLogoutUri)))
            {
                throw new ManagementValidationException(
                    "frontchannel_logout_origin_mismatch",
                    "frontchannelLogoutUri must use the same scheme, host and port as a redirect URI.",
                    "frontchannelLogoutUri");
            }
            var consentType = ClientPermissionPolicy.NormalizeConsentType(command.ConsentType)
                ?? OpenIddictConstants.ConsentTypes.Explicit;

            if (await applications.FindByClientIdAsync(
                    clientId,
                    cancellationToken) is not null)
            {
                await guard.TryWriteAuditAsync(
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
                    && publicJwks is null
                    ? OpenIddictConstants.ClientTypes.Public
                    : OpenIddictConstants.ClientTypes.Confidential,
                JsonWebKeySet = publicJwks,
            };

            var grantTypes = ClientPermissionPolicy.NormalizeGrantTypes(command.GrantTypes);

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
            ClientPermissionPolicy.AddDerivedProtocolPermissions(descriptor, grantTypes);

            var normalizedScopes = ClientPermissionPolicy.NormalizeScopes(command.Scopes);
            var definitionValidation = clientDefinitionValidator.Validate(
                new ClientDefinitionRequest(
                    ClientDefinitionSource.Management,
                    clientId,
                    string.IsNullOrEmpty(command.ClientSecret)
                        && publicJwks is null
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

            SetNativeReturnUris(descriptor.Properties, nativeReturnUris);
            SetDeviceCloseFallback(descriptor.Properties, deviceCloseFallbackUrl);

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
            ClientTokenLifetimePolicy.ApplyTokenLifetimes(
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
            await guard.TryWriteAuditAsync(
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
            await guard.TryWriteAuditAsync(
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
        var decision = await guard.DemandAsync(
            context,
            ManagementCapabilities.ClientsDelete,
            resource,
            cancellationToken,
            auditDenial: true);

        var application = await applications.FindByClientIdAsync(
            clientId,
            cancellationToken);
        if (application is null)
        {
            await guard.TryWriteAuditAsync(
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
            var canonicalClientId = entity.ClientId ?? clientId;
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
            await database.OAuthClientCredentials
                .Where(credential => credential.ClientId == canonicalClientId)
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
        var decision = await guard.DemandAsync(
            context,
            ManagementCapabilities.ClientsUpdate,
            resource,
            cancellationToken,
            auditDenial: true);

        var application = await applications.FindByClientIdAsync(
            clientId,
            cancellationToken);
        if (application is null)
        {
            await guard.TryWriteAuditAsync(
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

            var redirectUris = ClientUriPolicy.ValidateRedirectUris(
                command.RedirectUris,
                "redirectUris");
            var postLogoutRedirectUris = ClientUriPolicy.ValidateRedirectUris(
                command.PostLogoutRedirectUris,
                "postLogoutRedirectUris");
            var nativeReturnUris = ClientUriPolicy.ValidateNativeReturnUris(
                command.NativeReturnUris,
                "nativeReturnUris");
            var deviceCloseFallbackUrl = ClientUriPolicy.ValidateDeviceCloseFallback(
                command.DeviceCloseFallbackUrl,
                "deviceCloseFallbackUrl");
            var frontchannelLogoutUri = ClientUriPolicy.ValidateLogoutUri(
                command.FrontchannelLogoutUri,
                "frontchannelLogoutUri");
            var backchannelLogoutUri = ClientUriPolicy.ValidateLogoutUri(
                command.BackchannelLogoutUri,
                "backchannelLogoutUri");
            var jwksUri = ClientJwksPolicy.ValidateJwksUri(command.JwksUri);
            var publicJwks = command.JwksJson is null
                ? null
                : ClientJwksPolicy.ValidatePublicJwks(command.JwksJson);
            ClientTokenLifetimePolicy.ValidateTokenLifetimes(
                command.AccessTokenLifetimeMinutes,
                command.IdentityTokenLifetimeMinutes,
                command.RefreshTokenLifetimeDays);

            ClientUriPolicy.ValidateLogoutConfiguration(
                redirectUris,
                frontchannelLogoutUri,
                command.FrontchannelLogoutSessionRequired,
                backchannelLogoutUri,
                command.BackchannelLogoutSessionRequired);

            var consentType = ClientPermissionPolicy.NormalizeConsentType(command.ConsentType)
                ?? OpenIddictConstants.ConsentTypes.Explicit;
            var grantTypes = ClientPermissionPolicy.NormalizeGrantTypes(command.GrantTypes);
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

            var normalizedScopes = ClientPermissionPolicy.NormalizeScopes(command.Scopes);
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
            ClientPermissionPolicy.RemoveManagedPermissions(descriptor);
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
            ClientPermissionPolicy.AddDerivedProtocolPermissions(descriptor, grantTypes);
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

            // Null means the caller did not manage this metadata, so an older
            // API/UI client cannot silently unregister a callback it never
            // knew about; an explicit empty list clears it.
            if (command.NativeReturnUris is not null)
            {
                SetNativeReturnUris(descriptor.Properties, nativeReturnUris);
            }

            // Same null/empty contract as the native callbacks above: null
            // leaves the registration untouched; an explicit empty string
            // clears it.
            if (command.DeviceCloseFallbackUrl is not null)
            {
                SetDeviceCloseFallback(descriptor.Properties, deviceCloseFallbackUrl);
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
            // Null means “not managed by this caller”; an explicit empty
            // value removes the embedded public key set.
            if (command.JwksJson is not null)
            {
                descriptor.JsonWebKeySet =
                    ClientTlsCertificateCredential.MergePrivateKeyJwtKeys(
                        publicJwks,
                        entity.JsonWebKeySet);
            }
            ClientTokenLifetimePolicy.ApplyTokenLifetimes(
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
            await guard.TryWriteAuditAsync(
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
            await guard.TryWriteAuditAsync(
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

    public async Task<RotateManagementClientSecretResult> RotateSecretAsync(
        RotateManagementClientSecretCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        var clientId = command.ClientId?.Trim() ?? string.Empty;
        var resource = new ManagementResource(
            ManagementResourceTypes.Client,
            clientId);
        var decision = await guard.DemandAsync(
            context,
            ManagementCapabilities.ClientsUpdate,
            resource,
            cancellationToken,
            auditDenial: true);

        var application = await applications.FindByClientIdAsync(
            clientId,
            cancellationToken);
        if (application is null)
        {
            await guard.TryWriteAuditAsync(
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
                    "Recarregue a aplicação antes de substituir a credencial.",
                    "expectedVersion");
            }

            if (!string.Equals(
                    command.ExpectedVersion,
                    entity.ConcurrencyToken,
                    StringComparison.Ordinal))
            {
                throw new ManagementConflictException(
                    "client_changed",
                    "O cliente foi alterado por outra operação. Recarregue os dados antes de substituir a credencial.");
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
                    "Este cliente é gerenciado por manifesto declarativo. Altere a referência do segredo no manifesto e aplique o provisionamento.");
            }

            var generated = command.Generate;
            var oneTimeSecret = generated
                ? WebEncoders.Base64UrlEncode(
                    RandomNumberGenerator.GetBytes(ClientCredentialPolicy.GeneratedClientSecretBytes))
                : ClientCredentialPolicy.ValidateReplacementClientSecret(command.ClientSecret);

            await using var transaction = await database.Database
                .BeginTransactionAsync(cancellationToken);

            // OpenIddict accepts a shared secret only for confidential clients.
            // Mutating the tracked entity here lets the manager validate and
            // persist the type transition together with the newly hashed secret.
            entity.ClientType = OpenIddictConstants.ClientTypes.Confidential;
            await applications.UpdateAsync(
                application,
                oneTimeSecret,
                cancellationToken);

            var detail = await ToDetailAsync(application, cancellationToken);
            database.ManagementAuditEvents.Add(ManagementAuditEventFactory.Create(
                context,
                ManagementCapabilities.ClientsUpdate,
                resource,
                decision,
                "succeeded",
                "client_secret_rotated"));
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            return new RotateManagementClientSecretResult(
                detail,
                oneTimeSecret,
                generated);
        }
        catch (ManagementValidationException exception)
        {
            await guard.TryWriteAuditAsync(
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
            await guard.TryWriteAuditAsync(
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
                "OAuth client secret rotation lost a concurrency race. ClientId={ClientId} CorrelationId={CorrelationId}",
                clientId,
                context.CorrelationId);
            throw new ManagementConflictException(
                "client_changed",
                "O cliente foi alterado por outra operação. Recarregue os dados antes de substituir a credencial.");
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "OAuth client secret rotation failed. ClientId={ClientId} CorrelationId={CorrelationId}",
                clientId,
                context.CorrelationId);
            throw;
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

        var entity = application as OpenIddictEntityFrameworkCoreApplication;
        var now = DateTime.UtcNow;
        var activeAdditionalCredentials = entity?.ClientId is { } clientId
            ? await database.OAuthClientCredentials
                .AsNoTracking()
                .CountAsync(credential =>
                    credential.ClientId == clientId
                    && credential.Kind == OAuthClientCredentialKinds.SharedSecret
                    && credential.RevokedAtUtc == null
                    && (credential.NotBeforeUtc == null || credential.NotBeforeUtc <= now)
                    && (credential.ExpiresAtUtc == null || credential.ExpiresAtUtc > now),
                    cancellationToken)
            : 0;
        var hasPrimarySecret = !string.IsNullOrWhiteSpace(entity?.ClientSecret);
        var tlsCertificates = ClientTlsCertificateCredential.Read(
            entity?.JsonWebKeySet,
            DateTimeOffset.UtcNow);
        var authenticationMethods = ClientCredentialPolicy.GetAuthenticationMethods(
            hasPrimarySecret || activeAdditionalCredentials > 0,
            entity?.JsonWebKeySet,
            tlsCertificates);

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
            Version: entity?.ConcurrencyToken,
            IsManifestManaged: descriptor.Properties.ContainsKey(
                OpenIddictManifestProvisioner.SchemaVersionProperty),
            JwksUri: GetSetting(settings, "jwks_uri"),
            AccessTokenLifetimeMinutes: ClientTokenLifetimePolicy.GetLifetimeMinutes(
                settings,
                OpenIddictConstants.Settings.TokenLifetimes.AccessToken),
            IdentityTokenLifetimeMinutes: ClientTokenLifetimePolicy.GetLifetimeMinutes(
                settings,
                OpenIddictConstants.Settings.TokenLifetimes.IdentityToken),
            RefreshTokenLifetimeDays: ClientTokenLifetimePolicy.GetLifetimeDays(
                settings,
                OpenIddictConstants.Settings.TokenLifetimes.RefreshToken),
            GlobalAccessTokenLifetimeMinutes: configuration.GetValue<int?>(
                "Sufficit:Identity:Tokens:AccessTokenLifetimeMinutes") ?? 60,
            GlobalIdentityTokenLifetimeMinutes: configuration.GetValue<int?>(
                "Sufficit:Identity:Tokens:IdentityTokenLifetimeMinutes") ?? 20,
            GlobalRefreshTokenLifetimeDays: configuration.GetValue<double?>(
                "Sufficit:Identity:Tokens:RefreshTokenLifetimeDays") ?? 14,
            Origin: descriptor.Properties.ContainsKey(
                    OpenIddictManifestProvisioner.SchemaVersionProperty)
                ? "manifest"
                : descriptor.Properties.ContainsKey(
                    DynamicClientRegistrationProperties.Origin)
                    ? DynamicClientRegistrationProperties.OriginValue
                    : "manual",
            RegisteredAtUtc: GetInstantProperty(
                descriptor.Properties,
                DynamicClientRegistrationProperties.RegisteredAt),
            RegisteredAnonymously: GetBooleanProperty(
                descriptor.Properties,
                DynamicClientRegistrationProperties.Anonymous),
            RegisteredFromAddress: GetStringProperty(
                descriptor.Properties,
                DynamicClientRegistrationProperties.RemoteAddress),
            RegisteredUserAgent: GetStringProperty(
                descriptor.Properties,
                DynamicClientRegistrationProperties.UserAgent),
            HasClientSecret: hasPrimarySecret || activeAdditionalCredentials > 0,
            JwksJson: ClientTlsCertificateCredential
                .ExtractPrivateKeyJwtKeys(entity?.JsonWebKeySet)?.ToString(),
            AuthenticationMethods: authenticationMethods,
            ActiveCredentialCount:
                activeAdditionalCredentials + (hasPrimarySecret ? 1 : 0),
            NativeReturnUris: ReadNativeReturnUris(descriptor.Properties),
            DeviceCloseFallbackUrl: DeviceCloseFallbackPolicy.Read(descriptor.Properties));
    }

    /// <summary>
    /// Writes the <c>native_return_uris</c> extension metadata into the client
    /// property bag, removing the key entirely when nothing is registered so a
    /// client that uses none carries no trace of the feature.
    /// </summary>
    private static void SetNativeReturnUris(
        IDictionary<string, JsonElement> properties,
        IReadOnlyList<string> values)
    {
        properties.Remove(NativeReturnUriPolicy.PropertyKey);
        if (values.Count == 0)
        {
            return;
        }

        properties[NativeReturnUriPolicy.PropertyKey] =
            JsonSerializer.SerializeToElement(values);
    }

    /// <summary>
    /// Writes the <c>device_close_fallback_url</c> extension metadata into the
    /// client property bag, removing the key entirely when nothing is
    /// registered — a client that uses no fallback carries no trace of it.
    /// </summary>
    private static void SetDeviceCloseFallback(
        IDictionary<string, JsonElement> properties,
        string? url)
    {
        properties.Remove(DeviceCloseFallbackPolicy.PropertyKey);
        if (url is null)
        {
            return;
        }

        properties[DeviceCloseFallbackPolicy.PropertyKey] =
            JsonSerializer.SerializeToElement(url);
    }

    private static IReadOnlyList<string> ReadNativeReturnUris(
        IReadOnlyDictionary<string, JsonElement> properties) =>
        properties.TryGetValue(
            NativeReturnUriPolicy.PropertyKey,
            out var value)
        && value.ValueKind == JsonValueKind.Array
            ? value.EnumerateArray()
                .Where(element => element.ValueKind == JsonValueKind.String)
                .Select(element => element.GetString()!)
                .Where(uri => !string.IsNullOrWhiteSpace(uri))
                .ToArray()
            : [];

    private static string? GetStringProperty(
        IReadOnlyDictionary<string, JsonElement> properties,
        string key) =>
        properties.TryGetValue(key, out var value)
        && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static bool GetBooleanProperty(
        IReadOnlyDictionary<string, JsonElement> properties,
        string key) =>
        properties.TryGetValue(key, out var value)
        && value.ValueKind == JsonValueKind.True;

    private static DateTimeOffset? GetInstantProperty(
        IReadOnlyDictionary<string, JsonElement> properties,
        string key) =>
        GetStringProperty(properties, key) is { } raw
        && DateTimeOffset.TryParse(
            raw,
            System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AdjustToUniversal
                | System.Globalization.DateTimeStyles.AssumeUniversal,
            out var parsed)
            ? parsed
            : null;

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
        if (origin is not ("all" or "manual" or "manifest" or "dcr"))
        {
            throw new ManagementValidationException(
                "client_query_origin_invalid",
                "origin deve ser all, manual, manifest ou dcr.",
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

    /// <summary>
    /// Reads the DCR provenance stamps from the raw Properties JSON column.
    /// Returns empty values for clients that were not self-registered.
    /// </summary>
    private static (DateTimeOffset? RegisteredAtUtc, bool Anonymous,
        string? RemoteAddress, string? UserAgent)
        ReadRegistrationProvenance(string? properties)
    {
        if (string.IsNullOrWhiteSpace(properties)) return (null, false, null, null);
        try
        {
            using var document = JsonDocument.Parse(properties);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                return (null, false, null, null);

            var root = document.RootElement;
            return (
                root.TryGetProperty(
                    DynamicClientRegistrationProperties.RegisteredAt,
                    out var registeredAt)
                && registeredAt.ValueKind == JsonValueKind.String
                && DateTimeOffset.TryParse(
                    registeredAt.GetString(),
                    System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.AdjustToUniversal
                        | System.Globalization.DateTimeStyles.AssumeUniversal,
                    out var parsed)
                    ? parsed
                    : null,
                root.TryGetProperty(
                    DynamicClientRegistrationProperties.Anonymous,
                    out var anonymous)
                    && anonymous.ValueKind == JsonValueKind.True,
                root.TryGetProperty(
                    DynamicClientRegistrationProperties.RemoteAddress,
                    out var address)
                && address.ValueKind == JsonValueKind.String
                    ? address.GetString()
                    : null,
                root.TryGetProperty(
                    DynamicClientRegistrationProperties.UserAgent,
                    out var userAgent)
                && userAgent.ValueKind == JsonValueKind.String
                    ? userAgent.GetString()
                    : null);
        }
        catch (JsonException)
        {
            // A malformed Properties blob must not break the console listing.
            return (null, false, null, null);
        }
    }

    private static string ResolveOrigin(string? properties) =>
        IsManifestManaged(properties) ? "manifest"
        : IsSelfRegistered(properties) ? "dcr"
        : "manual";

    private static bool IsSelfRegistered(string? properties) =>
        properties?.Contains(
            DynamicClientRegistrationProperties.Origin,
            StringComparison.Ordinal) is true;

    private static bool IsManifestManaged(string? properties) =>
        properties?.Contains(
            OpenIddictManifestProvisioner.SchemaVersionProperty,
            StringComparison.Ordinal) is true;

    private static string? NullIfWhiteSpace(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
#endif
