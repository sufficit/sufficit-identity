using System.Globalization;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Application.Security;
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
