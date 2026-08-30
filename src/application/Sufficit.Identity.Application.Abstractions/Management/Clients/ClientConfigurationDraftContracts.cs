using System.Security.Cryptography;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Clients;

public static class ManagementClientProfiles
{
    public const string Web = "web";
    public const string Spa = "spa";
    public const string Native = "native";
    public const string Service = "service";
    public const string Device = "device";
    public const string Advanced = "advanced";
}

public static class ManagementClientDraftSteps
{
    public const string Identity = "identity";
    public const string Protocol = "protocol";
    public const string Permissions = "permissions";
    public const string Uris = "uris";
    public const string Credentials = "credentials";
    public const string Review = "review";

    public static IReadOnlyList<string> All { get; } =
        [Identity, Protocol, Permissions, Uris, Credentials, Review];
}

public sealed record ManagementClientProfile(
    string Id,
    string DisplayName,
    string Description,
    string Icon,
    string Outcome,
    bool RequiresRedirectUris,
    bool CreatesCredential,
    bool IsAvailable = true,
    string? UnavailableReason = null);

public sealed record ManagementClientAvailableScope(
    string Name,
    string DisplayName,
    string? Description,
    IReadOnlyList<string> Resources,
    bool IsProtocolScope);

public sealed class ManagementClientDraftValues
{
    public string ClientId { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string ClientType { get; set; } = "public";
    public string ConsentType { get; set; } = "explicit";
    public bool AuthorizationCode { get; set; }
    public bool RefreshToken { get; set; }
    public bool ClientCredentials { get; set; }
    public bool DeviceCode { get; set; }
    public bool RequirePar { get; set; }
    /// <summary>Null inherits the server-wide token lifetime.</summary>
    public int? AccessTokenLifetimeMinutes { get; set; }
    public int? IdentityTokenLifetimeMinutes { get; set; }
    public int? RefreshTokenLifetimeDays { get; set; }
    public List<string> Scopes { get; set; } = [];
    public List<string> RedirectUris { get; set; } = [];
    public List<string> PostLogoutRedirectUris { get; set; } = [];
    public string? FrontchannelLogoutUri { get; set; }
    public bool FrontchannelLogoutSessionRequired { get; set; }
    public string? BackchannelLogoutUri { get; set; }
    public bool BackchannelLogoutSessionRequired { get; set; }
}

public enum ClientValidationSeverity
{
    Warning,
    Error
}

public sealed record ClientValidationIssue(
    string Code,
    string Step,
    string Field,
    ClientValidationSeverity Severity,
    string Message,
    string? Remediation = null);

public sealed record ClientDraftValidation(
    bool IsReady,
    IReadOnlyList<ClientValidationIssue> Issues)
{
    public IReadOnlyList<ClientValidationIssue> Errors =>
        Issues.Where(issue => issue.Severity is ClientValidationSeverity.Error)
            .ToArray();
}

public sealed record ManagementClientDraftSummary(
    Guid Id,
    string Profile,
    string ProfileDisplayName,
    string CurrentStep,
    string? ClientId,
    string? DisplayName,
    bool IsReady,
    DateTimeOffset UpdatedAt,
    DateTimeOffset ExpiresAt);

public sealed record ManagementClientDraftDetail(
    Guid Id,
    string Profile,
    string CurrentStep,
    ManagementClientDraftValues Values,
    ClientDraftValidation Validation,
    string Version,
    DateTimeOffset UpdatedAt,
    DateTimeOffset ExpiresAt);

public sealed record SaveManagementClientDraftCommand(
    Guid Id,
    string Version,
    string CurrentStep,
    ManagementClientDraftValues Values);

public sealed record CompleteManagementClientDraftResult(
    ManagementClientDetail Client,
    string? OneTimeSecret);

public interface IClientConfigurationDraftService
{
    Task<IReadOnlyList<ManagementClientProfile>> GetProfilesAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ManagementClientAvailableScope>> GetAvailableScopesAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ManagementClientDraftSummary>> ListAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementClientDraftDetail> CreateAsync(
        string profile,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementClientDraftDetail> GetAsync(
        Guid id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementClientDraftDetail> SaveAsync(
        SaveManagementClientDraftCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<CompleteManagementClientDraftResult> CompleteAsync(
        Guid id,
        string version,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task AbandonAsync(
        Guid id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}
