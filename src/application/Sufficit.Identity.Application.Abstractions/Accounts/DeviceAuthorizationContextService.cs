namespace Sufficit.Identity.Application.Accounts;

/// <summary>
/// Human-readable projection of an OAuth scope. The protocol identifier stays
/// available for auditing while presentation metadata comes from the scope
/// registry owned by the deployment.
/// </summary>
public sealed record AuthorizationScopePresentation(
    string Name,
    string? DisplayName,
    string? Description,
    IReadOnlyList<string> Resources);

public sealed record DeviceAuthorizationContext(
    bool IsValid,
    string? ClientId,
    string? ClientDisplayName,
    IReadOnlyList<string> RequestedScopes,
    TimeSpan? AccessTokenLifetime,
    bool AllowsRefreshAccess,
    IReadOnlyList<AuthorizationScopePresentation>? ScopePresentations = null,
    IReadOnlyList<string>? RequestedResources = null);

/// <summary>
/// Projects the validated, short-lived device authorization transaction into
/// the neutral context consumed by the public confirmation UI.
/// </summary>
public interface IDeviceAuthorizationContextService
{
    Task<DeviceAuthorizationContext> GetCurrentAsync(
        CancellationToken cancellationToken = default);
}
