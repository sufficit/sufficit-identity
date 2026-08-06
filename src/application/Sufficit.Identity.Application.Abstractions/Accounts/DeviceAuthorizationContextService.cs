namespace Sufficit.Identity.Application.Accounts;

public sealed record DeviceAuthorizationContext(
    bool IsValid,
    string? ClientId,
    string? ClientDisplayName,
    IReadOnlyList<string> RequestedScopes);

/// <summary>
/// Projects the validated, short-lived device authorization transaction into
/// the neutral context consumed by the public confirmation UI.
/// </summary>
public interface IDeviceAuthorizationContextService
{
    Task<DeviceAuthorizationContext> GetCurrentAsync(
        CancellationToken cancellationToken = default);
}
