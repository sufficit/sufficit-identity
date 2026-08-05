namespace Sufficit.Identity.Application.Accounts;

public sealed record AuthorizationConsentParameter(
    string Name,
    string Value);

public sealed record AuthorizationConsentContext(
    bool IsValid,
    string? ClientId,
    string? ClientDisplayName,
    IReadOnlyList<string> RequestedScopes,
    IReadOnlyList<AuthorizationConsentParameter> PassthroughParameters);

/// <summary>
/// Canonical projection of a pending OAuth/OIDC authorization request for the
/// consent presentation. Protocol request objects and persistence managers stay
/// inside the runtime adapter.
/// </summary>
public interface IAuthorizationConsentService
{
    Task<AuthorizationConsentContext> GetCurrentAsync(
        CancellationToken cancellationToken = default);
}
