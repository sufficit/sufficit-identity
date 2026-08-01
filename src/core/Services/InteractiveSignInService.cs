namespace Sufficit.Identity.Core.Services;

/// <summary>
/// Provider-neutral projection of an external authentication option rendered
/// by the public login surface.
/// </summary>
public sealed record InteractiveSignInProvider(
    string Name,
    string DisplayName);

public sealed record PasswordSignInCommand(
    string UserName,
    string Password,
    bool IsPersistent);

public sealed record AuthenticatorSignInCommand(
    string Code,
    bool IsPersistent,
    bool RememberClient);

/// <summary>
/// Stable outcomes understood by presentation adapters. Framework-specific
/// result types remain inside the active identity runtime.
/// </summary>
public enum InteractiveSignInStatus
{
    Failed = 0,
    Succeeded,
    RequiresTwoFactor,
    LockedOut,
    NotAllowed,
}

public sealed record InteractiveSignInResult(InteractiveSignInStatus Status)
{
    public bool Succeeded => Status == InteractiveSignInStatus.Succeeded;
}

/// <summary>
/// Canonical application boundary for interactive password and second-factor
/// sign-in. UI adapters never resolve identity users, stores, authentication
/// schemes or framework sign-in managers directly.
/// </summary>
public interface IInteractiveSignInService
{
    Task<IReadOnlyList<InteractiveSignInProvider>> GetExternalProvidersAsync(
        CancellationToken cancellationToken = default);

    Task<InteractiveSignInResult> PasswordSignInAsync(
        PasswordSignInCommand command,
        CancellationToken cancellationToken = default);

    Task<bool> HasPendingTwoFactorSignInAsync(
        CancellationToken cancellationToken = default);

    Task<InteractiveSignInResult> AuthenticatorSignInAsync(
        AuthenticatorSignInCommand command,
        CancellationToken cancellationToken = default);

    Task<InteractiveSignInResult> RecoveryCodeSignInAsync(
        string code,
        CancellationToken cancellationToken = default);
}
