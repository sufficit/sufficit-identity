using System.Security.Claims;

namespace Sufficit.Identity.Management.Vault;

public interface IPersonalVaultReveal
{
    Task<PersonalVaultRevealResult> RevealAsync(
        ClaimsPrincipal principal, string name, string code, string? grant,
        CancellationToken cancellationToken = default);
}

public enum PersonalVaultRevealStatus
{
    Revealed,
    Challenge,
    InvalidCode,
    AuthenticatorRequired,
    LockedOut,
    Unauthorized,
    Unavailable,
    NotFound
}

public sealed record PersonalVaultRevealResult(
    PersonalVaultRevealStatus Status,
    string? Value = null,
    string? Grant = null,
    TimeSpan Remaining = default);
