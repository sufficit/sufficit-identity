namespace Sufficit.Identity.Application.Accounts;

/// <summary>Public requirements for a new password, projected from runtime validation.</summary>
public sealed record AccountPasswordPolicy(
    int RequiredLength,
    bool RequireDigit,
    bool RequireLowercase,
    bool RequireUppercase,
    bool RequireNonAlphanumeric,
    int RequiredUniqueChars,
    bool RejectBreached);

public interface IAccountPasswordPolicyProvider
{
    AccountPasswordPolicy GetPolicy();
}
