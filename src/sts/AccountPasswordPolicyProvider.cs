using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Application.Accounts;

namespace Sufficit.Identity.STS;

public sealed class AccountPasswordPolicyProvider(
    IOptions<IdentityOptions> identityOptions,
    SufficitIdentityOptions options) : IAccountPasswordPolicyProvider
{
    public AccountPasswordPolicy GetPolicy()
    {
        var requirements = identityOptions.Value.Password;
        return new(requirements.RequiredLength, requirements.RequireDigit,
            requirements.RequireLowercase, requirements.RequireUppercase,
            requirements.RequireNonAlphanumeric, requirements.RequiredUniqueChars,
            options.Password.RejectBreached);
    }
}
