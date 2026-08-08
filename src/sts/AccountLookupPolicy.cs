using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.STS;

/// <summary>
/// Resolves email identities without ever selecting an arbitrary row when
/// legacy data contains duplicate normalized addresses.
/// </summary>
public interface IAccountLookupPolicy
{
    Task<ApplicationUser?> FindUniqueByEmailAsync(
        string email,
        CancellationToken cancellationToken = default);
}

public sealed class AccountLookupPolicy(
    UserManager<ApplicationUser> userManager,
    ILogger<AccountLookupPolicy> logger) : IAccountLookupPolicy
{
    public async Task<ApplicationUser?> FindUniqueByEmailAsync(
        string email,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return null;
        }

        var normalized = userManager.NormalizeEmail(email.Trim());
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return null;
        }

        var matches = await userManager.Users
            .Where(user => user.NormalizedEmail == normalized)
            .OrderBy(user => user.Id)
            .Take(2)
            .ToListAsync(cancellationToken);

        if (matches.Count > 1)
        {
            // Deliberately do not include the address or user IDs in the log:
            // the operator can correlate the redacted duplicate report by its
            // aggregate count without turning recovery into an oracle.
            logger.LogWarning(
                "Ambiguous normalized email lookup was rejected because multiple accounts matched.");
            return null;
        }

        return matches.SingleOrDefault();
    }
}
