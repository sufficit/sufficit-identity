using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using OpenIddict.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS.Tokens;

/// <summary>
/// Keeps authorization-chain revocation set-based even when MariaDB requires
/// OpenIddict's tracked fallback for pruning (DELETE with LIMIT in a subquery).
/// </summary>
internal sealed class SufficitOpenIddictTokenStore(
    IMemoryCache cache,
    IOpenIddictEntityFrameworkCoreContext context,
    IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> options)
    : OpenIddictEntityFrameworkCoreTokenStore(cache, context, options)
{
    public override async ValueTask<long> RevokeByAuthorizationIdAsync(
        string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var database = await Context.GetDbContextAsync(cancellationToken);
        var key = ConvertIdentifierFromString(identifier);

        // Same predicate/status transition as OpenIddict 7.7's native bulk
        // path. This UPDATE has no paging/subquery LIMIT and is supported by
        // our MariaDB provider. Do not toggle the shared options: concurrent
        // pruning must retain DisableBulkOperations=true.
        // Execute immediately, without materializing payloads or repeatedly
        // scanning a tracked authorization chain in SaveChangesAsync.
        return await database.Set<OpenIddictEntityFrameworkCoreToken>()
            .Where(token => token.Authorization!.Id == key && token.Status != Statuses.Revoked)
            .ExecuteUpdateAsync(update => update.SetProperty(
                token => token.Status, Statuses.Revoked), cancellationToken);
    }

    /// <summary>
    /// Removing a claim revokes everything the account holds. The tracked fallback loads
    /// and saves one token per transaction: a system user with 19 000 tokens outlasted the
    /// caller, and the loop then kept failing on every remaining token.
    /// </summary>
    public override async ValueTask<long> RevokeBySubjectAsync(
        string subject, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(subject);

        var database = await Context.GetDbContextAsync(cancellationToken);

        return await database.Set<OpenIddictEntityFrameworkCoreToken>()
            .Where(token => token.Subject == subject && token.Status != Statuses.Revoked)
            .ExecuteUpdateAsync(update => update.SetProperty(
                token => token.Status, Statuses.Revoked), cancellationToken);
    }
}
