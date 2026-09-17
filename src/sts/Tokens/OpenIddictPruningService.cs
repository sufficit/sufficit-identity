using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;

namespace Sufficit.Identity.STS.Tokens;

/// <summary>One idempotent sweep, independent of HTTP hosting and scheduling.</summary>
public sealed class OpenIddictPruningService(IServiceProvider services)
{
    public async Task<(long Tokens, long Authorizations)> PruneAsync(
        int retentionDays, CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(retentionDays);
        var threshold = DateTimeOffset.UtcNow.AddDays(-retentionDays);
        await using var scope = services.CreateAsyncScope();
        var tokens = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
        var authorizations = scope.ServiceProvider.GetRequiredService<IOpenIddictAuthorizationManager>();
        var removedTokens = await tokens.PruneAsync(threshold, cancellationToken);
        // Only after token deletion can orphaned ad-hoc authorizations be removed.
        var removedAuthorizations = await authorizations.PruneAsync(threshold, cancellationToken);
        return (removedTokens, removedAuthorizations);
    }
}
