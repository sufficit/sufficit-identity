using System.Security.Claims;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Tests;

internal sealed class TestAllowProtectedPrincipalAccessPolicy
    : IProtectedPrincipalAccessPolicy
{
    public ValueTask<ManagementAuthorizationDecision> EvaluateAsync(
        ClaimsPrincipal principal,
        string capability,
        string targetUserId,
        CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(ManagementAuthorizationDecision.Allowed());
}
