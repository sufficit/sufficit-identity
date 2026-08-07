using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.STS;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class CredentialMutationSecurityTests
{
    [Fact]
    public async Task Enforce_mode_accepts_recent_authentication_and_rejects_stale_sessions()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:CredentialMutations:StepUpMode"] = "Enforce",
                ["Sufficit:Identity:CredentialMutations:MaximumAuthenticationAgeMinutes"] = "15",
            });
        await using var scope = factory.Services.CreateAsyncScope();
        var coordinator = scope.ServiceProvider
            .GetRequiredService<ICredentialMutationSecurityCoordinator>();

        var recent = await coordinator.AuthorizeAsync(
            PrincipalAuthenticatedAt(DateTimeOffset.UtcNow.AddMinutes(-5)),
            "passkey-registration");
        var stale = await coordinator.AuthorizeAsync(
            PrincipalAuthenticatedAt(DateTimeOffset.UtcNow.AddHours(-1)),
            "passkey-registration");

        Assert.True(recent.Allowed);
        Assert.False(stale.Allowed);
        Assert.Equal("step-up-required", stale.ErrorCode);
    }

    [Fact]
    public async Task Audit_mode_preserves_legacy_sessions_without_authentication_time()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>());
        await using var scope = factory.Services.CreateAsyncScope();
        var coordinator = scope.ServiceProvider
            .GetRequiredService<ICredentialMutationSecurityCoordinator>();
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, "legacy-user")],
            IdentityConstants.ApplicationScheme));

        var authorization = await coordinator.AuthorizeAsync(
            principal,
            "external-identity-removal");

        Assert.True(authorization.Allowed);
    }

    private static ClaimsPrincipal PrincipalAuthenticatedAt(
        DateTimeOffset authenticatedAt) =>
        new(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, "step-up-user"),
                new Claim("auth_time", authenticatedAt.ToUnixTimeSeconds().ToString()),
            ],
            IdentityConstants.ApplicationScheme));
}
