using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Authorizations;
using Sufficit.Identity.Management.Claims;
using Sufficit.Identity.Management.Sessions;
using Sufficit.Identity.Management.Users;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Plan A1: break-glass against a protected principal leaves the same mark in
/// the audit whether it reaches the user directly or through a claim, a
/// session or an authorization. It used to leave none at all: the evaluator
/// returned a plain allowance and every service's own reason code overwrote
/// the rest.
/// </summary>
public sealed class ProtectedPrincipalBreakGlassAuditTests
{
    private const string BreakGlassOutcome = "allowed:protected_principal_break_glass";

    [Fact]
    public async Task Break_glass_is_audited_alike_through_the_user_a_claim_a_session_and_an_authorization()
    {
        using var baseFactory = new ManagementTestFactory();
        await ((IAsyncLifetime)baseFactory).InitializeAsync();
        using var factory = baseFactory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<IManagementAuthorizationEvaluator>();
                services.AddScoped<IManagementAuthorizationEvaluator, CapabilityManagementAuthorizationEvaluator>();
            }));

        await using var scope = factory.Services.CreateAsyncScope();
        var provider = scope.ServiceProvider;
        var users = provider.GetRequiredService<UserManager<ApplicationUser>>();
        var database = provider.GetRequiredService<AppDbContext>();
        var target = await users.FindByNameAsync(TestDataSeeder.DefaultUsername)
            ?? throw new InvalidOperationException("Seeded user is missing.");
        Assert.True((await users.AddClaimAsync(target, new Claim("identity_principal_tier", "9"))).Succeeded);
        var claimId = await database.Set<IdentityUserClaim<string>>()
            .Where(claim => claim.UserId == target.Id && claim.ClaimType == TestDataSeeder.DirectiveClaimType)
            .Select(claim => claim.Id)
            .SingleAsync();
        var (authorizationId, tokenId) = await SeedGrantAsync(provider, target.Id);

        var operatorSubject = $"operator-{Guid.NewGuid():N}";
        var context = new ManagementRequestContext(
            new ClaimsPrincipal(new ClaimsIdentity(
                [
                    new Claim("sub", operatorSubject),
                    new Claim("identity_principal_tier", "1"),
                    new Claim("identity_break_glass", "identity.management"),
                    new Claim("amr", "pwd"),
                    new Claim("amr", "mfa"),
                ],
                authenticationType: "test")),
            "correlation");

        await provider.GetRequiredService<IUserManagementService>()
            .SetLockoutAsync(target.Id, new SetManagementUserLockoutCommand(true), context);
        await provider.GetRequiredService<IClaimManagementService>().DeleteAsync(claimId, context);
        await provider.GetRequiredService<ISessionManagementService>().RevokeAsync(tokenId, context);
        await provider.GetRequiredService<IAuthorizationManagementService>().RevokeAsync(authorizationId, context);

        var outcomes = await database.ManagementAuditEvents.AsNoTracking()
            .Where(entry => entry.OperatorSubject == operatorSubject && entry.OperationOutcome == "succeeded")
            .Select(entry => new { entry.Capability, entry.AuthorizationOutcome })
            .ToListAsync();

        foreach (var capability in new[]
                 {
                     ManagementCapabilities.UsersDisable,
                     ManagementCapabilities.ClaimsDelete,
                     ManagementCapabilities.SessionsRevoke,
                     ManagementCapabilities.AuthorizationsRevoke,
                 })
        {
            var entry = Assert.Single(outcomes, item => item.Capability == capability);
            Assert.Equal(BreakGlassOutcome, entry.AuthorizationOutcome);
        }
    }

    [Theory]
    [InlineData("allowed", "allowed")]
    [InlineData("protected_principal_break_glass", BreakGlassOutcome)]
    [InlineData("protected_principal_observed", "allowed:protected_principal_observed")]
    public void An_allowance_keeps_its_own_reason_next_to_the_operation_code(string reason, string expected)
    {
        Assert.Equal(expected, Sufficit.Identity.Management.Audit.ManagementAuditEventFactory
            .DescribeAuthorization(ManagementAuthorizationDecision.Allowed(reason)));
        Assert.Equal("denied", Sufficit.Identity.Management.Audit.ManagementAuditEventFactory
            .DescribeAuthorization(ManagementAuthorizationDecision.Denied(reason)));
    }

    private static async Task<(string AuthorizationId, string TokenId)> SeedGrantAsync(
        IServiceProvider services,
        string userId)
    {
        var applications = services.GetRequiredService<IOpenIddictApplicationManager>();
        var authorizations = services.GetRequiredService<IOpenIddictAuthorizationManager>();
        var tokens = services.GetRequiredService<IOpenIddictTokenManager>();
        var application = await applications.FindByClientIdAsync(TestDataSeeder.AuthorizationCodeClientId)
            ?? throw new InvalidOperationException("Seeded application is missing.");
        var applicationId = await applications.GetIdAsync(application)
            ?? throw new InvalidOperationException("Seeded application has no identifier.");
        var authorization = await authorizations.CreateAsync(new OpenIddictAuthorizationDescriptor
        {
            ApplicationId = applicationId,
            CreationDate = DateTimeOffset.UtcNow,
            Status = Statuses.Valid,
            Subject = userId,
            Type = AuthorizationTypes.Permanent,
            Scopes = { Scopes.OpenId },
        });
        var authorizationId = await authorizations.GetIdAsync(authorization)
            ?? throw new InvalidOperationException("Seeded authorization has no identifier.");
        var token = await tokens.CreateAsync(new OpenIddictTokenDescriptor
        {
            ApplicationId = applicationId,
            CreationDate = DateTimeOffset.UtcNow,
            ExpirationDate = DateTimeOffset.UtcNow.AddHours(1),
            Status = Statuses.Valid,
            Subject = userId,
            Type = TokenTypeHints.RefreshToken,
        });
        var tokenId = await tokens.GetIdAsync(token)
            ?? throw new InvalidOperationException("Seeded token has no identifier.");
        return (authorizationId, tokenId);
    }
}
