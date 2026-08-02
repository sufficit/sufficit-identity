using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

[Collection(StsCollection.Name)]
public sealed class AccountAccessServiceTests(
    SufficitIdentityTestFactory factory)
{
    [Fact]
    public async Task Applications_are_grouped_and_sessions_project_only_active_credentials()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var users = services.GetRequiredService<UserManager<ApplicationUser>>();
        var service = services.GetRequiredService<IAccountAccessService>();
        var user = await CreateUserAsync(users);
        var first = await CreateGrantAsync(
            services,
            user,
            [Scopes.OpenId, Scopes.Profile],
            TokenTypeHints.AccessToken);
        var second = await CreateGrantAsync(
            services,
            user,
            [Scopes.OpenId, Scopes.Email],
            TokenTypeHints.RefreshToken);
        await CreateTokenAsync(
            services,
            user,
            first.ApplicationId,
            first.AuthorizationId,
            TokenTypeHints.AccessToken,
            DateTimeOffset.UtcNow.AddHours(-2),
            DateTimeOffset.UtcNow.AddHours(-1));

        var applications = await service.GetConnectedApplicationsAsync(
            PrincipalFor(user));
        var sessions = await service.GetSessionsAsync(PrincipalFor(user));

        var application = Assert.Single(applications);
        Assert.Equal(first.ApplicationId, application.ApplicationId);
        Assert.Equal(
            TestDataSeeder.AuthorizationCodeClientId,
            application.ClientId);
        Assert.Equal(2, application.AuthorizationCount);
        Assert.Equal(2, application.ActiveCredentialCount);
        Assert.Contains(Scopes.OpenId, application.Scopes);
        Assert.Contains(Scopes.Profile, application.Scopes);
        Assert.Contains(Scopes.Email, application.Scopes);

        Assert.Equal(2, sessions.Count);
        Assert.Contains(sessions, session => session.Id == first.TokenId);
        Assert.Contains(sessions, session => session.Id == second.TokenId);
        Assert.All(sessions, session =>
        {
            Assert.Equal(
                TestDataSeeder.AuthorizationCodeClientId,
                session.ClientId);
            Assert.NotNull(session.CreatedAt);
        });
    }

    [Fact]
    public async Task Revocation_fails_closed_for_another_account()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var users = services.GetRequiredService<UserManager<ApplicationUser>>();
        var service = services.GetRequiredService<IAccountAccessService>();
        var owner = await CreateUserAsync(users);
        var other = await CreateUserAsync(users);
        var ownerGrant = await CreateGrantAsync(
            services,
            owner,
            [Scopes.OpenId],
            TokenTypeHints.RefreshToken);
        var otherGrant = await CreateGrantAsync(
            services,
            other,
            [Scopes.OpenId],
            TokenTypeHints.RefreshToken);

        var foreignSession = await service.RevokeSessionAsync(
            PrincipalFor(owner),
            otherGrant.TokenId);
        var ownerApplication = await service.RevokeConnectedApplicationAsync(
            PrincipalFor(owner),
            ownerGrant.ApplicationId);

        Assert.False(foreignSession.Succeeded);
        Assert.Contains(
            foreignSession.Errors,
            error => error.Code == "session-not-found");
        Assert.True(ownerApplication.Succeeded);

        await using var verificationScope = factory.Services.CreateAsyncScope();
        var authorizations = verificationScope.ServiceProvider
            .GetRequiredService<IOpenIddictAuthorizationManager>();
        var tokens = verificationScope.ServiceProvider
            .GetRequiredService<IOpenIddictTokenManager>();
        Assert.Equal(
            Statuses.Revoked,
            await AuthorizationStatusAsync(
                authorizations,
                ownerGrant.AuthorizationId));
        Assert.Equal(
            Statuses.Revoked,
            await TokenStatusAsync(tokens, ownerGrant.TokenId));
        Assert.Equal(
            Statuses.Valid,
            await AuthorizationStatusAsync(
                authorizations,
                otherGrant.AuthorizationId));
        Assert.Equal(
            Statuses.Valid,
            await TokenStatusAsync(tokens, otherGrant.TokenId));
    }

    [Fact]
    public async Task Single_and_global_revocation_have_distinct_security_effects()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var users = services.GetRequiredService<UserManager<ApplicationUser>>();
        var authorizations = services
            .GetRequiredService<IOpenIddictAuthorizationManager>();
        var tokens = services.GetRequiredService<IOpenIddictTokenManager>();
        var service = services.GetRequiredService<IAccountAccessService>();
        var user = await CreateUserAsync(users);
        var grant = await CreateGrantAsync(
            services,
            user,
            [Scopes.OpenId],
            TokenTypeHints.AccessToken);
        var secondToken = await CreateTokenAsync(
            services,
            user,
            grant.ApplicationId,
            grant.AuthorizationId,
            TokenTypeHints.RefreshToken,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddHours(1));
        var originalStamp = await users.GetSecurityStampAsync(user);

        var single = await service.RevokeSessionAsync(
            PrincipalFor(user),
            grant.TokenId);

        Assert.True(single.Succeeded);
        Assert.Equal(
            Statuses.Revoked,
            await TokenStatusAsync(tokens, grant.TokenId));
        Assert.Equal(
            Statuses.Valid,
            await TokenStatusAsync(tokens, secondToken));
        Assert.Equal(
            Statuses.Valid,
            await AuthorizationStatusAsync(
                authorizations,
                grant.AuthorizationId));
        Assert.Equal(originalStamp, await users.GetSecurityStampAsync(user));

        var all = await service.RevokeAllSessionsAsync(PrincipalFor(user));

        Assert.True(all.Succeeded);
        Assert.NotEqual(originalStamp, await users.GetSecurityStampAsync(user));

        await using var verificationScope = factory.Services.CreateAsyncScope();
        var verificationAuthorizations = verificationScope.ServiceProvider
            .GetRequiredService<IOpenIddictAuthorizationManager>();
        var verificationTokens = verificationScope.ServiceProvider
            .GetRequiredService<IOpenIddictTokenManager>();
        Assert.Equal(
            Statuses.Revoked,
            await TokenStatusAsync(verificationTokens, secondToken));
        Assert.Equal(
            Statuses.Revoked,
            await AuthorizationStatusAsync(
                verificationAuthorizations,
                grant.AuthorizationId));
    }

    [Fact]
    public async Task Unauthenticated_principals_fail_closed()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var service = scope.ServiceProvider
            .GetRequiredService<IAccountAccessService>();
        var anonymous = new ClaimsPrincipal(new ClaimsIdentity());

        Assert.Empty(await service.GetConnectedApplicationsAsync(anonymous));
        Assert.Empty(await service.GetSessionsAsync(anonymous));

        var application = await service.RevokeConnectedApplicationAsync(
            anonymous,
            "application");
        var session = await service.RevokeSessionAsync(
            anonymous,
            "session");
        var all = await service.RevokeAllSessionsAsync(anonymous);

        Assert.All(
            new[] { application, session, all },
            result =>
            {
                Assert.False(result.Succeeded);
                Assert.Contains(
                    result.Errors,
                    error => error.Code == "unauthenticated");
            });
    }

    private static async Task<ApplicationUser> CreateUserAsync(
        UserManager<ApplicationUser> users) =>
        await TestDataSeeder.CreateUserAsync(
            users,
            $"account-access-{Guid.NewGuid():N}",
            TestDataSeeder.DefaultPassword);

    private static async Task<SeededGrant> CreateGrantAsync(
        IServiceProvider services,
        ApplicationUser user,
        IReadOnlyList<string> scopes,
        string tokenType)
    {
        var applications = services
            .GetRequiredService<IOpenIddictApplicationManager>();
        var authorizations = services
            .GetRequiredService<IOpenIddictAuthorizationManager>();
        var application = await applications.FindByClientIdAsync(
                TestDataSeeder.AuthorizationCodeClientId)
            ?? throw new InvalidOperationException(
                "Seeded application is missing.");
        var applicationId = await applications.GetIdAsync(application)
            ?? throw new InvalidOperationException(
                "Seeded application has no identifier.");
        var descriptor = new OpenIddictAuthorizationDescriptor
        {
            ApplicationId = applicationId,
            CreationDate = DateTimeOffset.UtcNow,
            Status = Statuses.Valid,
            Subject = user.Id,
            Type = AuthorizationTypes.Permanent,
        };
        descriptor.Scopes.UnionWith(scopes);
        var authorization = await authorizations.CreateAsync(descriptor);
        var authorizationId = await authorizations.GetIdAsync(authorization)
            ?? throw new InvalidOperationException(
                "Seeded authorization has no identifier.");
        var tokenId = await CreateTokenAsync(
            services,
            user,
            applicationId,
            authorizationId,
            tokenType,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddHours(1));
        return new SeededGrant(applicationId, authorizationId, tokenId);
    }

    private static async Task<string> CreateTokenAsync(
        IServiceProvider services,
        ApplicationUser user,
        string applicationId,
        string authorizationId,
        string tokenType,
        DateTimeOffset creationDate,
        DateTimeOffset expirationDate)
    {
        var tokens = services.GetRequiredService<IOpenIddictTokenManager>();
        var token = await tokens.CreateAsync(
            new OpenIddictTokenDescriptor
            {
                ApplicationId = applicationId,
                AuthorizationId = authorizationId,
                CreationDate = creationDate,
                ExpirationDate = expirationDate,
                Status = Statuses.Valid,
                Subject = user.Id,
                Type = tokenType,
            });
        return await tokens.GetIdAsync(token)
            ?? throw new InvalidOperationException(
                "Seeded token has no identifier.");
    }

    private static async Task<string?> AuthorizationStatusAsync(
        IOpenIddictAuthorizationManager manager,
        string id)
    {
        var authorization = await manager.FindByIdAsync(id)
            ?? throw new InvalidOperationException(
                "Seeded authorization is missing.");
        return await manager.GetStatusAsync(authorization);
    }

    private static async Task<string?> TokenStatusAsync(
        IOpenIddictTokenManager manager,
        string id)
    {
        var token = await manager.FindByIdAsync(id)
            ?? throw new InvalidOperationException("Seeded token is missing.");
        return await manager.GetStatusAsync(token);
    }

    private static ClaimsPrincipal PrincipalFor(ApplicationUser user) =>
        new(
            new ClaimsIdentity(
                [
                    new Claim(ClaimTypes.NameIdentifier, user.Id),
                    new Claim(ClaimTypes.Name, user.UserName!),
                ],
                IdentityConstants.ApplicationScheme,
                ClaimTypes.Name,
                ClaimTypes.Role));

    private sealed record SeededGrant(
        string ApplicationId,
        string AuthorizationId,
        string TokenId);
}
