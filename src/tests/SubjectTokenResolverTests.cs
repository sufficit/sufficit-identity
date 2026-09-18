using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.STS.Grants;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

/// <summary>
/// A token exchange is performed on behalf of a user or of the client the
/// subject_token was issued to (RFC 8693 2.1). That decision used to live
/// inline in the exchange handler, split across two places; A6 turns it into
/// one contract, so the difference is testable on its own.
/// </summary>
[Collection(StsCollection.Name)]
public sealed class SubjectTokenResolverTests
{
    private readonly SufficitIdentityTestFactory _factory;

    public SubjectTokenResolverTests(SufficitIdentityTestFactory factory) =>
        _factory = factory;

    [Fact]
    public async Task A_subject_token_of_a_user_resolves_to_that_user()
    {
        var username = $"subject-resolver-{Guid.NewGuid():N}";
        using var scope = _factory.Services.CreateScope();
        var users = scope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();
        var user = await TestDataSeeder.CreateUserAsync(
            users,
            username,
            TestDataSeeder.DefaultPassword);

        var resolution = await ResolveAsync(
            scope.ServiceProvider,
            SubjectToken(user.Id),
            authorizedParty: TestDataSeeder.AuthorizationCodeClientId);

        Assert.False(resolution.IsRejected);
        Assert.Equal(user.Id, resolution.User?.Id);
        Assert.Null(resolution.Application);
    }

    [Fact]
    public async Task An_unknown_subject_is_rejected()
    {
        using var scope = _factory.Services.CreateScope();

        var resolution = await ResolveAsync(
            scope.ServiceProvider,
            SubjectToken($"missing-{Guid.NewGuid():N}"),
            authorizedParty: TestDataSeeder.AuthorizationCodeClientId);

        Assert.True(resolution.IsRejected);
        Assert.Contains("user", resolution.Rejection!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task A_client_token_resolves_only_when_the_client_is_its_own_authorized_party()
    {
        using var scope = _factory.Services.CreateScope();
        var options = scope.ServiceProvider.GetRequiredService<TokenExchangeOptions>();
        if (!options.AllowClientSubjectTokens)
        {
            // The default posture refuses a subject token with no user at all;
            // that refusal is what the previous test pins.
            return;
        }

        var clientId = TestDataSeeder.AuthorizationCodeClientId;

        var matching = await ResolveAsync(
            scope.ServiceProvider,
            SubjectToken(clientId),
            authorizedParty: clientId);
        var mismatched = await ResolveAsync(
            scope.ServiceProvider,
            SubjectToken(clientId),
            authorizedParty: "another-client");

        Assert.False(matching.IsRejected);
        Assert.Equal(clientId, matching.ClientId);
        Assert.True(mismatched.IsRejected);
    }

    private static Task<SubjectTokenResolution> ResolveAsync(
        IServiceProvider services,
        ClaimsPrincipal subjectToken,
        string? authorizedParty) =>
        services.GetRequiredService<ISubjectTokenResolver>()
            .ResolveAsync(subjectToken, authorizedParty);

    private static ClaimsPrincipal SubjectToken(string subject)
    {
        var identity = new ClaimsIdentity("subject_token");
        identity.SetClaim(Claims.Subject, subject);
        return new ClaimsPrincipal(identity);
    }
}
