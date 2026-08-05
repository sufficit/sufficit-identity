using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

public sealed class SessionsAndAuthorizationsControllerTests
{
    [Fact]
    public async Task Sessions_list_exposes_metadata_without_token_material_and_revokes_one()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var seeded = await SeedGrantAsync(factory.Services);
        using var client = factory.CreateClient();

        using var listed = await client.GetAsync(
            $"/api/sessions?userId={Uri.EscapeDataString(seeded.UserId)}");
        var body = await listed.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(HttpStatusCode.OK, listed.StatusCode);
        Assert.Equal(1, body.GetProperty("totalCount").GetInt32());
        var session = Assert.Single(
            body.GetProperty("items").EnumerateArray());
        Assert.Equal(seeded.TokenId, session.GetProperty("id").GetString());
        Assert.Equal(
            TestDataSeeder.AuthorizationCodeClientId,
            session.GetProperty("clientId").GetString());
        Assert.Equal(
            TokenTypeHints.RefreshToken,
            session.GetProperty("type").GetString());
        Assert.False(session.TryGetProperty("payload", out _));
        Assert.False(session.TryGetProperty("referenceId", out _));

        using var revoked = await client.DeleteAsync(
            $"/api/sessions/{Uri.EscapeDataString(seeded.TokenId)}");
        Assert.Equal(HttpStatusCode.NoContent, revoked.StatusCode);

        await using var scope = factory.Services.CreateAsyncScope();
        var tokens = scope.ServiceProvider
            .GetRequiredService<IOpenIddictTokenManager>();
        var token = await tokens.FindByIdAsync(seeded.TokenId)
            ?? throw new InvalidOperationException("Seeded token is missing.");
        Assert.Equal(
            Statuses.Revoked,
            await tokens.GetStatusAsync(token));
    }

    [Fact]
    public async Task Authorization_list_exposes_scopes_and_revokes_related_credentials()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var seeded = await SeedGrantAsync(factory.Services);
        using var client = factory.CreateClient();

        using var listed = await client.GetAsync(
            $"/api/authorizations?userId={Uri.EscapeDataString(seeded.UserId)}");
        var body = await listed.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(HttpStatusCode.OK, listed.StatusCode);
        Assert.Equal(1, body.GetProperty("totalCount").GetInt32());
        var grant = Assert.Single(
            body.GetProperty("items").EnumerateArray());
        Assert.Equal(
            seeded.AuthorizationId,
            grant.GetProperty("id").GetString());
        Assert.Contains(
            grant.GetProperty("scopes").EnumerateArray(),
            scope => scope.GetString() == TestDataSeeder.ScopeName);
        Assert.Equal(1, grant.GetProperty("credentialCount").GetInt32());
        Assert.False(grant.TryGetProperty("properties", out _));

        using var revoked = await client.DeleteAsync(
            $"/api/authorizations/{Uri.EscapeDataString(seeded.AuthorizationId)}");
        Assert.Equal(HttpStatusCode.NoContent, revoked.StatusCode);

        await using var verificationScope =
            factory.Services.CreateAsyncScope();
        var authorizations = verificationScope.ServiceProvider
            .GetRequiredService<IOpenIddictAuthorizationManager>();
        var tokens = verificationScope.ServiceProvider
            .GetRequiredService<IOpenIddictTokenManager>();
        var authorization = await authorizations.FindByIdAsync(
                seeded.AuthorizationId)
            ?? throw new InvalidOperationException(
                "Seeded authorization is missing.");
        var token = await tokens.FindByIdAsync(seeded.TokenId)
            ?? throw new InvalidOperationException("Seeded token is missing.");

        Assert.Equal(
            Statuses.Revoked,
            await authorizations.GetStatusAsync(authorization));
        Assert.Equal(
            Statuses.Revoked,
            await tokens.GetStatusAsync(token));
    }

    private static async Task<SeededGrant> SeedGrantAsync(
        IServiceProvider services)
    {
        await using var scope = services.CreateAsyncScope();
        var users = scope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();
        var applications = scope.ServiceProvider
            .GetRequiredService<IOpenIddictApplicationManager>();
        var authorizations = scope.ServiceProvider
            .GetRequiredService<IOpenIddictAuthorizationManager>();
        var tokens = scope.ServiceProvider
            .GetRequiredService<IOpenIddictTokenManager>();
        var user = await users.FindByNameAsync(TestDataSeeder.DefaultUsername)
            ?? throw new InvalidOperationException("Seeded user is missing.");
        var application = await applications.FindByClientIdAsync(
                TestDataSeeder.AuthorizationCodeClientId)
            ?? throw new InvalidOperationException(
                "Seeded application is missing.");
        var applicationId = await applications.GetIdAsync(application)
            ?? throw new InvalidOperationException(
                "Seeded application has no identifier.");

        var authorization = await authorizations.CreateAsync(
            new OpenIddictAuthorizationDescriptor
            {
                ApplicationId = applicationId,
                CreationDate = DateTimeOffset.UtcNow,
                Status = Statuses.Valid,
                Subject = user.Id,
                Type = AuthorizationTypes.Permanent,
                Scopes = { Scopes.OpenId, TestDataSeeder.ScopeName }
            });
        var authorizationId = await authorizations.GetIdAsync(authorization)
            ?? throw new InvalidOperationException(
                "Seeded authorization has no identifier.");
        var token = await tokens.CreateAsync(
            new OpenIddictTokenDescriptor
            {
                ApplicationId = applicationId,
                AuthorizationId = authorizationId,
                CreationDate = DateTimeOffset.UtcNow,
                ExpirationDate = DateTimeOffset.UtcNow.AddHours(1),
                Status = Statuses.Valid,
                Subject = user.Id,
                Type = TokenTypeHints.RefreshToken
            });
        var tokenId = await tokens.GetIdAsync(token)
            ?? throw new InvalidOperationException(
                "Seeded token has no identifier.");

        return new SeededGrant(user.Id, authorizationId, tokenId);
    }

    private sealed record SeededGrant(
        string UserId,
        string AuthorizationId,
        string TokenId);
}
