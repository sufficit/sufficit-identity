using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

[Collection(StsCollection.Name)]
public sealed class PersonalTokensTests
{
    private readonly SufficitIdentityTestFactory _factory;

    public PersonalTokensTests(SufficitIdentityTestFactory factory) =>
        _factory = factory;

    [Fact]
    public async Task Personal_token_enforcement_rejects_scope_not_held_by_caller()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:PersonalTokens:Mode"] = "Enforce",
                ["Sufficit:Identity:PersonalTokens:RequiredScope"] = "",
                ["Sufficit:Identity:PersonalTokens:RequireRecentAuthentication"] = "false",
                ["Sufficit:Identity:PersonalTokens:MaximumLifetimeDays"] = "30",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var accessToken = await GetAccessTokenAsync(client);
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", accessToken);

        using var response = await client.PostAsJsonAsync(
            "/api/account/tokens",
            new
            {
                expiration = DateTimeOffset.UtcNow.AddDays(7),
                scopes = new[] { Scopes.Profile },
            });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("invalid_scope", body.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Personal_token_can_be_explicitly_attenuated_to_requested_scopes()
    {
        var client = _factory.CreateClient();
        var accessToken = await GetAccessTokenAsync(client);
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", accessToken);

        using var createResponse = await client.PostAsJsonAsync(
            "/api/account/tokens",
            new
            {
                description = "profile-only",
                expiration = DateTimeOffset.UtcNow.AddDays(7),
                scopes = new[] { Scopes.Profile },
            });
        Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode);
        using var created = JsonDocument.Parse(
            await createResponse.Content.ReadAsStringAsync());
        var personalToken = created.RootElement.GetProperty("accessToken").GetString();

        using var introspectionResponse = await client.PostAsJsonAsync(
            "/api/account/tokens/introspect",
            new { token = personalToken });
        using var introspection = JsonDocument.Parse(
            await introspectionResponse.Content.ReadAsStringAsync());
        Assert.Equal(
            Scopes.Profile,
            introspection.RootElement.GetProperty("scope").GetString());

        using var rejected = await client.PostAsJsonAsync(
            "/api/account/tokens",
            new
            {
                expiration = DateTimeOffset.UtcNow.AddDays(7),
                scopes = new[] { "unregistered-escalation" },
            });
        Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
    }

    [Fact]
    public async Task Personal_token_lifecycle_is_self_contained_in_the_new_identity()
    {
        var client = _factory.CreateClient();
        var accessToken = await GetAccessTokenAsync(client);
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", accessToken);

        var initialExpiration = DateTimeOffset.UtcNow.AddDays(45);
        using var createResponse = await client.PostAsJsonAsync(
            "/api/account/tokens",
            new
            {
                description = "Integration test",
                expiration = initialExpiration,
            });
        Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode);

        using var created = JsonDocument.Parse(
            await createResponse.Content.ReadAsStringAsync());
        var referenceToken = created.RootElement.GetProperty("accessToken").GetString();
        var tokenId = created.RootElement.GetProperty("token").GetProperty("key").GetString();
        Assert.False(string.IsNullOrWhiteSpace(referenceToken));
        Assert.False(string.IsNullOrWhiteSpace(tokenId));
        Assert.DoesNotContain('.', referenceToken!);
        Assert.Equal("SufficitAPIUserAccess",
            created.RootElement.GetProperty("token").GetProperty("clientId").GetString());

        // Read through a fresh DbContext so this assertion verifies the
        // metadata bag was committed, rather than only being visible on the
        // tracked OpenIddict entity used by the request.
        await using (var scope = _factory.Services.CreateAsyncScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<Sufficit.Identity.Core.Data.AppDbContext>();
            var persisted = await database.Set<OpenIddictEntityFrameworkCoreToken>()
                .AsNoTracking()
                .SingleAsync(token => token.Id == tokenId);
            Assert.NotNull(persisted.Properties);
            Assert.Contains("SufficitAPIUserAccess", persisted.Properties, StringComparison.Ordinal);
            Assert.Contains("Integration test", persisted.Properties, StringComparison.Ordinal);
        }

        using var listResponse = await client.GetAsync("/api/account/tokens");
        Assert.Equal(HttpStatusCode.OK, listResponse.StatusCode);
        using var listed = JsonDocument.Parse(await listResponse.Content.ReadAsStringAsync());
        Assert.Contains(listed.RootElement.EnumerateArray(), item =>
            item.GetProperty("key").GetString() == tokenId
            && item.GetProperty("description").GetString() == "Integration test");

        using var introspectResponse = await client.PostAsJsonAsync(
            "/api/account/tokens/introspect",
            new { token = referenceToken });
        Assert.Equal(HttpStatusCode.OK, introspectResponse.StatusCode);
        using var introspected = JsonDocument.Parse(
            await introspectResponse.Content.ReadAsStringAsync());
        Assert.True(introspected.RootElement.GetProperty("active").GetBoolean());
        Assert.Equal(TestDataSeeder.DefaultUsername,
            introspected.RootElement.GetProperty("username").GetString());
        Assert.Equal("SufficitAPIUserAccess",
            introspected.RootElement.GetProperty("client_id").GetString());

        var updatedExpiration = DateTimeOffset.UtcNow.AddDays(60);
        using var updateResponse = await client.PatchAsJsonAsync(
            $"/api/account/tokens/{Uri.EscapeDataString(tokenId!)}",
            new
            {
                updateDescription = true,
                description = "Updated token",
                updateExpiration = true,
                expiration = updatedExpiration,
            });
        Assert.Equal(HttpStatusCode.OK, updateResponse.StatusCode);
        using var updated = JsonDocument.Parse(
            await updateResponse.Content.ReadAsStringAsync());
        Assert.Equal("Updated token", updated.RootElement.GetProperty("description").GetString());

        using var updatedIntrospectionResponse = await client.PostAsJsonAsync(
            "/api/account/tokens/introspect",
            new { token = tokenId });
        using var updatedIntrospection = JsonDocument.Parse(
            await updatedIntrospectionResponse.Content.ReadAsStringAsync());
        Assert.True(updatedIntrospection.RootElement.GetProperty("active").GetBoolean());
        Assert.InRange(
            updatedIntrospection.RootElement.GetProperty("exp").GetInt64(),
            updatedExpiration.AddSeconds(-2).ToUnixTimeSeconds(),
            updatedExpiration.AddSeconds(2).ToUnixTimeSeconds());

        using var revokeResponse = await client.DeleteAsync(
            $"/api/account/tokens/{Uri.EscapeDataString(tokenId!)}");
        Assert.Equal(HttpStatusCode.NoContent, revokeResponse.StatusCode);

        using var revokedIntrospectionResponse = await client.PostAsJsonAsync(
            "/api/account/tokens/introspect",
            new { token = referenceToken });
        using var revokedIntrospection = JsonDocument.Parse(
            await revokedIntrospectionResponse.Content.ReadAsStringAsync());
        Assert.False(revokedIntrospection.RootElement.GetProperty("active").GetBoolean());
    }

    [Fact]
    public async Task Personal_token_uses_current_persisted_roles_and_claims()
    {
        var username = $"personal-claims-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#4";
        const string role = "financial";
        const string directive = "sufficit:test:financial-directive";

        await using (var scope = _factory.Services.CreateAsyncScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var roles = scope.ServiceProvider.GetRequiredService<RoleManager<ApplicationRole>>();
            var scopeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
            var directiveScope = await scopeManager.FindByNameAsync("directives");
            if (directiveScope is null)
            {
                await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
                {
                    Name = "directives",
                    Resources = { TestDataSeeder.IntrospectionClientId },
                });
            }
            else
            {
                var descriptor = new OpenIddictScopeDescriptor();
                await scopeManager.PopulateAsync(descriptor, directiveScope);
                descriptor.Resources.Add(TestDataSeeder.IntrospectionClientId);
                await scopeManager.UpdateAsync(directiveScope, descriptor);
            }

            var user = await TestDataSeeder.CreateUserAsync(users, username, password, directive);
            await TestDataSeeder.AddToRoleAsync(roles, users, user, role);
        }

        var client = _factory.CreateClient();
        // Deliberately request neither `roles` nor `directives`: the token used
        // to manage personal tokens does not contain those claims. The created
        // personal token must rebuild them from the authoritative user store.
        var managementToken = await GetAccessTokenAsync(client, username, password);
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", managementToken);

        using var createResponse = await client.PostAsJsonAsync(
            "/api/account/tokens",
            new
            {
                description = "Current authorization snapshot",
                expiration = DateTimeOffset.UtcNow.AddDays(30),
            });
        Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode);
        using var created = JsonDocument.Parse(await createResponse.Content.ReadAsStringAsync());
        var personalToken = created.RootElement.GetProperty("accessToken").GetString();
        Assert.False(string.IsNullOrWhiteSpace(personalToken));

        using var selfIntrospectionResponse = await client.PostAsJsonAsync(
            "/api/account/tokens/introspect",
            new { token = personalToken });
        Assert.Equal(HttpStatusCode.OK, selfIntrospectionResponse.StatusCode);
        using var selfIntrospection = JsonDocument.Parse(
            await selfIntrospectionResponse.Content.ReadAsStringAsync());
        Assert.Contains(
            TestDataSeeder.IntrospectionClientId,
            selfIntrospection.RootElement.GetProperty("aud").EnumerateArray()
                .Select(item => item.GetString()));

        client.DefaultRequestHeaders.Authorization = IntrospectionTests.BasicAuthFor(
            TestDataSeeder.IntrospectionClientId,
            TestDataSeeder.IntrospectionClientSecret);
        var (status, introspection) = await client.PostFormAsync(
            "/connect/introspect",
            new Dictionary<string, string> { ["token"] = personalToken! });

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.True(introspection.GetProperty("active").GetBoolean());
        Assert.True(
            introspection.TryGetProperty(Claims.Role, out var roleClaim),
            introspection.ToString());
        Assert.Equal(role, roleClaim.GetString());
        Assert.Equal(
            directive,
            introspection.GetProperty(TestDataSeeder.DirectiveClaimType).GetString());
        var scopes = introspection.GetProperty("scope").GetString() ?? string.Empty;
        Assert.Contains(Scopes.Roles, scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries));
        Assert.Contains("directives", scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries));

        // The same bearer can be forwarded by compatibility proxies to the
        // new self-service endpoint without needing a separate admin secret.
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", personalToken);
        using var listResponse = await client.GetAsync("/api/account/tokens");
        Assert.Equal(HttpStatusCode.OK, listResponse.StatusCode);
    }

    [Fact]
    public async Task List_includes_metadata_only_legacy_tokens_but_does_not_mutate_them()
    {
        var client = _factory.CreateClient();
        var accessToken = await GetAccessTokenAsync(client);

        string tokenId;
        await using (var scope = _factory.Services.CreateAsyncScope())
        {
            var users = scope.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            var user = await users.FindByNameAsync(TestDataSeeder.DefaultUsername)
                ?? throw new InvalidOperationException("The seeded user is missing.");
            var tokens = scope.ServiceProvider
                .GetRequiredService<IOpenIddictTokenManager>();
            var descriptor = new OpenIddictTokenDescriptor
            {
                CreationDate = DateTimeOffset.UtcNow.AddDays(-30),
                ExpirationDate = DateTimeOffset.UtcNow.AddDays(30),
                RedemptionDate = DateTimeOffset.UtcNow,
                ReferenceId = $"legacy-test-{Guid.NewGuid():N}",
                Status = Statuses.Revoked,
                Subject = user.Id,
                Type = "legacy_reference_token",
            };
            descriptor.Properties["urn:sufficit:token:client_id"] =
                JsonSerializer.SerializeToElement("legacy-client");
            descriptor.Properties["urn:sufficit:token:description"] =
                JsonSerializer.SerializeToElement("Imported legacy token");

            var token = await tokens.CreateAsync(descriptor);
            tokenId = await tokens.GetIdAsync(token)
                ?? throw new InvalidOperationException("The legacy token id is missing.");
        }

        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", accessToken);
        using var listResponse = await client.GetAsync("/api/account/tokens");
        Assert.Equal(HttpStatusCode.OK, listResponse.StatusCode);
        using var listed = JsonDocument.Parse(await listResponse.Content.ReadAsStringAsync());
        Assert.Contains(listed.RootElement.EnumerateArray(), item =>
            item.GetProperty("key").GetString() == tokenId
            && item.GetProperty("type").GetString() == "legacy_reference_token"
            && item.GetProperty("status").GetString() == Statuses.Revoked
            && item.GetProperty("clientId").GetString() == "legacy-client"
            && item.GetProperty("description").GetString() == "Imported legacy token");

        using var updateResponse = await client.PatchAsJsonAsync(
            $"/api/account/tokens/{Uri.EscapeDataString(tokenId)}",
            new
            {
                updateDescription = true,
                description = "must not change",
                updateExpiration = false,
                expiration = (DateTimeOffset?)null,
            });
        Assert.Equal(HttpStatusCode.NotFound, updateResponse.StatusCode);

        using var revokeResponse = await client.DeleteAsync(
            $"/api/account/tokens/{Uri.EscapeDataString(tokenId)}");
        Assert.Equal(HttpStatusCode.NotFound, revokeResponse.StatusCode);
    }

    [Fact]
    public async Task Regeneration_links_and_hides_the_legacy_tombstone_without_inventing_description()
    {
        var client = _factory.CreateClient();
        var accessToken = await GetAccessTokenAsync(client);
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", accessToken);

        string legacyTokenId;
        await using (var scope = _factory.Services.CreateAsyncScope())
        {
            var users = scope.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            var user = await users.FindByNameAsync(TestDataSeeder.DefaultUsername)
                ?? throw new InvalidOperationException("The seeded user is missing.");
            var tokens = scope.ServiceProvider
                .GetRequiredService<IOpenIddictTokenManager>();
            var descriptor = new OpenIddictTokenDescriptor
            {
                CreationDate = DateTimeOffset.UtcNow.AddDays(-30),
                ExpirationDate = DateTimeOffset.UtcNow.AddDays(30),
                RedemptionDate = DateTimeOffset.UtcNow,
                ReferenceId = $"legacy-regeneration-{Guid.NewGuid():N}",
                Status = Statuses.Revoked,
                Subject = user.Id,
                Type = "legacy_reference_token",
            };
            descriptor.Properties["urn:sufficit:token:client_id"] =
                JsonSerializer.SerializeToElement("legacy-client");

            var token = await tokens.CreateAsync(descriptor);
            legacyTokenId = await tokens.GetIdAsync(token)
                ?? throw new InvalidOperationException("The legacy token id is missing.");
        }

        using var createResponse = await client.PostAsJsonAsync(
            "/api/account/tokens",
            new
            {
                description = (string?)null,
                expiration = DateTimeOffset.UtcNow.AddDays(30),
                replacesTokenId = legacyTokenId,
            });
        Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode);

        using var created = JsonDocument.Parse(
            await createResponse.Content.ReadAsStringAsync());
        var newTokenId = created.RootElement.GetProperty("token").GetProperty("key").GetString();
        Assert.False(string.IsNullOrWhiteSpace(newTokenId));
        Assert.Equal(JsonValueKind.Null,
            created.RootElement.GetProperty("token").GetProperty("description").ValueKind);

        using var listResponse = await client.GetAsync("/api/account/tokens");
        Assert.Equal(HttpStatusCode.OK, listResponse.StatusCode);
        using var listed = JsonDocument.Parse(await listResponse.Content.ReadAsStringAsync());
        Assert.DoesNotContain(listed.RootElement.EnumerateArray(), item =>
            item.GetProperty("key").GetString() == legacyTokenId);
        Assert.Contains(listed.RootElement.EnumerateArray(), item =>
            item.GetProperty("key").GetString() == newTokenId
            && item.GetProperty("description").ValueKind == JsonValueKind.Null);

        await using var verificationScope = _factory.Services.CreateAsyncScope();
        var database = verificationScope.ServiceProvider
            .GetRequiredService<Sufficit.Identity.Core.Data.AppDbContext>();
        var persisted = await database.Set<OpenIddictEntityFrameworkCoreToken>()
            .AsNoTracking()
            .SingleAsync(token => token.Id == newTokenId);
        Assert.NotNull(persisted.Properties);
        using var properties = JsonDocument.Parse(persisted.Properties!);
        Assert.Equal(
            legacyTokenId,
            properties.RootElement
                .GetProperty("urn:sufficit:token:replaces_id")
                .GetString());
        Assert.False(properties.RootElement.TryGetProperty(
            "urn:sufficit:token:description",
            out _));
    }

    private static Task<string> GetAccessTokenAsync(HttpClient client) =>
        GetAccessTokenAsync(client, TestDataSeeder.DefaultUsername, TestDataSeeder.DefaultPassword);

    private static async Task<string> GetAccessTokenAsync(
        HttpClient client,
        string username,
        string password)
    {
        var (status, body) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = username,
            ["password"] = password,
            ["client_id"] = TestDataSeeder.PasswordClientId,
            ["client_secret"] = TestDataSeeder.PasswordClientSecret,
            ["scope"] = TestDataSeeder.ScopeName,
        });
        Assert.Equal(HttpStatusCode.OK, status);
        return body.GetProperty("access_token").GetString()
            ?? throw new InvalidOperationException("The test access token is missing.");
    }
}
