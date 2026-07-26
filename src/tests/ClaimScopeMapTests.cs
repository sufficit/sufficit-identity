using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Covers the config-driven claim-type → required-scope allowlist (eval #10 /
/// plan item 2.5 [M5]). The retrocompatible empty-map case is already pinned
/// by <see cref="IntrospectionTests"/> (directive present for a caller
/// requesting only a plain custom scope); this class covers the GATING cases
/// that only apply once an operator adds an entry to the map.
/// </summary>
/// <remarks>
/// Each test builds its own isolated <see cref="SufficitIdentityTestFactory"/>
/// (outside the shared <see cref="StsCollection"/>) because the map is an
/// overlay the shared fixture intentionally leaves empty.
/// </remarks>
public sealed class ClaimScopeMapTests
{
    private const string DirectiveScopeName = "directives";
    private const string MappedClientId = "test-directive-client";
    private const string MappedClientSecret = "test-directive-client-secret";

    [Fact]
    public async Task Mapped_claim_is_absent_when_the_token_lacks_the_required_scope()
    {
        // Map: { "directive": "directives" }. The token requests only
        // test.scope (NOT directives) → GetDestinations drops `directive`
        // from the access token, so introspection does not surface it.
        using var factory = SufficitIdentityTestFactory.CreateIsolated(MapConfiguration());
        await ((IAsyncLifetime)factory).InitializeAsync();
        await ProvisionDirectiveScopeAndClientAsync(factory);

        var username = $"csm-noscope-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#A";
        const string directiveValue = "sufficit:test:csm-noscope";

        using (var scope = factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(userManager, username, password, directiveValue);
        }

        var client = factory.CreateClient();
        var (tokenStatus, tokenBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = username,
            ["password"] = password,
            ["client_id"] = MappedClientId,
            ["client_secret"] = MappedClientSecret,
            // Only test.scope — NOT directives.
            ["scope"] = TestDataSeeder.ScopeName,
        });
        Assert.Equal(HttpStatusCode.OK, tokenStatus);
        var accessToken = tokenBody.GetProperty("access_token").GetString();
        Assert.False(string.IsNullOrEmpty(accessToken));

        client.DefaultRequestHeaders.Authorization = IntrospectionTests.BasicAuthFor(
            TestDataSeeder.IntrospectionClientId, TestDataSeeder.IntrospectionClientSecret);
        var (_, introspectBody) = await client.PostFormAsync("/connect/introspect", new Dictionary<string, string>
        {
            ["token"] = accessToken!,
        });

        Assert.True(introspectBody.GetProperty("active").GetBoolean());
        // Critical assertion: the mapped claim was DROPPED because the token's
        // scope set does not include the mapped scope.
        Assert.False(
            introspectBody.TryGetProperty(TestDataSeeder.DirectiveClaimType, out _),
            "directive claim leaked into a token whose scope set lacks the mapped 'directives' scope.");
    }

    [Fact]
    public async Task Mapped_claim_is_present_when_the_token_carries_the_required_scope()
    {
        // Same map, but the token DOES request directives → GetDestinations
        // routes `directive` to the access token, so introspection surfaces it.
        using var factory = SufficitIdentityTestFactory.CreateIsolated(MapConfiguration());
        await ((IAsyncLifetime)factory).InitializeAsync();
        await ProvisionDirectiveScopeAndClientAsync(factory);

        var username = $"csm-scope-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#B";
        const string directiveValue = "sufficit:test:csm-scope";

        using (var scope = factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(userManager, username, password, directiveValue);
        }

        var client = factory.CreateClient();
        var (tokenStatus, tokenBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = username,
            ["password"] = password,
            ["client_id"] = MappedClientId,
            ["client_secret"] = MappedClientSecret,
            // This time the token DOES carry the mapped scope.
            ["scope"] = $"{TestDataSeeder.ScopeName} {DirectiveScopeName}",
        });
        Assert.Equal(HttpStatusCode.OK, tokenStatus);
        var accessToken = tokenBody.GetProperty("access_token").GetString();
        Assert.False(string.IsNullOrEmpty(accessToken));

        client.DefaultRequestHeaders.Authorization = IntrospectionTests.BasicAuthFor(
            TestDataSeeder.IntrospectionClientId, TestDataSeeder.IntrospectionClientSecret);
        var (_, introspectBody) = await client.PostFormAsync("/connect/introspect", new Dictionary<string, string>
        {
            ["token"] = accessToken!,
        });

        Assert.True(introspectBody.GetProperty("active").GetBoolean());
        Assert.Equal(directiveValue,
            introspectBody.GetProperty(TestDataSeeder.DirectiveClaimType).GetString());
    }

    /// <summary>
    /// Overlay that configures <c>ClaimScopeMap.ClaimToScope</c> to map
    /// <c>directive</c> → <c>directives</c>. The in-memory-collection binding
    /// syntax for a dictionary is <c>:0</c>/<c>:1</c> indices on the value
    /// keys, but a single key→value map is a single <c>ClaimToScope:directive</c>
    /// entry — which binds cleanly to <c>Dictionary&lt;string,string&gt;</c>.
    /// </summary>
    private static IReadOnlyDictionary<string, string?> MapConfiguration() => new Dictionary<string, string?>
    {
        ["Sufficit:Identity:ClaimScopeMap:ClaimToScope:directive"] = DirectiveScopeName,
    };

    /// <summary>
    /// Provisions the <c>directives</c> scope (with the introspection client as
    /// a resource/audience, so introspection surfaces the non-standard
    /// <c>directive</c> claim) and a confidential password-grant client
    /// permitted to request both <c>test.scope</c> and <c>directives</c>.
    /// Mirrors the seeding pattern in <see cref="TestDataSeeder"/>.
    /// </summary>
    private static async Task ProvisionDirectiveScopeAndClientAsync(SufficitIdentityTestFactory factory)
    {
        using var scope = factory.Services.CreateScope();
        var scopeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
        var appManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        if (await scopeManager.FindByNameAsync(DirectiveScopeName) is null)
        {
            await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = DirectiveScopeName,
                DisplayName = "Directive claim scope",
                // The introspection client must be a resource so the
                // non-standard directive claim is not stripped as "sensitive".
                Resources = { TestDataSeeder.IntrospectionClientId },
            });
        }

        if (await appManager.FindByClientIdAsync(MappedClientId) is null)
        {
            await appManager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = MappedClientId,
                ClientSecret = MappedClientSecret,
                ClientType = ClientTypes.Confidential,
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.Password,
                    Permissions.Prefixes.Scope + TestDataSeeder.ScopeName,
                    Permissions.Prefixes.Scope + DirectiveScopeName,
                },
            });
        }
    }
}
