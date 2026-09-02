using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.STS;
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

    [Fact]
    public async Task Mapped_claim_is_returned_by_userinfo_without_domain_logic_in_the_sts()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(MapConfiguration());
        await ((IAsyncLifetime)factory).InitializeAsync();
        await ProvisionDirectiveScopeAndClientAsync(factory);

        var username = $"csm-userinfo-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#U";
        const string directiveValue = "sufficit:test:csm-userinfo";
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
            ["scope"] = $"openid {DirectiveScopeName}",
        });
        Assert.Equal(HttpStatusCode.OK, tokenStatus);
        var accessToken = tokenBody.GetProperty("access_token").GetString();
        Assert.False(string.IsNullOrEmpty(accessToken));

        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", accessToken);
        var userinfo = await client.GetFromJsonAsync<JsonElement>("/connect/userinfo");
        Assert.Equal(directiveValue,
            userinfo.GetProperty(TestDataSeeder.DirectiveClaimType).GetString());
    }

    [Fact]
    public async Task Mapped_directive_is_projected_to_the_id_token_for_blazor_roles()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(MapConfiguration());
        await ((IAsyncLifetime)factory).InitializeAsync();
        await ProvisionDirectiveScopeAndClientAsync(factory);

        var username = $"csm-idtoken-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#C";
        const string directiveValue = "sufficit:test:csm-idtoken";
        using (var scope = factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(userManager, username, password, directiveValue);
        }

        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });
        await TestOnlyEndpoints.SignInAsync(client, username);
        var (verifier, challenge) = Pkce.CreatePair();
        var code = await AuthorizationCodeFlowTests.AuthorizeAsync(
            client,
            challenge,
            scope: $"openid {DirectiveScopeName}");
        var (status, body) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = TestDataSeeder.AuthorizationCodeRedirectUri,
            ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
            ["code_verifier"] = verifier,
        });

        Assert.Equal(HttpStatusCode.OK, status);
        var idToken = body.GetProperty("id_token").GetString();
        Assert.False(string.IsNullOrWhiteSpace(idToken));
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(idToken);
        Assert.Contains(jwt.Claims, claim =>
            claim.Type == TestDataSeeder.DirectiveClaimType
            && claim.Value == directiveValue);
    }

    [Fact]
    public async Task Mapped_claim_survives_a_refresh_token_redemption()
    {
        // Regression: a refreshed access token must still carry the mapped
        // `directive` claim. The refresh grant rebuilds the identity from
        // current user state (BuildIdentityAsync) and must re-apply the granted
        // scopes/resources onto it — otherwise GetDestinations sees no
        // `directives` scope and drops `directive`, so long-running/unattended
        // clients (which only ever hold refreshed tokens) lose authorization
        // even though their initial token worked.
        using var factory = SufficitIdentityTestFactory.CreateIsolated(MapConfiguration());
        await ((IAsyncLifetime)factory).InitializeAsync();
        await ProvisionDirectiveScopeAndClientAsync(factory);

        var username = $"csm-refresh-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#R";
        const string directiveValue = "sufficit:test:csm-refresh";
        using (var scope = factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(userManager, username, password, directiveValue);
        }

        var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        await TestOnlyEndpoints.SignInAsync(client, username);
        var (verifier, challenge) = Pkce.CreatePair();
        var code = await AuthorizationCodeFlowTests.AuthorizeAsync(
            client, challenge, scope: $"openid offline_access {DirectiveScopeName}");

        var (initialStatus, initialBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = TestDataSeeder.AuthorizationCodeRedirectUri,
            ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
            ["code_verifier"] = verifier,
        });
        Assert.Equal(HttpStatusCode.OK, initialStatus);
        var refreshToken = initialBody.GetProperty("refresh_token").GetString();
        Assert.False(string.IsNullOrEmpty(refreshToken));
        var initialAccessToken = initialBody.GetProperty("access_token").GetString()!;

        // Redeem the refresh token BEFORE introspecting — introspection sets a
        // Basic auth header on the client that must not leak into this POST.
        var (refreshStatus, refreshBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken!,
            ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
        });
        Assert.Equal(HttpStatusCode.OK, refreshStatus);
        var refreshedAccessToken = refreshBody.GetProperty("access_token").GetString()!;

        // Baseline: the initial token carries `directive`; the regression is
        // that the refreshed token must carry it too.
        Assert.Equal(directiveValue, await IntrospectDirectiveAsync(client, initialAccessToken));
        Assert.Equal(directiveValue, await IntrospectDirectiveAsync(client, refreshedAccessToken));
    }

    [Fact]
    public async Task Scope_less_legacy_refresh_grant_recovers_scopes_from_its_authorization()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(MapConfiguration());
        await ((IAsyncLifetime)factory).InitializeAsync();

        using var scope = factory.Services.CreateScope();
        var applicationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var authorizationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictAuthorizationManager>();
        var application = await applicationManager.FindByClientIdAsync(
            TestDataSeeder.AuthorizationCodeClientId);
        Assert.NotNull(application);

        var descriptor = new OpenIddictAuthorizationDescriptor
        {
            ApplicationId = await applicationManager.GetIdAsync(application),
            Status = OpenIddictConstants.Statuses.Valid,
            Subject = $"legacy-refresh-{Guid.NewGuid():N}",
            Type = OpenIddictConstants.AuthorizationTypes.Permanent,
        };
        descriptor.Scopes.UnionWith(["openid", "roles", DirectiveScopeName]);
        var authorization = await authorizationManager.CreateAsync(descriptor);
        var authorizationId = await authorizationManager.GetIdAsync(authorization);

        var grant = new ClaimsPrincipal(new ClaimsIdentity("refresh-token"));
        grant.SetAuthorizationId(authorizationId);
        Assert.Empty(grant.GetScopes());

        var recovered = await RefreshGrantScopeResolver.ResolveAsync(
            grant,
            authorizationManager);

        Assert.Equal(
            [DirectiveScopeName, "openid", "roles"],
            recovered.Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task Refresh_grant_scopes_take_precedence_over_authorization_fallback()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(MapConfiguration());
        await ((IAsyncLifetime)factory).InitializeAsync();

        using var scope = factory.Services.CreateScope();
        var authorizationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictAuthorizationManager>();
        var grant = new ClaimsPrincipal(new ClaimsIdentity("refresh-token"));
        grant.SetScopes("openid", "profile");

        var resolved = await RefreshGrantScopeResolver.ResolveAsync(
            grant,
            authorizationManager);

        Assert.Equal(["openid", "profile"], resolved.ToArray());
    }

    /// <summary>Introspects <paramref name="accessToken"/> and returns the mapped directive value (or null).</summary>
    private static async Task<string?> IntrospectDirectiveAsync(HttpClient client, string accessToken)
    {
        client.DefaultRequestHeaders.Authorization = IntrospectionTests.BasicAuthFor(
            TestDataSeeder.IntrospectionClientId, TestDataSeeder.IntrospectionClientSecret);
        var (_, body) = await client.PostFormAsync("/connect/introspect", new Dictionary<string, string>
        {
            ["token"] = accessToken,
        });
        Assert.True(body.GetProperty("active").GetBoolean());
        return body.TryGetProperty(TestDataSeeder.DirectiveClaimType, out var v) ? v.GetString() : null;
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

        var authorizationCodeClient = await appManager.FindByClientIdAsync(
            TestDataSeeder.AuthorizationCodeClientId)
            ?? throw new InvalidOperationException("The authorization-code test client was not seeded.");
        var descriptor = new OpenIddictApplicationDescriptor();
        await appManager.PopulateAsync(descriptor, authorizationCodeClient);
        descriptor.Permissions.Add(Permissions.Prefixes.Scope + DirectiveScopeName);
        await appManager.UpdateAsync(authorizationCodeClient, descriptor);
    }

    // ------------------------------------------------------------------
    // Storage name vs wire name.
    //
    // The persisted claim type used to travel straight into the token, which
    // made renaming it in the database a breaking change for every consumer at
    // once. These pin the decoupling: both names are emitted whichever one the
    // grant is stored as, so the migration is invisible — and, critically, the
    // second name inherits the scope gate instead of bypassing it.
    // ------------------------------------------------------------------

    [Theory]
    [InlineData("directive")]
    [InlineData("entitlements")]
    public async Task Both_names_reach_the_token_whichever_one_the_grant_is_stored_under(
        string storedClaimType)
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(MapConfiguration());
        await ((IAsyncLifetime)factory).InitializeAsync();
        await ProvisionDirectiveScopeAndClientAsync(factory);

        var username = $"csm-both-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#Both";
        var value = $"phonecalls:{Guid.NewGuid():N}";

        using (var scope = factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await TestDataSeeder.CreateUserAsync(userManager, username, password);
            await userManager.AddClaimAsync(user, new Claim(storedClaimType, value));
        }

        var body = await IntrospectAsync(factory, username, password,
            $"{TestDataSeeder.ScopeName} {DirectiveScopeName}");

        Assert.True(body.GetProperty("active").GetBoolean());
        foreach (var emitted in new[] { "directive", "entitlements" })
        {
            Assert.True(
                body.TryGetProperty(emitted, out var claim),
                $"stored as '{storedClaimType}', but '{emitted}' is missing from the token");
            Assert.Contains(value, Values(claim));
        }
    }

    /// <summary>
    /// The half that must not regress: the second name is a projection of a
    /// gated claim, never a way around the gate.
    /// </summary>
    [Theory]
    [InlineData("directive")]
    [InlineData("entitlements")]
    public async Task Neither_name_reaches_a_token_lacking_the_mapped_scope(
        string storedClaimType)
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(MapConfiguration());
        await ((IAsyncLifetime)factory).InitializeAsync();
        await ProvisionDirectiveScopeAndClientAsync(factory);

        var username = $"csm-nogate-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#Gate";
        var value = $"telephonyadmin:{Guid.NewGuid():N}";

        using (var scope = factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await TestDataSeeder.CreateUserAsync(userManager, username, password);
            await userManager.AddClaimAsync(user, new Claim(storedClaimType, value));
        }

        // Deliberately WITHOUT the mapped scope.
        var body = await IntrospectAsync(factory, username, password, TestDataSeeder.ScopeName);

        Assert.True(body.GetProperty("active").GetBoolean());
        foreach (var emitted in new[] { "directive", "entitlements" })
        {
            Assert.False(
                body.TryGetProperty(emitted, out _),
                $"stored as '{storedClaimType}': '{emitted}' leaked into a token whose scope set lacks '{DirectiveScopeName}'");
        }
    }

    private static IEnumerable<string> Values(JsonElement claim) =>
        claim.ValueKind == JsonValueKind.Array
            ? claim.EnumerateArray().Select(item => item.GetString() ?? string.Empty)
            : [claim.GetString() ?? string.Empty];

    private static async Task<JsonElement> IntrospectAsync(
        SufficitIdentityTestFactory factory, string username, string password, string scope)
    {
        var client = factory.CreateClient();
        var (tokenStatus, tokenBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = username,
            ["password"] = password,
            ["client_id"] = MappedClientId,
            ["client_secret"] = MappedClientSecret,
            ["scope"] = scope,
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
        return introspectBody;
    }
}
