using System.Net;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

[Collection(StsCollection.Name)]
public sealed class TokenExchangeTests
{
    private readonly SufficitIdentityTestFactory _factory;

    public TokenExchangeTests(SufficitIdentityTestFactory factory) => _factory = factory;

    [Fact]
    public async Task Token_exchange_issues_a_delegated_token_carrying_the_act_claim()
    {
        var username = $"exchange-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#4";

        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(userManager, username, password);
        }

        var client = _factory.CreateClient();

        // 1) Obtain a subject_token via the password grant.
        var (subjectStatus, subjectBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = username,
            ["password"] = password,
            ["client_id"] = TestDataSeeder.PasswordClientId,
            ["client_secret"] = TestDataSeeder.PasswordClientSecret,
            // TestDataSeeder.ScopeName resources include the introspection
            // client; the exchanged token below inherits this scope (the
            // exchange request itself sends no scope param), which is what
            // makes the introspection client a trusted audience allowed to see
            // non-standard claims (e.g. `act`) in the introspection response.
            ["scope"] = TestDataSeeder.ScopeName,
        });
        Assert.Equal(HttpStatusCode.OK, subjectStatus);
        var subjectToken = subjectBody.GetProperty("access_token").GetString();
        Assert.False(string.IsNullOrEmpty(subjectToken));

        // 2) Exchange it as test-exchange (RFC 8693).
        var (exchangeStatus, exchangeBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
            ["subject_token"] = subjectToken!,
            ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["client_id"] = TestDataSeeder.TokenExchangeClientId,
            ["client_secret"] = TestDataSeeder.TokenExchangeClientSecret,
        });
        Assert.Equal(HttpStatusCode.OK, exchangeStatus);
        var exchangedToken = exchangeBody.GetProperty("access_token").GetString();
        Assert.False(string.IsNullOrEmpty(exchangedToken));

        // 3) Introspect the exchanged token: active + "act" claim identifying
        // the exchanging client (test-exchange), per RFC 8693 §4.1.
        client.DefaultRequestHeaders.Authorization = IntrospectionTests.BasicAuthFor(
            TestDataSeeder.IntrospectionClientId, TestDataSeeder.IntrospectionClientSecret);

        var (introspectStatus, introspectBody) = await client.PostFormAsync("/connect/introspect", new Dictionary<string, string>
        {
            ["token"] = exchangedToken!,
        });

        Assert.Equal(HttpStatusCode.OK, introspectStatus);
        Assert.True(introspectBody.GetProperty("active").GetBoolean());

        var act = introspectBody.GetProperty("act");
        Assert.Equal(TestDataSeeder.TokenExchangeClientId, act.GetProperty("sub").GetString());
    }

    [Fact]
    public async Task Token_exchange_does_not_leak_the_subjects_role_claim_when_the_delegated_scope_lacks_roles()
    {
        // Destinations-gating regression guard (eval #4/#10): BuildIdentityAsync
        // always stages the subject's FULL role breadth onto the in-memory
        // ClaimsIdentity before ExchangeForTokenExchangeAsync narrows the
        // SCOPE set to the intersection of what the exchanging client asked
        // for and what the subject_token itself carried — but the role
        // CLAIM only follows if GetDestinations sees "roles" in that
        // narrowed scope set. A client that exchanges without requesting
        // "roles" must not silently receive the subject's roles anyway.
        var username = $"exchange-roles-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#13";
        const string roleName = "test-exchange-role";

        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<ApplicationRole>>();
            var user = await TestDataSeeder.CreateUserAsync(userManager, username, password);
            await TestDataSeeder.AddToRoleAsync(roleManager, userManager, user, roleName);
        }

        var client = _factory.CreateClient();

        // 1) Subject token WITH "roles" scope: proves the user really does
        // carry a role claim when a token actually requests that scope
        // (PasswordClientId was given the "roles" scope permission
        // specifically to make this possible — see TestDataSeeder).
        var (subjectStatus, subjectBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = username,
            ["password"] = password,
            ["client_id"] = TestDataSeeder.PasswordClientId,
            ["client_secret"] = TestDataSeeder.PasswordClientSecret,
            ["scope"] = $"{TestDataSeeder.ScopeName} roles",
        });
        Assert.Equal(HttpStatusCode.OK, subjectStatus);
        var subjectToken = subjectBody.GetProperty("access_token").GetString();
        Assert.False(string.IsNullOrEmpty(subjectToken));

        // 2) Exchange WITHOUT requesting "roles": delegated scope set =
        // intersection({test.scope}, {test.scope, roles}) = {test.scope}.
        var (exchangeStatus, exchangeBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
            ["subject_token"] = subjectToken!,
            ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["client_id"] = TestDataSeeder.TokenExchangeClientId,
            ["client_secret"] = TestDataSeeder.TokenExchangeClientSecret,
            ["scope"] = TestDataSeeder.ScopeName,
        });
        Assert.Equal(HttpStatusCode.OK, exchangeStatus);
        var exchangedToken = exchangeBody.GetProperty("access_token").GetString();
        Assert.False(string.IsNullOrEmpty(exchangedToken));

        client.DefaultRequestHeaders.Authorization = IntrospectionTests.BasicAuthFor(
            TestDataSeeder.IntrospectionClientId, TestDataSeeder.IntrospectionClientSecret);

        var (introspectStatus, introspectBody) = await client.PostFormAsync("/connect/introspect", new Dictionary<string, string>
        {
            ["token"] = exchangedToken!,
        });

        Assert.Equal(HttpStatusCode.OK, introspectStatus);
        Assert.True(introspectBody.GetProperty("active").GetBoolean());

        // The delegated scope really did drop "roles" ...
        var grantedScopes = (introspectBody.GetProperty("scope").GetString() ?? "").Split(
            ' ', StringSplitOptions.RemoveEmptyEntries);
        Assert.DoesNotContain("roles", grantedScopes);

        // ... and, critically, the role claim itself does not ride along
        // regardless — this is the actual bug the eval flagged (only the
        // scope SET was ever narrowed, not the claims).
        Assert.False(
            introspectBody.TryGetProperty("role", out var roleClaim),
            $"Exchanged token unexpectedly carries a 'role' claim ({roleClaim}) despite the delegated scope lacking 'roles'.");
    }
}

/// <summary>
/// Covers the Sufficit-level <c>Sufficit:Identity:TokenExchange:AllowedClientIds</c>
/// allowlist gate (eval #4/#8): a client can carry the OpenIddict-level
/// <c>Permissions.GrantTypes.TokenExchange</c> permission (so it reaches
/// <c>AuthorizationController.ExchangeForTokenExchangeAsync</c> at all) and
/// still be rejected by this second, Sufficit-specific layer.
///
/// The shared <see cref="StsCollection"/> fixture leaves
/// <c>AllowedClientIds</c> empty (= "no restriction", so
/// <see cref="TestDataSeeder.TokenExchangeClientId"/> works unmodified for
/// every other test in this file) — exercising the REJECTION branch needs a
/// non-empty allowlist, i.e. a different server configuration, so this class
/// builds its own, fully isolated <see cref="SufficitIdentityTestFactory"/>
/// instead of joining <see cref="StsCollection"/>.
/// </summary>
public sealed class TokenExchangeAllowlistTests
{
    [Fact]
    public async Task Token_exchange_from_a_client_outside_the_configured_allowlist_is_rejected()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
        {
            // Only TokenExchangeClientId is allowed here.
            // TokenExchangeBlockedClientId still carries the OpenIddict-level
            // grant-type permission (TestDataSeeder) but is deliberately left
            // out of this list.
            ["Sufficit:Identity:TokenExchange:AllowedClientIds:0"] = TestDataSeeder.TokenExchangeClientId,
        });
        await ((IAsyncLifetime)factory).InitializeAsync();

        var client = factory.CreateClient();

        var (subjectStatus, subjectBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = TestDataSeeder.DefaultUsername,
            ["password"] = TestDataSeeder.DefaultPassword,
            ["client_id"] = TestDataSeeder.PasswordClientId,
            ["client_secret"] = TestDataSeeder.PasswordClientSecret,
            ["scope"] = TestDataSeeder.ScopeName,
        });
        Assert.Equal(HttpStatusCode.OK, subjectStatus);
        var subjectToken = subjectBody.GetProperty("access_token").GetString();
        Assert.False(string.IsNullOrEmpty(subjectToken));

        var (exchangeStatus, exchangeBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
            ["subject_token"] = subjectToken!,
            ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["client_id"] = TestDataSeeder.TokenExchangeBlockedClientId,
            ["client_secret"] = TestDataSeeder.TokenExchangeBlockedClientSecret,
        });

        Assert.Equal(HttpStatusCode.BadRequest, exchangeStatus);
        Assert.Equal("unauthorized_client", exchangeBody.GetProperty("error").GetString());
    }
}
