using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

/// <summary>
/// RFC 8693 delegation beyond a user subject: a client exchanging its own
/// token, and an explicit actor_token that must belong to the caller.
/// </summary>
public sealed class TokenExchangeDelegationTests
{
    private const string TokenExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange";
    private const string AccessTokenType = "urn:ietf:params:oauth:token-type:access_token";

    [Fact]
    public async Task Client_subject_token_is_rejected_by_default()
    {
        using var factory = await CreateFactoryAsync(allowClientSubjectTokens: false);
        var client = factory.CreateClient();
        var clientToken = await ClientCredentialsTokenAsync(client);

        var (status, body) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = TokenExchangeGrant,
            ["subject_token"] = clientToken,
            ["subject_token_type"] = AccessTokenType,
            ["client_id"] = TestDataSeeder.ClientCredentialsClientId,
            ["client_secret"] = TestDataSeeder.ClientCredentialsClientSecret,
        });

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("invalid_grant", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Client_exchanges_its_own_token_when_enabled()
    {
        using var factory = await CreateFactoryAsync(allowClientSubjectTokens: true);
        var client = factory.CreateClient();
        var clientToken = await ClientCredentialsTokenAsync(client);

        var (status, body) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = TokenExchangeGrant,
            ["subject_token"] = clientToken,
            ["subject_token_type"] = AccessTokenType,
            ["client_id"] = TestDataSeeder.ClientCredentialsClientId,
            ["client_secret"] = TestDataSeeder.ClientCredentialsClientSecret,
        });

        Assert.Equal(HttpStatusCode.OK, status);
        var introspection = await IntrospectAsync(
            factory, body.GetProperty("access_token").GetString()!);
        Assert.Equal(TestDataSeeder.ClientCredentialsClientId,
            introspection.GetProperty("sub").GetString());
        Assert.Equal(TestDataSeeder.ClientCredentialsClientId,
            introspection.GetProperty("act").GetProperty("sub").GetString());
    }

    [Fact]
    public async Task A_delegation_chain_stops_at_the_configured_depth()
    {
        // Each exchange nests the previous act claim inside the new one
        // (RFC 8693 4.1). Unbounded, a chain grows one level per exchange —
        // tokens get larger every hop, and a loop between two services never
        // ends. The bound is the deployment's, and the refusal comes before
        // anything is issued.
        using var factory = await CreateFactoryAsync(
            allowClientSubjectTokens: true,
            maxDelegationDepth: 2);
        var client = factory.CreateClient();

        var token = await ClientCredentialsTokenAsync(client);
        for (var depth = 1; depth <= 2; depth++)
        {
            var (accepted, acceptedBody) = await ExchangeOwnTokenAsync(client, token);
            Assert.True(
                accepted == HttpStatusCode.OK,
                $"Exchange {depth} should be within the bound: {acceptedBody}");
            token = acceptedBody.GetProperty("access_token").GetString()!;
            Assert.Equal(depth, ActDepth(await IntrospectAsync(factory, token)));
        }

        var (refused, refusedBody) = await ExchangeOwnTokenAsync(client, token);
        Assert.Equal(HttpStatusCode.BadRequest, refused);
        Assert.Equal("invalid_grant", refusedBody.GetProperty("error").GetString());
        Assert.Contains(
            "delegation",
            refusedBody.GetProperty("error_description").GetString());

        static int ActDepth(JsonElement introspection)
        {
            var depth = 0;
            var current = introspection;
            while (current.ValueKind == JsonValueKind.Object
                && current.TryGetProperty("act", out var act))
            {
                depth++;
                current = act;
            }

            return depth;
        }
    }

    [Theory]
    [InlineData(null, 0)]
    [InlineData("", 0)]
    [InlineData("""{"sub":"a"}""", 1)]
    [InlineData("""{"sub":"a","act":{"sub":"b"}}""", 2)]
    [InlineData("""{"sub":"a","act":{"sub":"b","act":{"sub":"c"}}}""", 3)]
    public void Delegation_depth_counts_nested_actors(string? act, int expected) =>
        Assert.Equal(expected, Sufficit.Identity.STS.Grants.TokenExchangeGrantHandler
            .DelegationDepth(act));

    [Theory]
    // A chain that cannot be read cannot be extended: refusing is safer than
    // guessing its depth, and safer than the exception it would otherwise
    // raise further down, when the prior act is deserialized for nesting.
    [InlineData("not json")]
    [InlineData("\"a-string\"")]
    [InlineData("""{"sub":"a","act":"not-an-object"}""")]
    [InlineData("""{"sub":"a","act":[1,2]}""")]
    public void An_unreadable_delegation_chain_has_no_depth(string act) =>
        Assert.Null(Sufficit.Identity.STS.Grants.TokenExchangeGrantHandler
            .DelegationDepth(act));

    [Fact]
    public void A_delegation_chain_nested_past_the_parser_limit_has_no_depth()
    {
        var act = string.Concat(Enumerable.Repeat("""{"sub":"x","act":""", 100))
            + """{"sub":"x"}""" + new string('}', 100);

        Assert.Null(Sufficit.Identity.STS.Grants.TokenExchangeGrantHandler
            .DelegationDepth(act));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(17)]
    public async Task An_out_of_range_delegation_depth_refuses_startup(int depth)
    {
        var failure = await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            using var factory = await CreateFactoryAsync(
                allowClientSubjectTokens: false,
                maxDelegationDepth: depth);
        });

        Assert.Contains("MaxDelegationDepth", failure.ToString());
    }

    private static Task<(HttpStatusCode Status, JsonElement Body)> ExchangeOwnTokenAsync(
        HttpClient client,
        string subjectToken) =>
        client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = TokenExchangeGrant,
            ["subject_token"] = subjectToken,
            ["subject_token_type"] = AccessTokenType,
            ["client_id"] = TestDataSeeder.ClientCredentialsClientId,
            ["client_secret"] = TestDataSeeder.ClientCredentialsClientSecret,
        });

    [Fact]
    public async Task Actor_token_issued_to_the_caller_names_the_actor()
    {
        using var factory = await CreateFactoryAsync(allowClientSubjectTokens: false);
        string actorUserId;
        const string actorPassword = "Act0r!Passw0rd#21";
        var actorUsername = $"actor-{Guid.NewGuid():N}";
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            actorUserId = (await TestDataSeeder.CreateUserAsync(
                users, actorUsername, actorPassword)).Id;
        }

        var client = factory.CreateClient();
        var subjectToken = await PasswordTokenAsync(client,
            TestDataSeeder.DefaultUsername, TestDataSeeder.DefaultPassword,
            TestDataSeeder.PasswordClientId, TestDataSeeder.PasswordClientSecret);
        var actorToken = await PasswordTokenAsync(client,
            actorUsername, actorPassword,
            TestDataSeeder.TokenExchangeClientId, TestDataSeeder.TokenExchangeClientSecret);

        var (status, body) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = TokenExchangeGrant,
            ["subject_token"] = subjectToken,
            ["subject_token_type"] = AccessTokenType,
            ["actor_token"] = actorToken,
            ["actor_token_type"] = AccessTokenType,
            ["client_id"] = TestDataSeeder.TokenExchangeClientId,
            ["client_secret"] = TestDataSeeder.TokenExchangeClientSecret,
        });

        Assert.Equal(HttpStatusCode.OK, status);
        var act = (await IntrospectAsync(
            factory, body.GetProperty("access_token").GetString()!)).GetProperty("act");
        Assert.Equal(actorUserId, act.GetProperty("sub").GetString());
        Assert.Equal(TestDataSeeder.TokenExchangeClientId,
            act.GetProperty("client_id").GetString());
    }

    [Fact]
    public async Task Actor_token_issued_to_another_client_is_rejected()
    {
        using var factory = await CreateFactoryAsync(allowClientSubjectTokens: false);
        var client = factory.CreateClient();
        var subjectToken = await PasswordTokenAsync(client,
            TestDataSeeder.DefaultUsername, TestDataSeeder.DefaultPassword,
            TestDataSeeder.PasswordClientId, TestDataSeeder.PasswordClientSecret);
        var foreignActorToken = await ClientCredentialsTokenAsync(client);

        var (status, body) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = TokenExchangeGrant,
            ["subject_token"] = subjectToken,
            ["subject_token_type"] = AccessTokenType,
            ["actor_token"] = foreignActorToken,
            ["actor_token_type"] = AccessTokenType,
            ["client_id"] = TestDataSeeder.TokenExchangeClientId,
            ["client_secret"] = TestDataSeeder.TokenExchangeClientSecret,
        });

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("invalid_grant", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task May_act_admits_only_the_named_actor()
    {
        using var factory = await CreateFactoryAsync(allowClientSubjectTokens: false);
        const string password = "Act0r!Passw0rd#21";
        var allowedName = $"allowed-{Guid.NewGuid():N}";
        var otherName = $"other-{Guid.NewGuid():N}";
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var allowed = await TestDataSeeder.CreateUserAsync(users, allowedName, password);
            await TestDataSeeder.CreateUserAsync(users, otherName, password);
            var subject = await users.FindByNameAsync(TestDataSeeder.DefaultUsername)
                ?? throw new InvalidOperationException("Seed user not found.");
            await users.AddClaimAsync(subject, new System.Security.Claims.Claim(
                "may_act", JsonSerializer.Serialize(new { sub = allowed.Id })));
        }

        var client = factory.CreateClient();
        var subjectToken = await PasswordTokenAsync(client,
            TestDataSeeder.DefaultUsername, TestDataSeeder.DefaultPassword,
            TestDataSeeder.PasswordClientId, TestDataSeeder.PasswordClientSecret);

        async Task<(HttpStatusCode Status, JsonElement Body)> ExchangeAsync(string actorName)
        {
            var actorToken = await PasswordTokenAsync(client, actorName, password,
                TestDataSeeder.TokenExchangeClientId, TestDataSeeder.TokenExchangeClientSecret);
            return await client.PostFormAsync("/connect/token", new Dictionary<string, string>
            {
                ["grant_type"] = TokenExchangeGrant,
                ["subject_token"] = subjectToken,
                ["subject_token_type"] = AccessTokenType,
                ["actor_token"] = actorToken,
                ["actor_token_type"] = AccessTokenType,
                ["client_id"] = TestDataSeeder.TokenExchangeClientId,
                ["client_secret"] = TestDataSeeder.TokenExchangeClientSecret,
            });
        }

        var (otherStatus, otherBody) = await ExchangeAsync(otherName);
        Assert.Equal(HttpStatusCode.BadRequest, otherStatus);
        Assert.Equal("invalid_grant", otherBody.GetProperty("error").GetString());

        var (allowedStatus, _) = await ExchangeAsync(allowedName);
        Assert.Equal(HttpStatusCode.OK, allowedStatus);
    }

    [Theory]
    [InlineData("{\"sub\":\"actor\"}", true)]
    [InlineData("{\"sub\":\"actor\",\"client_id\":\"caller\"}", true)]
    [InlineData("{\"client_id\":\"caller\"}", true)]
    [InlineData("{\"sub\":\"someone-else\"}", false)]
    [InlineData("{\"sub\":\"actor\",\"client_id\":\"other-client\"}", false)]
    [InlineData("{\"iss\":\"https://issuer.example\"}", false)]
    [InlineData("\"actor\"", false)]
    [InlineData("not json", false)]
    public void May_act_requires_every_named_member_to_match(string mayAct, bool expected) =>
        Assert.Equal(expected,
            Sufficit.Identity.STS.Grants.TokenExchangeGrantHandler.MayActAuthorizes(
                mayAct, "actor", "caller"));

    private static async Task<SufficitIdentityTestFactory> CreateFactoryAsync(
        bool allowClientSubjectTokens,
        int? maxDelegationDepth = null)
    {
        var configuration = new Dictionary<string, string?>
        {
            ["Sufficit:Identity:TokenExchange:AllowClientSubjectTokens"] =
                allowClientSubjectTokens ? "true" : "false",
        };
        if (maxDelegationDepth is { } depth)
        {
            configuration["Sufficit:Identity:TokenExchange:MaxDelegationDepth"] =
                depth.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        var factory = SufficitIdentityTestFactory.CreateIsolated(configuration);
        await ((IAsyncLifetime)factory).InitializeAsync();

        await using var scope = factory.Services.CreateAsyncScope();
        var applications = scope.ServiceProvider
            .GetRequiredService<IOpenIddictApplicationManager>();
        await AddPermissionAsync(applications,
            TestDataSeeder.ClientCredentialsClientId, Permissions.GrantTypes.TokenExchange);
        await AddPermissionAsync(applications,
            TestDataSeeder.TokenExchangeClientId, Permissions.GrantTypes.Password);
        return factory;
    }

    private static async Task AddPermissionAsync(
        IOpenIddictApplicationManager applications,
        string clientId,
        string permission)
    {
        var application = await applications.FindByClientIdAsync(clientId)
            ?? throw new InvalidOperationException($"Client '{clientId}' is missing.");
        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(descriptor, application);
        descriptor.Permissions.Add(permission);
        await applications.UpdateAsync(application, descriptor);
    }

    private static async Task<string> ClientCredentialsTokenAsync(HttpClient client)
    {
        var (status, body) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = TestDataSeeder.ClientCredentialsClientId,
            ["client_secret"] = TestDataSeeder.ClientCredentialsClientSecret,
            ["scope"] = TestDataSeeder.ScopeName,
        });
        Assert.Equal(HttpStatusCode.OK, status);
        return body.GetProperty("access_token").GetString()!;
    }

    private static async Task<string> PasswordTokenAsync(
        HttpClient client,
        string username,
        string password,
        string clientId,
        string clientSecret)
    {
        var (status, body) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = username,
            ["password"] = password,
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret,
            ["scope"] = TestDataSeeder.ScopeName,
        });
        Assert.Equal(HttpStatusCode.OK, status);
        return body.GetProperty("access_token").GetString()!;
    }

    private static async Task<JsonElement> IntrospectAsync(
        SufficitIdentityTestFactory factory,
        string token)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = IntrospectionTests.BasicAuthFor(
            TestDataSeeder.IntrospectionClientId, TestDataSeeder.IntrospectionClientSecret);
        var (status, body) = await client.PostFormAsync("/connect/introspect", new Dictionary<string, string>
        {
            ["token"] = token,
        });
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.True(body.GetProperty("active").GetBoolean());
        return body;
    }
}
