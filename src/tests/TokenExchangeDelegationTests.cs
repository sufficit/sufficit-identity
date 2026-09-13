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

    private static async Task<SufficitIdentityTestFactory> CreateFactoryAsync(
        bool allowClientSubjectTokens)
    {
        var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:TokenExchange:AllowClientSubjectTokens"] =
                allowClientSubjectTokens ? "true" : "false",
        });
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
