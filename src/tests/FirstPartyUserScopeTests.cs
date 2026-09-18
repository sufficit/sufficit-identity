using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.STS;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

public sealed class FirstPartyUserScopeTests
{
    private const string FleetScope = "fleet.api", FleetResource = "sufficit_fleet";

    [Theory]
    [InlineData(true, true, true, true)]
    [InlineData(false, true, true, false)]
    [InlineData(true, false, true, false)]
    [InlineData(true, true, false, false)]
    public async Task Grants_require_explicit_configuration_permission_and_registered_scope(
        bool configured, bool permission, bool registered, bool expected)
    {
        await using var factory = new SufficitIdentityTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        await Configure(factory, configured, permission, registered);
        using var scope = factory.Services.CreateScope();
        var policy = scope.ServiceProvider.GetRequiredService<FirstPartyUserScopePolicy>();
        var result = await policy.ResolveAsync(TestDataSeeder.DeviceClientId, [Scopes.OpenId]);
        Assert.Equal(expected, result.Contains(FleetScope));
        Assert.Contains(Scopes.OpenId, result);
        Assert.DoesNotContain(FleetScope, await policy.ResolveAsync(TestDataSeeder.AuthorizationCodeClientId, [Scopes.OpenId]));
        Assert.DoesNotContain(FleetScope, await policy.ResolveAsync(null, [Scopes.OpenId]));
    }

    [Fact]
    public async Task Legacy_device_refresh_adds_configured_scope_and_audience_preserving_subject()
    {
        await using var factory = new SufficitIdentityTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var first = await Enroll(client);
        Assert.DoesNotContain(FleetScope, first.GetProperty("scope").GetString());
        var before = await Inspect(client, first.GetProperty("access_token").GetString()!);
        await Configure(factory, true, true, true);
        var (status, refreshed) = await client.PostFormAsync("/connect/token", new Dictionary<string, string> {
            ["grant_type"] = "refresh_token", ["refresh_token"] = first.GetProperty("refresh_token").GetString()!,
            ["client_id"] = TestDataSeeder.DeviceClientId, ["client_secret"] = TestDataSeeder.DeviceClientSecret
        });
        Assert.Equal(HttpStatusCode.OK, status);
        var after = await Inspect(client, refreshed.GetProperty("access_token").GetString()!);
        Assert.True(after.GetProperty("active").GetBoolean());
        Assert.Contains(FleetScope, after.GetProperty("scope").ToString());
        Assert.Equal(before.GetProperty("sub").GetString(), after.GetProperty("sub").GetString());
        Assert.Contains(FleetResource, after.GetProperty("aud").ToString());
        Assert.Contains(TestDataSeeder.IntrospectionClientId, after.GetProperty("aud").ToString());
        var fresh = await Enroll(client);
        Assert.Contains(FleetScope, fresh.GetProperty("scope").GetString());
    }

    [Fact]
    public async Task Machine_grants_do_not_inherit_user_scope_mapping()
    {
        await using var factory = new SufficitIdentityTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        await Configure(factory, true, true, true, TestDataSeeder.ClientCredentialsClientId);
        using var client = factory.CreateClient();
        var (status, body) = await client.PostFormAsync("/connect/token", new Dictionary<string, string> {
            ["grant_type"] = "client_credentials", ["client_id"] = TestDataSeeder.ClientCredentialsClientId,
            ["client_secret"] = TestDataSeeder.ClientCredentialsClientSecret, ["scope"] = TestDataSeeder.ScopeName
        });
        Assert.Equal(HttpStatusCode.OK, status);
        var details = await Inspect(client, body.GetProperty("access_token").GetString()!);
        Assert.DoesNotContain(FleetScope, details.GetProperty("scope").ToString());
    }

    private static async Task Configure(SufficitIdentityTestFactory factory, bool configured, bool permission,
        bool registered, string clientId = TestDataSeeder.DeviceClientId)
    {
        using var scope = factory.Services.CreateScope();
        if (configured) scope.ServiceProvider.GetRequiredService<SufficitIdentityOptions>().FirstPartyUserScopes[clientId] = [FleetScope];
        if (registered) await scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>().CreateAsync(
            new OpenIddictScopeDescriptor { Name = FleetScope, Resources = { FleetResource } });
        if (permission)
        {
            var apps = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var app = (await apps.FindByClientIdAsync(clientId))!;
            var descriptor = new OpenIddictApplicationDescriptor();
            await apps.PopulateAsync(descriptor, app);
            descriptor.Permissions.Add(Permissions.Prefixes.Scope + FleetScope);
            await apps.UpdateAsync(app, descriptor);
        }
    }

    private static async Task<JsonElement> Enroll(HttpClient client)
    {
        var (status, body) = await client.PostFormAsync("/connect/deviceauthorization", new Dictionary<string, string> {
            ["client_id"] = TestDataSeeder.DeviceClientId, ["client_secret"] = TestDataSeeder.DeviceClientSecret,
            ["scope"] = "openid profile offline_access " + TestDataSeeder.ScopeName
        });
        Assert.Equal(HttpStatusCode.OK, status);
        await TestOnlyEndpoints.SignInAsync(client, TestDataSeeder.DefaultUsername);
        var csrf = await TestOnlyEndpoints.GetAntiforgeryTokenAsync(client);
        using var approved = await client.PostAsync("/connect/device", new FormUrlEncodedContent(new Dictionary<string, string> {
            ["user_code"] = body.GetProperty("user_code").GetString()!, ["approved"] = "true", ["__RequestVerificationToken"] = csrf
        }));
        Assert.Equal(HttpStatusCode.Redirect, approved.StatusCode);
        var (pollStatus, token) = await client.PostFormAsync("/connect/token", new Dictionary<string, string> {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code", ["device_code"] = body.GetProperty("device_code").GetString()!,
            ["client_id"] = TestDataSeeder.DeviceClientId, ["client_secret"] = TestDataSeeder.DeviceClientSecret
        });
        Assert.Equal(HttpStatusCode.OK, pollStatus);
        return token;
    }

    private static async Task<JsonElement> Inspect(HttpClient client, string token)
    {
        var (status, body) = await client.PostFormAsync("/connect/introspect", new Dictionary<string, string> {
            ["token"] = token, ["client_id"] = TestDataSeeder.IntrospectionClientId, ["client_secret"] = TestDataSeeder.IntrospectionClientSecret
        });
        Assert.Equal(HttpStatusCode.OK, status);
        return body;
    }
}
