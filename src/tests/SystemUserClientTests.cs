using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

/// <summary>
/// A confidential client bound to a system user: client_credentials issues a
/// token that names the user, and management authority comes from that user's
/// roles, read at check time and without MFA.
/// </summary>
public sealed class SystemUserClientTests
{
    private const string ClientId = "test-bound-service";
    private const string Secret = "Bound-Service-Secret-0123456789";
    private const string Role = "examplereaders";
    private const string ManagementScope = "identity.management";

    [Fact]
    public async Task A_bound_client_gets_a_token_that_names_its_system_user()
    {
        await using var env = await Environment.CreateAsync();
        var user = await env.CreateSystemUserAsync();
        await env.BindAsync(user.Id);

        var token = await env.TokenAsync();

        using var request = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var userinfo = await env.Client.SendAsync(request);
        var body = await userinfo.Content.ReadAsStringAsync();
        Assert.True(userinfo.StatusCode == HttpStatusCode.OK, body);
        Assert.Equal(user.Id, JsonDocument.Parse(body).RootElement.GetProperty("sub").GetString());
    }

    [Fact]
    public async Task Its_role_grants_management_without_mfa_and_stops_the_moment_the_role_goes()
    {
        await using var env = await Environment.CreateAsync();
        var user = await env.CreateSystemUserAsync();
        await env.BindAsync(user.Id);
        var token = await env.TokenAsync();

        Assert.Equal(HttpStatusCode.Forbidden, await env.ReadClaimsAsync(token, user.Id));

        await env.SetRoleAsync(user.Id, granted: true);
        Assert.Equal(HttpStatusCode.OK, await env.ReadClaimsAsync(token, user.Id));

        // Same token: the role is read at check time, not from the token.
        await env.SetRoleAsync(user.Id, granted: false);
        Assert.Equal(HttpStatusCode.Forbidden, await env.ReadClaimsAsync(token, user.Id));
    }

    [Fact]
    public async Task A_client_bound_to_a_person_or_a_disabled_system_user_is_refused()
    {
        await using var env = await Environment.CreateAsync();

        var person = await env.CreatePersonAsync();
        await env.BindAsync(person.Id);
        var (status, body) = await env.RequestTokenAsync();
        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("unauthorized_client", body.GetProperty("error").GetString());

        var system = await env.CreateSystemUserAsync();
        await env.BindAsync(system.Id);
        await env.DisableAsync(system.Id);
        (status, body) = await env.RequestTokenAsync();
        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("unauthorized_client", body.GetProperty("error").GetString());
    }

    private sealed class Environment : IAsyncDisposable
    {
        private readonly ManagementTestFactory _factory;

        private Environment(ManagementTestFactory factory)
        {
            _factory = factory;
            Client = factory.CreateClient();
        }

        public HttpClient Client { get; }

        public static async Task<Environment> CreateAsync()
        {
            var factory = new ManagementTestFactory(bypassAuthz: false, extraConfiguration: new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Management:RequireMfa"] = "true",
                [$"Sufficit:Identity:Management:Authorization:RoleCapabilities:{Role}:0"] = "identity.claims.read",
            });
            await ((IAsyncLifetime)factory).InitializeAsync();
            await using var scope = factory.Services.CreateAsyncScope();
            var scopes = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
            if (await scopes.FindByNameAsync(ManagementScope) is null)
            {
                await scopes.CreateAsync(new OpenIddictScopeDescriptor { Name = ManagementScope });
            }

            await scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>().CreateAsync(
                new OpenIddictApplicationDescriptor
                {
                    ClientId = ClientId,
                    ClientSecret = Secret,
                    ClientType = ClientTypes.Confidential,
                    DisplayName = "Bound service",
                    Permissions =
                    {
                        Permissions.Endpoints.Token,
                        Permissions.GrantTypes.ClientCredentials,
                        Permissions.Prefixes.Scope + ManagementScope,
                    },
                });
            var roles = scope.ServiceProvider.GetRequiredService<RoleManager<ApplicationRole>>();
            Assert.True((await roles.CreateAsync(new ApplicationRole { Name = Role })).Succeeded);
            return new Environment(factory);
        }

        public async Task<ApplicationUser> CreateSystemUserAsync()
        {
            await using var scope = _factory.Services.CreateAsyncScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = new ApplicationUser { UserName = $"system-{Guid.NewGuid():N}" };
            Assert.True((await users.CreateAsync(user)).Succeeded);
            return user;
        }

        public async Task<ApplicationUser> CreatePersonAsync()
        {
            await using var scope = _factory.Services.CreateAsyncScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = new ApplicationUser { UserName = $"person-{Guid.NewGuid():N}", Email = "person@example.test" };
            Assert.True((await users.CreateAsync(user, "Pers0n!Passw0rd#1")).Succeeded);
            return user;
        }

        public async Task DisableAsync(string userId)
        {
            await using var scope = _factory.Services.CreateAsyncScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = (await users.FindByIdAsync(userId))!;
            await users.SetLockoutEnabledAsync(user, true);
            await users.SetLockoutEndDateAsync(user, DateTimeOffset.MaxValue);
        }

        public async Task SetRoleAsync(string userId, bool granted)
        {
            await using var scope = _factory.Services.CreateAsyncScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = (await users.FindByIdAsync(userId))!;
            var result = granted ? await users.AddToRoleAsync(user, Role) : await users.RemoveFromRoleAsync(user, Role);
            Assert.True(result.Succeeded);
        }

        public async Task BindAsync(string userId)
        {
            await using var scope = _factory.Services.CreateAsyncScope();
            var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var application = (await applications.FindByClientIdAsync(ClientId))!;
            var descriptor = new OpenIddictApplicationDescriptor();
            await applications.PopulateAsync(descriptor, application);
            descriptor.Properties[SystemUserClientBinding.PropertyName] = JsonSerializer.SerializeToElement(userId);
            await applications.UpdateAsync(application, descriptor);
        }

        public async Task<string> TokenAsync()
        {
            var (status, body) = await RequestTokenAsync();
            Assert.True(status == HttpStatusCode.OK, body.ToString());
            return body.GetProperty("access_token").GetString()!;
        }

        public async Task<(HttpStatusCode Status, JsonElement Body)> RequestTokenAsync()
        {
            using var response = await Client.PostAsync("/connect/token", new FormUrlEncodedContent(
                new Dictionary<string, string>
                {
                    ["grant_type"] = "client_credentials",
                    ["client_id"] = ClientId,
                    ["client_secret"] = Secret,
                    ["scope"] = ManagementScope,
                }));
            var text = await response.Content.ReadAsStringAsync();
            return (response.StatusCode, JsonDocument.Parse(text).RootElement.Clone());
        }

        public async Task<HttpStatusCode> ReadClaimsAsync(string token, string userId)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"/api/claims?userId={userId}");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var response = await Client.SendAsync(request);
            return response.StatusCode;
        }

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await _factory.DisposeAsync();
        }
    }
}
