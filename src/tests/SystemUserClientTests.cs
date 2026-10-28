using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
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

    [Fact]
    public async Task A_client_that_is_not_bound_gets_no_management_access()
    {
        await using var env = await Environment.CreateAsync();
        var user = await env.CreateSystemUserAsync();
        await env.SetRoleAsync(user.Id, granted: true);

        // The client holds no authority of its own any more: unbound, its
        // token names nobody, and nothing grants it a capability.
        var token = await env.TokenAsync();
        Assert.Equal(HttpStatusCode.Forbidden, await env.ReadClaimsAsync(token, user.Id));
    }

    [Fact]
    public async Task The_api_binds_and_unbinds_a_client_and_refuses_what_it_should()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var api = factory.CreateClient();
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            await applications.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = ClientId,
                ClientSecret = Secret,
                ClientType = ClientTypes.Confidential,
                Permissions = { Permissions.Endpoints.Token, Permissions.GrantTypes.ClientCredentials },
            });
            await applications.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "test-public-app",
                ClientType = ClientTypes.Public,
                Permissions = { Permissions.Endpoints.Token },
            });
        }

        async Task<string> CreateAsync(string name)
        {
            using var created = await api.PostAsJsonAsync("/api/users/system", new { userName = name });
            Assert.Equal(HttpStatusCode.OK, created.StatusCode);
            return (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("userId").GetString()!;
        }

        var first = await CreateAsync("bound-service-a");
        var second = await CreateAsync("bound-service-b");

        using (var notConfidential = await api.PutAsync(
                   $"/api/users/system/clients?userId={first}&clientId=test-public-app", null))
        {
            Assert.Equal(HttpStatusCode.BadRequest, notConfidential.StatusCode);
        }

        using (var bound = await api.PutAsync($"/api/users/system/clients?userId={first}&clientId={ClientId}", null))
        {
            Assert.Equal(HttpStatusCode.OK, bound.StatusCode);
        }

        // Same user again: nothing changes. Another user: conflict, never a silent rebind.
        using (var again = await api.PutAsync($"/api/system-users/clients?userId={first}&clientId={ClientId}", null))
        {
            Assert.Equal(HttpStatusCode.OK, again.StatusCode);
        }

        using (var elsewhere = await api.PutAsync($"/api/users/system/clients?userId={second}&clientId={ClientId}", null))
        {
            Assert.Equal(HttpStatusCode.Conflict, elsewhere.StatusCode);
        }

        var listed = await api.GetFromJsonAsync<JsonElement>($"/api/users/system/clients?userId={first}");
        Assert.Equal(ClientId, Assert.Single(listed.EnumerateArray()).GetProperty("clientId").GetString());

        using (var wrongUser = await api.DeleteAsync($"/api/users/system/clients?userId={second}&clientId={ClientId}"))
        {
            Assert.Equal(HttpStatusCode.NotFound, wrongUser.StatusCode);
        }

        using (var unbound = await api.DeleteAsync($"/api/users/system/clients?userId={first}&clientId={ClientId}"))
        {
            Assert.Equal(HttpStatusCode.NoContent, unbound.StatusCode);
        }

        Assert.Empty((await api.GetFromJsonAsync<JsonElement>($"/api/users/system/clients?userId={first}")).EnumerateArray());
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
