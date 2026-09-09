using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Clients;
using Sufficit.Identity.STS;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Local onboarding rehearsal. The operator is fixture bootstrap authority;
/// the partner administrator and backend never receive provider capabilities.
/// Business grants are seeded explicitly: no portfolio/delegation API is implied.
/// </summary>
public sealed class PartnerAuthorizationSimulationTests
{
    private static ManagementRequestContext Operator() => new(
        new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("sub", "simulation-provider-operator"),
            new Claim("permission", ManagementCapabilities.ClientsCreate),
            new Claim("permission", ManagementCapabilities.ClientsRead),
            new Claim("permission", ManagementCapabilities.ClientsUpdate),
        ], "simulation-bootstrap")), "partner-auth-simulation");

    private static ManagementTestFactory Factory(string clientId) => new(
        bypassAuthz: false,
        extraConfiguration: new Dictionary<string, string?>
        {
            [$"Sufficit:Identity:Tokens:AccessTokenFormatsByClient:{clientId}"] = "Jwt",
        });

    [Fact]
    public async Task Annual_first_credential_issues_short_machine_tokens_and_is_revocable()
    {
        var clientId = $"partner-system-{Guid.NewGuid():N}";
        var allowed = $"phonecalls:{Guid.NewGuid():D}";
        var humanOnly = $"phonecalls:{Guid.NewGuid():D}";
        using var factory = Factory(clientId);
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var http = factory.CreateClient();
        string humanId;
        CreateManagementClientCredentialResult credential;
        var expiry = DateTimeOffset.UtcNow.AddYears(1);
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var human = await TestDataSeeder.CreateUserAsync(users,
                $"partner-admin-{Guid.NewGuid():N}", $"A!9-{Guid.NewGuid():N}", humanOnly);
            humanId = human.Id;
            Assert.Empty(await users.GetRolesAsync(human));
            var clients = scope.ServiceProvider.GetRequiredService<IClientManagementService>();
            credential = await CreateDatedClientAsync(clients, clientId, expiry);

            // Explicit internal fixture grant, not an inherited human role or
            // a public API that lets the partner grant itself any context.
            var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var application = await applications.FindByClientIdAsync(clientId);
            var descriptor = new OpenIddictApplicationDescriptor();
            await applications.PopulateAsync(descriptor, application!);
            descriptor.Properties[ClientEntitlements.PropertyName] =
                JsonSerializer.SerializeToElement(new[] { allowed });
            await applications.UpdateAsync(application!, descriptor);
            Assert.Null(((OpenIddictEntityFrameworkCoreApplication)application!).ClientSecret);
            var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var stored = await database.OAuthClientCredentials.SingleAsync(c => c.ClientId == clientId);
            Assert.NotEqual(credential.OneTimeSecret, stored.SecretHash);
            Assert.Equal(expiry.UtcDateTime, stored.ExpiresAtUtc);
        }

        Assert.False(credential.CreatedAsPrimary);
        var registered = Assert.Single(credential.Overview.Credentials);
        Assert.False(registered.IsPrimary);
        Assert.Contains("client_secret_basic", credential.Overview.AuthenticationMethods);
        var token = await IssueAsync(http, clientId, credential.OneTimeSecret);
        var principal = await ValidateAsync(http, token.GetProperty("access_token").GetString()!);
        Assert.Equal(clientId, principal.FindFirst("sub")?.Value);
        Assert.NotEqual(humanId, principal.FindFirst("sub")?.Value);
        Assert.True(principal.HasClaim(ClientEntitlements.ClaimType, allowed));
        Assert.True(principal.HasClaim(ClientEntitlements.LegacyClaimType, allowed));
        Assert.DoesNotContain(principal.Claims, c => c.Value == humanOnly);
        Assert.DoesNotContain(principal.Claims, c => c.Type is "role" or "permission");
        // expires_in is remaining lifetime when serialized, so a clock tick
        // between issuance and serialization may consume a second.
        Assert.InRange(token.GetProperty("expires_in").GetInt32(), 890, 900);
        Assert.Equal(900,
            long.Parse(principal.FindFirst("exp")!.Value, System.Globalization.CultureInfo.InvariantCulture)
            - long.Parse(principal.FindFirst("iat")!.Value, System.Globalization.CultureInfo.InvariantCulture));
        Assert.False(token.TryGetProperty("refresh_token", out _));
        Assert.False(token.TryGetProperty("id_token", out _));
        await IssueAsync(http, clientId, credential.OneTimeSecret); // renewal uses same credential
        await AssertInvalidCredentialAsync(http, clientId, credential.OneTimeSecret + "wrong");
        await AssertInvalidCredentialAsync(http, TestDataSeeder.ClientCredentialsClientId,
            credential.OneTimeSecret);

        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Bearer", token.GetProperty("access_token").GetString());
        using var denied = await http.GetAsync("/api/clients");
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        http.DefaultRequestHeaders.Authorization = null;

        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var evaluator = scope.ServiceProvider.GetRequiredService<IManagementAuthorizationEvaluator>();
            var decision = await evaluator.EvaluateAsync(principal,
                ManagementCapabilities.ClientsUpdate,
                new ManagementResource(ManagementResourceTypes.Client, clientId));
            Assert.False(decision.IsAllowed);
            var clients = scope.ServiceProvider.GetRequiredService<IClientManagementService>();
            var read = await clients.GetCredentialsAsync(clientId, Operator());
            Assert.DoesNotContain(credential.OneTimeSecret, JsonSerializer.Serialize(read));
            await Assert.ThrowsAsync<ManagementAccessException>(() =>
                clients.CreateCredentialAsync(new CreateManagementClientCredentialCommand(
                    clientId, read.ClientVersion, "unauthorized self-service", true,
                    ExpiresAtUtc: DateTimeOffset.UtcNow.AddYears(1)),
                    new ManagementRequestContext(principal, "partner-self-escalation-test")));
            Assert.Single((await clients.GetCredentialsAsync(clientId, Operator())).Credentials);
            await clients.RevokeCredentialAsync(new RevokeManagementClientCredentialCommand(
                clientId, registered.Id!.Value, registered.Version, "simulation completed"), Operator());
        }
        await AssertInvalidCredentialAsync(http, clientId, credential.OneTimeSecret);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task First_managed_credential_enforces_schedule_and_expiration(bool scheduled)
    {
        var clientId = $"partner-window-{Guid.NewGuid():N}";
        using var factory = Factory(clientId);
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var http = factory.CreateClient();
        CreateManagementClientCredentialResult credential;
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var clients = scope.ServiceProvider.GetRequiredService<IClientManagementService>();
            credential = await CreateDatedClientAsync(clients, clientId,
                DateTimeOffset.UtcNow.AddYears(1),
                scheduled ? DateTimeOffset.UtcNow.AddHours(1) : null);
            if (!scheduled)
            {
                // Advance only persisted validity, without sleeps or production clocks.
                var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
                var stored = await database.OAuthClientCredentials.SingleAsync(c => c.ClientId == clientId);
                stored.ExpiresAtUtc = DateTime.UtcNow.AddMinutes(-1);
                await database.SaveChangesAsync();
            }
        }
        await AssertInvalidCredentialAsync(http, clientId, credential.OneTimeSecret);
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var application = await applications.FindByClientIdAsync(clientId);
            Assert.Equal(ClientTypes.Confidential, await applications.GetClientTypeAsync(application!));
            Assert.Null(((OpenIddictEntityFrameworkCoreApplication)application!).ClientSecret);
        }
    }

    [Fact]
    public async Task Confidential_client_without_any_credential_is_still_rejected()
    {
        using var factory = Factory($"partner-empty-{Guid.NewGuid():N}");
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using var scope = factory.Services.CreateAsyncScope();
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        await Assert.ThrowsAsync<OpenIddictExceptions.ValidationException>(async () =>
            await applications.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = $"unconfigured-{Guid.NewGuid():N}",
                ClientType = ClientTypes.Confidential,
            }));
    }

    [Fact]
    public async Task Revoked_first_credential_can_be_replaced_without_weakening_other_validation()
    {
        var clientId = $"partner-rotate-{Guid.NewGuid():N}";
        using var factory = Factory(clientId);
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var http = factory.CreateClient();
        await using var scope = factory.Services.CreateAsyncScope();
        var clients = scope.ServiceProvider.GetRequiredService<IClientManagementService>();
        var first = await CreateDatedClientAsync(clients, clientId, DateTimeOffset.UtcNow.AddYears(1));
        var record = Assert.Single(first.Overview.Credentials);
        var revoked = await clients.RevokeCredentialAsync(new RevokeManagementClientCredentialCommand(
            clientId, record.Id!.Value, record.Version), Operator());
        var second = await clients.CreateCredentialAsync(new CreateManagementClientCredentialCommand(
            clientId, revoked.ClientVersion, "annual replacement", true,
            ExpiresAtUtc: DateTimeOffset.UtcNow.AddYears(1)), Operator());
        await AssertInvalidCredentialAsync(http, clientId, first.OneTimeSecret);
        var token = await IssueAsync(http, clientId, second.OneTimeSecret);
        var principal = await ValidateAsync(http, token.GetProperty("access_token").GetString()!);
        Assert.DoesNotContain(principal.Claims,
            claim => claim.Type is ClientEntitlements.ClaimType or ClientEntitlements.LegacyClaimType);

        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var application = await applications.FindByClientIdAsync(clientId);
        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(descriptor, application!);
        descriptor.RedirectUris.Add(new Uri("https://client.tests.local/callback#forbidden"));
        await Assert.ThrowsAsync<OpenIddictExceptions.ValidationException>(async () =>
            await applications.UpdateAsync(application!, descriptor));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(731)]
    public async Task Invalid_initial_expiration_leaves_the_public_client_unchanged(int days)
    {
        var clientId = $"partner-invalid-window-{Guid.NewGuid():N}";
        using var factory = Factory(clientId);
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using var scope = factory.Services.CreateAsyncScope();
        var clients = scope.ServiceProvider.GetRequiredService<IClientManagementService>();
        var created = await clients.CreateAsync(new CreateManagementClientCommand(
            clientId, null, null, null, false, [], [], []), Operator());
        await Assert.ThrowsAsync<ManagementValidationException>(() =>
            clients.CreateCredentialAsync(new CreateManagementClientCredentialCommand(
                clientId, created.Version, "invalid expiration", true,
                ExpiresAtUtc: DateTimeOffset.UtcNow.AddDays(days)), Operator()));
        var overview = await clients.GetCredentialsAsync(clientId, Operator());
        Assert.Empty(overview.Credentials);
        var detail = await clients.GetByClientIdAsync(clientId, Operator());
        Assert.Equal(ClientTypes.Public, detail.Type);
        Assert.Equal(created.Version, detail.Version);
    }

    private static async Task<CreateManagementClientCredentialResult> CreateDatedClientAsync(
        IClientManagementService clients, string clientId, DateTimeOffset expiresAt,
        DateTimeOffset? notBefore = null)
    {
        // Register an inert client first: client_credentials requires a
        // confidential client and cannot be enabled before it has a credential.
        var created = await clients.CreateAsync(new CreateManagementClientCommand(
            clientId, null, "Partner backend simulation", null, false,
            [], [], []), Operator());
        var credential = await clients.CreateCredentialAsync(new CreateManagementClientCredentialCommand(
            clientId, created.Version, "annual integration credential", true,
            NotBeforeUtc: notBefore, ExpiresAtUtc: expiresAt), Operator());
        await clients.UpdateAsync(new UpdateManagementClientCommand(
            clientId, created.DisplayName, null, false,
            [Permissions.GrantTypes.ClientCredentials], [TestDataSeeder.ScopeName], [],
            ExpectedVersion: credential.Overview.ClientVersion,
            AccessTokenLifetimeMinutes: 15), Operator());
        return credential;
    }

    private static Task<HttpResponseMessage> RequestAsync(HttpClient http, string clientId, string secret) =>
        http.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = GrantTypes.ClientCredentials,
            ["client_id"] = clientId,
            ["client_secret"] = secret,
            ["scope"] = TestDataSeeder.ScopeName,
        }));

    private static async Task<JsonElement> IssueAsync(HttpClient http, string clientId, string secret)
    {
        using var response = await RequestAsync(http, clientId, secret);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadFromJsonAsync<JsonElement>();
    }

    private static async Task AssertInvalidCredentialAsync(HttpClient http, string clientId, string secret)
    {
        using var response = await RequestAsync(http, clientId, secret);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var error = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(Errors.InvalidClient, error.GetProperty("error").GetString());
    }

    private static async Task<ClaimsPrincipal> ValidateAsync(HttpClient http, string token)
    {
        var discovery = await http.GetFromJsonAsync<JsonElement>("/.well-known/openid-configuration");
        var jwksPath = new Uri(discovery.GetProperty("jwks_uri").GetString()!).PathAndQuery;
        var keys = new JsonWebKeySet(await http.GetStringAsync(jwksPath)).GetSigningKeys();
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidIssuer = discovery.GetProperty("issuer").GetString(),
            ValidAudience = TestDataSeeder.IntrospectionClientId,
            IssuerSigningKeys = keys,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            RequireSignedTokens = true,
            ClockSkew = TimeSpan.Zero,
        });
        Assert.True(result.IsValid, result.Exception?.Message);
        return new ClaimsPrincipal(result.ClaimsIdentity);
    }
}
