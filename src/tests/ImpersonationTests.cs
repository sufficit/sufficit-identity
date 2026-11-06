using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.STS.Grants;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

/// <summary>Staff impersonation through token exchange with <c>impersonated_subject</c>.</summary>
public sealed class ImpersonationTests
{
    private const string Password = "Str0ng!Passw0rd#Imp";
    private const string SupportRole = "support-impersonation";

    private static async Task<SufficitIdentityTestFactory> CreateFactoryAsync(bool enabled = true, bool includeUnmappedClaims = true)
    {
        var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:ClaimScopeMap:IncludeUnmappedClaimsInAccessTokens"] = includeUnmappedClaims ? "true" : "false",
            ["Sufficit:Identity:TokenExchange:Impersonation:Enabled"] = enabled ? "true" : "false",
            ["Sufficit:Identity:TokenExchange:Impersonation:AllowedClientIds:0"] = TestDataSeeder.AuthorizationCodeClientId,
            ["Sufficit:Identity:Management:Authorization:RoleCapabilities:" + SupportRole + ":0"] = ManagementCapabilities.UsersImpersonate,
        });
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using var scope = factory.Services.CreateAsyncScope();
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var application = await applications.FindByClientIdAsync(TestDataSeeder.AuthorizationCodeClientId)
            ?? throw new InvalidOperationException("Authorization code client missing.");
        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(descriptor, application);
        descriptor.Permissions.Add(Permissions.GrantTypes.TokenExchange);
        await applications.UpdateAsync(application, descriptor);
        return factory;
    }

    private static async Task<string> UserAsync(SufficitIdentityTestFactory factory, string prefix, string? role = null)
    {
        using var scope = factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var roles = scope.ServiceProvider.GetRequiredService<RoleManager<ApplicationRole>>();
        var user = await TestDataSeeder.CreateUserAsync(users, $"{prefix}-{Guid.NewGuid():N}", Password);
        if (role is not null) await TestDataSeeder.AddToRoleAsync(roles, users, user, role);
        return user.Id;
    }

    private static async Task<string> UserNameAsync(SufficitIdentityTestFactory factory, string id)
    {
        using var scope = factory.Services.CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>().FindByIdAsync(id))!.UserName!;
    }

    /// <summary>A staff access token from the browser flow, with or without a second factor.</summary>
    private static async Task<string> StaffTokenAsync(SufficitIdentityTestFactory factory, string userId, bool withMfa)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        await TestOnlyEndpoints.SignInAsync(client, await UserNameAsync(factory, userId), withMfa: withMfa);
        var (verifier, challenge) = Pkce.CreatePair();
        var code = await AuthorizationCodeFlowTests.AuthorizeAsync(client, challenge, "openid profile " + TestDataSeeder.ScopeName);
        var (status, body) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = TestDataSeeder.AuthorizationCodeRedirectUri,
            ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
            ["code_verifier"] = verifier,
        });
        Assert.Equal(HttpStatusCode.OK, status);
        return body.GetProperty("access_token").GetString()!;
    }

    private static Task<(HttpStatusCode Status, JsonElement Body)> ImpersonateAsync(
        SufficitIdentityTestFactory factory, string staffToken, string targetId)
        => factory.CreateClient().PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = GrantTypes.TokenExchange,
            ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
            ["subject_token"] = staffToken,
            ["subject_token_type"] = TokenTypeIdentifiers.AccessToken,
            [ImpersonationIssuer.SubjectParameter] = targetId,
        });

    private static async Task<JsonElement> IntrospectAsync(SufficitIdentityTestFactory factory, string token)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = IntrospectionTests.BasicAuthFor(
            TestDataSeeder.IntrospectionClientId, TestDataSeeder.IntrospectionClientSecret);
        var (status, body) = await client.PostFormAsync("/connect/introspect", new Dictionary<string, string> { ["token"] = token });
        Assert.Equal(HttpStatusCode.OK, status);
        return body;
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)] // production posture: unmapped claims withheld; act is mapped explicitly
    public async Task Staff_with_capability_and_second_factor_acts_as_a_customer(bool includeUnmappedClaims)
    {
        await using var factory = await CreateFactoryAsync(includeUnmappedClaims: includeUnmappedClaims);
        var staff = await UserAsync(factory, "staff", SupportRole);
        var customer = await UserAsync(factory, "customer");
        var (status, body) = await ImpersonateAsync(factory, await StaffTokenAsync(factory, staff, withMfa: true), customer);

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.False(body.TryGetProperty("refresh_token", out _));
        Assert.InRange(body.GetProperty("expires_in").GetInt32(), 60, 30 * 60);
        var token = await IntrospectAsync(factory, body.GetProperty("access_token").GetString()!);
        Assert.True(token.GetProperty("active").GetBoolean());
        Assert.Equal(customer, token.GetProperty("sub").GetString());
        var act = token.GetProperty("act");
        if (act.ValueKind == JsonValueKind.String) act = JsonDocument.Parse(act.GetString()!).RootElement;
        Assert.Equal(staff, act.GetProperty("sub").GetString());

        using var scope = factory.Services.CreateScope();
        var audit = scope.ServiceProvider.GetRequiredService<Sufficit.Identity.Core.Data.AppDbContext>().ManagementAuditEvents
            .Where(e => e.Capability == ManagementCapabilities.UsersImpersonate && e.ResourceId == customer).ToList();
        var issued = Assert.Single(audit);
        Assert.Equal("allowed", issued.AuthorizationOutcome);
        Assert.Equal(staff, issued.OperatorSubject);
        Assert.Equal(Sufficit.Identity.Core.Entities.ManagementAuditRetention.Never, issued.ExpiresAtUtc);
    }

    [Fact]
    public async Task Sign_in_without_second_factor_is_refused()
    {
        await using var factory = await CreateFactoryAsync();
        var staff = await UserAsync(factory, "staff", SupportRole);
        var customer = await UserAsync(factory, "customer");
        var (status, body) = await ImpersonateAsync(factory, await StaffTokenAsync(factory, staff, withMfa: false), customer);
        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal(Errors.InvalidGrant, body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Staff_without_the_capability_is_refused()
    {
        await using var factory = await CreateFactoryAsync();
        var staff = await UserAsync(factory, "staff");
        var customer = await UserAsync(factory, "customer");
        var (status, body) = await ImpersonateAsync(factory, await StaffTokenAsync(factory, staff, withMfa: true), customer);
        Assert.NotEqual(HttpStatusCode.OK, status);
        Assert.Equal(Errors.AccessDenied, body.GetProperty("error").GetString());
    }

    [Theory]
    [InlineData("manager")]
    [InlineData("administrator")]
    [InlineData(SupportRole)]
    public async Task Privileged_people_cannot_be_impersonated(string role)
    {
        await using var factory = await CreateFactoryAsync();
        var staff = await UserAsync(factory, "staff", SupportRole);
        var privileged = await UserAsync(factory, "privileged", role);
        var (status, body) = await ImpersonateAsync(factory, await StaffTokenAsync(factory, staff, withMfa: true), privileged);
        Assert.NotEqual(HttpStatusCode.OK, status);
        Assert.Equal(Errors.AccessDenied, body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task An_impersonation_token_cannot_impersonate_again()
    {
        await using var factory = await CreateFactoryAsync();
        var staff = await UserAsync(factory, "staff", SupportRole);
        var customer = await UserAsync(factory, "customer");
        var other = await UserAsync(factory, "other");
        var (_, first) = await ImpersonateAsync(factory, await StaffTokenAsync(factory, staff, withMfa: true), customer);
        var (status, _) = await ImpersonateAsync(factory, first.GetProperty("access_token").GetString()!, other);
        Assert.NotEqual(HttpStatusCode.OK, status);
    }

    [Fact]
    public async Task Disabled_by_default()
    {
        await using var factory = await CreateFactoryAsync(enabled: false);
        var staff = await UserAsync(factory, "staff", SupportRole);
        var customer = await UserAsync(factory, "customer");
        var (status, _) = await ImpersonateAsync(factory, await StaffTokenAsync(factory, staff, withMfa: true), customer);
        Assert.NotEqual(HttpStatusCode.OK, status);
    }

    [Fact]
    public void Default_options_keep_the_feature_off_and_short_lived()
    {
        var options = new ImpersonationOptions();
        Assert.False(options.Enabled);
        Assert.Empty(options.AllowedClientIds);
        Assert.True(options.RequireSecondFactor);
        Assert.Equal(30, options.AccessTokenLifetimeMinutes);
    }
}
