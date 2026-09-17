using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.STS;
using Sufficit.Identity.Vault;
using static OpenIddict.Abstractions.OpenIddictConstants;

// Seeds the OpenID conformance environment. Idempotent: clients are recreated
// and the user's password is reset on every run, so a rerun always matches the
// plan configuration rendered by conformance/run.sh.
var settings = new HostApplicationBuilderSettings
{
    Args = args,
    // Not "Development": the generic host would validate every registration on
    // build, including services this tool never resolves.
    EnvironmentName = "ConformanceSeeder",
};
var builder = Host.CreateApplicationBuilder(settings);
builder.Services.AddSufficitIdentitySTS(
    builder.Configuration,
    secretStore: new EnvironmentSecretStore());

using var host = builder.Build();
await using var scope = host.Services.CreateAsyncScope();
var services = scope.ServiceProvider;
var configuration = services.GetRequiredService<IConfiguration>();

string Required(string key) =>
    configuration[key] is { Length: > 0 } value
        ? value
        : throw new InvalidOperationException($"Missing required setting {key}.");

var suiteBaseUrl = Required("Conformance:SuiteBaseUrl").TrimEnd('/');
var alias = Required("Conformance:Alias");
var userName = Required("Conformance:UserName");
var password = Required("Conformance:UserPassword");

var users = services.GetRequiredService<UserManager<ApplicationUser>>();
var user = await users.FindByNameAsync(userName);
if (user is null)
{
    user = new ApplicationUser
    {
        UserName = userName,
        Email = $"{userName}@identity-op.test",
        EmailConfirmed = true,
    };
    Ensure(await users.CreateAsync(user, password), "create the conformance user");
}
else
{
    var token = await users.GeneratePasswordResetTokenAsync(user);
    Ensure(await users.ResetPasswordAsync(user, token, password), "reset the conformance user password");
}

// The suite checks that every scope it asks for comes back with its standard
// claims, so the user needs the data behind phone and address.
if (await users.GetPhoneNumberAsync(user) is null or "")
{
    Ensure(
        await users.SetPhoneNumberAsync(user, "+5547999990000"),
        "set the conformance user phone number");
}

user.PhoneNumberConfirmed = true;
Ensure(await users.UpdateAsync(user), "confirm the conformance user phone number");

if (!(await users.GetClaimsAsync(user)).Any(claim => claim.Type == Claims.Address))
{
    Ensure(
        await users.AddClaimAsync(user, new Claim(
            Claims.Address,
            """{"formatted":"Rua Conformance 100, Blumenau, SC, BR","locality":"Blumenau","region":"SC","country":"BR"}""")),
        "add the conformance user address claim");
}

var applications = services.GetRequiredService<IOpenIddictApplicationManager>();
foreach (var index in new[] { 1, 2 })
{
    var clientId = Required($"Conformance:Client{index}:ClientId");
    if (await applications.FindByClientIdAsync(clientId) is { } existing)
    {
        await applications.DeleteAsync(existing);
    }

    var descriptor = new OpenIddictApplicationDescriptor
    {
        ClientId = clientId,
        ClientSecret = Required($"Conformance:Client{index}:ClientSecret"),
        ClientType = ClientTypes.Confidential,
        // The suite drives the browser; a consent page would need its own
        // automation and is not what the Basic profile tests.
        ConsentType = ConsentTypes.Implicit,
        DisplayName = $"OpenID conformance client {index}",
        RedirectUris = { new Uri($"{suiteBaseUrl}/test/a/{alias}/callback") },
        PostLogoutRedirectUris = { new Uri($"{suiteBaseUrl}/test/a/{alias}/post_logout_redirect") },
        Permissions =
        {
            Permissions.Endpoints.Authorization,
            Permissions.Endpoints.Token,
            Permissions.Endpoints.EndSession,
            Permissions.Endpoints.Revocation,
            Permissions.GrantTypes.AuthorizationCode,
            Permissions.GrantTypes.RefreshToken,
            Permissions.ResponseTypes.Code,
            Permissions.Prefixes.Scope + Scopes.Email,
            Permissions.Prefixes.Scope + Scopes.Profile,
            Permissions.Prefixes.Scope + Scopes.Address,
            Permissions.Prefixes.Scope + Scopes.Phone,
            Permissions.Prefixes.Scope + Scopes.OfflineAccess,
        },
    };
    await applications.CreateAsync(descriptor);
    Console.WriteLine($"Seeded client {clientId}.");
}

Console.WriteLine($"Seeded user {userName}.");
return 0;

static void Ensure(IdentityResult result, string action)
{
    if (!result.Succeeded)
    {
        throw new InvalidOperationException(
            $"Could not {action}: {string.Join("; ", result.Errors.Select(error => error.Code))}");
    }
}
