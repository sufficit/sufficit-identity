using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.Tokens;
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

// The Basic profile does not test consent, so its clients skip the page. The
// FAPI 2 plan has a module where the user denies the request: that one needs
// the page on every authorization, because an authorization granted by an
// earlier module would otherwise answer for this one.
var consentType = configuration["Conformance:ConsentType"]?.ToLowerInvariant() switch
{
    "explicit" => ConsentTypes.Explicit,
    "systematic" => ConsentTypes.Systematic,
    _ => ConsentTypes.Implicit,
};
var privateKeyJwt = string.Equals(
    configuration["Conformance:ClientAuthentication"],
    "private_key_jwt",
    StringComparison.OrdinalIgnoreCase);
var clientKeys = new Dictionary<string, JsonObject>(StringComparer.Ordinal);

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
        // FAPI 2.0 forbids a shared secret: the client proves itself with a
        // JWT assertion signed by a key it owns (RFC 7523), so the private key
        // goes to the suite and only the public one is registered here.
        ClientSecret = privateKeyJwt
            ? null
            : Required($"Conformance:Client{index}:ClientSecret"),
        ClientType = ClientTypes.Confidential,
        // The Basic profile does not test consent, so those clients skip the
        // page. The FAPI 2 plan has a module where the user denies the
        // request, which needs the page to exist (Conformance:ConsentType).
        ConsentType = consentType,
        DisplayName = $"OpenID conformance client {index}",
        RedirectUris =
        {
            new Uri($"{suiteBaseUrl}/test/a/{alias}/callback"),
            // The FAPI 2 plan checks that a redirect URI with a query string is
            // matched exactly, so the suite uses this one for its second client.
            new Uri($"{suiteBaseUrl}/test/a/{alias}/callback?dummy1=lorem&dummy2=ipsum"),
        },
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
            Permissions.Endpoints.PushedAuthorization,
        },
    };

    if (privateKeyJwt)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var securityKey = new ECDsaSecurityKey(key)
        {
            KeyId = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(16)),
        };

        descriptor.JsonWebKeySet = new JsonWebKeySet();
        descriptor.JsonWebKeySet.Keys.Add(PublicJwk(securityKey));
        clientKeys[clientId] = PrivateJwk(securityKey, key);
    }

    await applications.CreateAsync(descriptor);
    Console.WriteLine($"Seeded client {clientId}.");
}

if (clientKeys.Count > 0)
{
    // conformance/run.sh renders the plan configuration after this runs, so the
    // suite receives exactly the keys that were registered.
    var path = Required("Conformance:ClientKeysPath");
    await File.WriteAllTextAsync(
        path,
        JsonSerializer.Serialize(clientKeys, new JsonSerializerOptions { WriteIndented = true }));
    Console.WriteLine($"Wrote client keys to {path}.");
}

Console.WriteLine($"Seeded user {userName}.");
return 0;

// The suite needs the private key as a JWK; OpenIddict stores the public half.
static JsonWebKey PublicJwk(ECDsaSecurityKey key)
{
    var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(key);
    jwk.D = null;
    jwk.Alg = SecurityAlgorithms.EcdsaSha256;
    jwk.Use = "sig";
    return jwk;
}

static JsonObject PrivateJwk(ECDsaSecurityKey key, ECDsa algorithm)
{
    var parameters = algorithm.ExportParameters(includePrivateParameters: true);
    return new JsonObject
    {
        ["kty"] = "EC",
        ["crv"] = "P-256",
        ["kid"] = key.KeyId,
        ["alg"] = SecurityAlgorithms.EcdsaSha256,
        ["use"] = "sig",
        ["x"] = Base64UrlEncoder.Encode(parameters.Q.X),
        ["y"] = Base64UrlEncoder.Encode(parameters.Q.Y),
        ["d"] = Base64UrlEncoder.Encode(parameters.D),
    };
}

static void Ensure(IdentityResult result, string action)
{
    if (!result.Succeeded)
    {
        throw new InvalidOperationException(
            $"Could not {action}: {string.Join("; ", result.Errors.Select(error => error.Code))}");
    }
}
