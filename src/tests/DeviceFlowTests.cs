using System.Net;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Covers the RFC 8628 Device Authorization Grant (eval #B1 — "device flow
/// not functional end-to-end"; this suite is the regression guard for the
/// fix in AuthorizationController.ExchangeForDeviceCodeAsync +
/// DeviceController). Exercises the real HTTP surface:
/// POST /connect/deviceauthorization, polling /connect/token before
/// approval, the browser-facing POST ~/connect/device approval (stood in
/// for by the factory's test-only sign-in + antiforgery endpoints — the
/// real device page lives in the sibling sufficit-identity-ui repo), and
/// polling again after approval.
/// </summary>
[Collection(StsCollection.Name)]
public sealed class DeviceFlowTests
{
    private readonly SufficitIdentityTestFactory _factory;

    public DeviceFlowTests(SufficitIdentityTestFactory factory) => _factory = factory;

    [Fact]
    public async Task Device_authorization_issues_a_device_code_and_polling_before_approval_is_pending()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        var (authStatus, authBody) = await client.PostFormAsync("/connect/deviceauthorization", new Dictionary<string, string>
        {
            ["client_id"] = TestDataSeeder.DeviceClientId,
            ["client_secret"] = TestDataSeeder.DeviceClientSecret,
            ["scope"] = TestDataSeeder.ScopeName,
        });

        Assert.Equal(HttpStatusCode.OK, authStatus);
        var deviceCode = authBody.GetProperty("device_code").GetString();
        var userCode = authBody.GetProperty("user_code").GetString();
        Assert.False(string.IsNullOrEmpty(deviceCode));
        Assert.False(string.IsNullOrEmpty(userCode));

        var (pollStatus, pollBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code",
            ["device_code"] = deviceCode!,
            ["client_id"] = TestDataSeeder.DeviceClientId,
            ["client_secret"] = TestDataSeeder.DeviceClientSecret,
        });

        Assert.Equal(HttpStatusCode.BadRequest, pollStatus);
        Assert.Equal("authorization_pending", pollBody.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Approving_the_device_code_lets_the_polling_client_redeem_an_access_token()
    {
        var username = $"device-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#11";

        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(userManager, username, password);
        }

        // One shared client/cookie-jar: the "polling device" and the
        // "approving browser" are different actors in RFC 8628, but nothing
        // stops them from sharing an HttpClient/cookie-jar in this test —
        // the device_code itself (not a session) is what ties the two
        // requests together server-side.
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        var (authStatus, authBody) = await client.PostFormAsync("/connect/deviceauthorization", new Dictionary<string, string>
        {
            ["client_id"] = TestDataSeeder.DeviceClientId,
            ["client_secret"] = TestDataSeeder.DeviceClientSecret,
            ["scope"] = TestDataSeeder.ScopeName,
        });
        Assert.Equal(HttpStatusCode.OK, authStatus);
        var deviceCode = authBody.GetProperty("device_code").GetString()!;
        var userCode = authBody.GetProperty("user_code").GetString()!;

        // --- Browser side: sign in, fetch an antiforgery token, approve. ---
        await TestOnlyEndpoints.SignInAsync(client, username);
        var antiforgeryToken = await TestOnlyEndpoints.GetAntiforgeryTokenAsync(client);

        using var approveResponse = await client.PostAsync("/connect/device", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["user_code"] = userCode,
                ["approved"] = "true",
                ["__RequestVerificationToken"] = antiforgeryToken,
            }));

        var approveBody = await approveResponse.Content.ReadAsStringAsync();
        Assert.True(
            (int)approveResponse.StatusCode is >= 200 and < 300,
            $"Device approval POST failed: {(int)approveResponse.StatusCode} {approveResponse.StatusCode} - {approveBody}");

        // --- Device side: poll again, now expecting a token. ---
        var (pollStatus, pollBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code",
            ["device_code"] = deviceCode,
            ["client_id"] = TestDataSeeder.DeviceClientId,
            ["client_secret"] = TestDataSeeder.DeviceClientSecret,
        });

        Assert.Equal(HttpStatusCode.OK, pollStatus);
        Assert.False(string.IsNullOrEmpty(pollBody.GetProperty("access_token").GetString()));
    }

    [Fact]
    public async Task Denying_the_device_code_makes_subsequent_polling_return_access_denied()
    {
        var username = $"device-deny-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#12";

        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(userManager, username, password);
        }

        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        var (authStatus, authBody) = await client.PostFormAsync("/connect/deviceauthorization", new Dictionary<string, string>
        {
            ["client_id"] = TestDataSeeder.DeviceClientId,
            ["client_secret"] = TestDataSeeder.DeviceClientSecret,
            ["scope"] = TestDataSeeder.ScopeName,
        });
        Assert.Equal(HttpStatusCode.OK, authStatus);
        var deviceCode = authBody.GetProperty("device_code").GetString()!;
        var userCode = authBody.GetProperty("user_code").GetString()!;

        await TestOnlyEndpoints.SignInAsync(client, username);
        var antiforgeryToken = await TestOnlyEndpoints.GetAntiforgeryTokenAsync(client);

        using var denyResponse = await client.PostAsync("/connect/device", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["user_code"] = userCode,
                ["approved"] = "false",
                ["__RequestVerificationToken"] = antiforgeryToken,
            }));

        // DeviceController.Verify's own Forbid(AccessDenied) response.
        Assert.False(denyResponse.IsSuccessStatusCode);

        var (pollStatus, pollBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code",
            ["device_code"] = deviceCode,
            ["client_id"] = TestDataSeeder.DeviceClientId,
            ["client_secret"] = TestDataSeeder.DeviceClientSecret,
        });

        Assert.Equal(HttpStatusCode.BadRequest, pollStatus);
        Assert.Equal("access_denied", pollBody.GetProperty("error").GetString());
    }
}
