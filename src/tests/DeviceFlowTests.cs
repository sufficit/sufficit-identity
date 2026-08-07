using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Application.Accounts;
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
/// real device page lives in the embedded public UI), and
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
            ["scope"] = $"openid profile email offline_access {TestDataSeeder.ScopeName}",
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

        using var manualVerification = await client.GetAsync("/connect/device");
        Assert.Equal(HttpStatusCode.Redirect, manualVerification.StatusCode);
        Assert.Equal(
            "/device/usercode",
            manualVerification.Headers.Location?.OriginalString);
    }

    [Fact]
    public async Task Device_info_recognizes_an_issued_user_code_and_rejects_an_unknown_code()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        var (authStatus, authBody) = await client.PostFormAsync("/connect/deviceauthorization", new Dictionary<string, string>
        {
            ["client_id"] = TestDataSeeder.DeviceClientId,
            ["client_secret"] = TestDataSeeder.DeviceClientSecret,
            ["scope"] = $"openid profile email offline_access {TestDataSeeder.ScopeName}",
        });

        Assert.Equal(HttpStatusCode.OK, authStatus);
        var userCode = authBody.GetProperty("user_code").GetString();
        Assert.False(string.IsNullOrEmpty(userCode));

        using var issuedResponse = await client.GetAsync(
            $"/connect/device/info?user_code={Uri.EscapeDataString(userCode!)}");
        using var issuedBody = JsonDocument.Parse(await issuedResponse.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.OK, issuedResponse.StatusCode);
        Assert.True(issuedBody.RootElement.GetProperty("valid").GetBoolean());

        var normalized = userCode!.Replace("-", string.Empty, StringComparison.Ordinal);
        using var normalizedResponse = await client.GetAsync(
            $"/connect/device/info?user_code={Uri.EscapeDataString(normalized)}");
        using var normalizedBody = JsonDocument.Parse(await normalizedResponse.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.OK, normalizedResponse.StatusCode);
        Assert.True(normalizedBody.RootElement.GetProperty("valid").GetBoolean());

        using var unknownResponse = await client.GetAsync(
            "/connect/device/info?user_code=ZZZZ-ZZZZ-ZZZZ");
        using var unknownBody = JsonDocument.Parse(await unknownResponse.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.OK, unknownResponse.StatusCode);
        Assert.False(unknownBody.RootElement.GetProperty("valid").GetBoolean());
    }

    [Fact]
    public async Task Device_confirmation_requires_login_and_describes_the_client_and_requested_scopes()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });

        var (authStatus, authBody) = await client.PostFormAsync(
            "/connect/deviceauthorization",
            new Dictionary<string, string>
            {
                ["client_id"] = TestDataSeeder.DeviceClientId,
                ["client_secret"] = TestDataSeeder.DeviceClientSecret,
                ["scope"] = $"openid profile email offline_access {TestDataSeeder.ScopeName}",
            });
        Assert.Equal(HttpStatusCode.OK, authStatus);
        var userCode = authBody.GetProperty("user_code").GetString()!;
        var verificationPath = $"/connect/device?user_code={Uri.EscapeDataString(userCode)}";

        using var anonymousResponse = await client.GetAsync(verificationPath);
        Assert.Equal(HttpStatusCode.Redirect, anonymousResponse.StatusCode);
        Assert.Contains(
            "/account/login?ReturnUrl=",
            anonymousResponse.Headers.Location?.OriginalString,
            StringComparison.Ordinal);

        await TestOnlyEndpoints.SignInAsync(client, TestDataSeeder.DefaultUsername);
        using var verificationResponse = await client.GetAsync(verificationPath);

        Assert.Equal(HttpStatusCode.Redirect, verificationResponse.StatusCode);
        var confirmationPath = verificationResponse.Headers.Location?.OriginalString;
        Assert.NotNull(confirmationPath);
        Assert.StartsWith("/device?", confirmationPath);
        Assert.Contains("device_context=", confirmationPath);

        using var scope = _factory.Services.CreateScope();
        var accessor = scope.ServiceProvider.GetRequiredService<IHttpContextAccessor>();
        accessor.HttpContext = new DefaultHttpContext
        {
            RequestServices = scope.ServiceProvider,
        };
        accessor.HttpContext.Request.QueryString =
            new QueryString(new Uri("http://localhost" + confirmationPath).Query);

        var contextService = scope.ServiceProvider
            .GetRequiredService<IDeviceAuthorizationContextService>();
        var context = await contextService.GetCurrentAsync();

        Assert.True(context.IsValid);
        Assert.Equal(TestDataSeeder.DeviceClientId, context.ClientId);
        Assert.Equal("Test Device Client", context.ClientDisplayName);
        Assert.Contains("openid", context.RequestedScopes);
        Assert.Contains("profile", context.RequestedScopes);
        Assert.Contains("email", context.RequestedScopes);
        Assert.Contains("offline_access", context.RequestedScopes);
        var customScope = Assert.Single(
            context.ScopePresentations!,
            scope => scope.Name == TestDataSeeder.ScopeName);
        Assert.Equal("Test scope", customScope.DisplayName);
        Assert.Contains(
            TestDataSeeder.IntrospectionClientId,
            customScope.Resources);
        Assert.Contains(
            TestDataSeeder.IntrospectionClientId,
            context.RequestedResources!);
        Assert.Equal(TimeSpan.FromMinutes(45), context.AccessTokenLifetime);
        Assert.True(context.AllowsRefreshAccess);
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
            ["scope"] = $"openid profile email offline_access {TestDataSeeder.ScopeName}",
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

        Assert.Equal(HttpStatusCode.Redirect, approveResponse.StatusCode);
        Assert.Equal(
            "/device?result=approved",
            approveResponse.Headers.Location?.OriginalString);

        // --- Device side: poll again, now expecting a token. ---
        var (pollStatus, pollBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code",
            ["device_code"] = deviceCode,
            ["client_id"] = TestDataSeeder.DeviceClientId,
            ["client_secret"] = TestDataSeeder.DeviceClientSecret,
        });

        Assert.Equal(HttpStatusCode.OK, pollStatus);
        var accessToken = pollBody.GetProperty("access_token").GetString();
        Assert.False(string.IsNullOrEmpty(accessToken));
        Assert.False(string.IsNullOrEmpty(pollBody.GetProperty("refresh_token").GetString()));
        Assert.False(string.IsNullOrEmpty(pollBody.GetProperty("id_token").GetString()));
        Assert.InRange(pollBody.GetProperty("expires_in").GetInt32(), 2_690, 2_700);

        var grantedScopes = pollBody.GetProperty("scope").GetString()!
            .Split(' ', StringSplitOptions.RemoveEmptyEntries);
        Assert.Contains("openid", grantedScopes);
        Assert.Contains("profile", grantedScopes);
        Assert.Contains("email", grantedScopes);
        Assert.Contains("offline_access", grantedScopes);
        Assert.Contains(TestDataSeeder.ScopeName, grantedScopes);

        using var userInfoRequest = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        userInfoRequest.Headers.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
        using var userInfoResponse = await client.SendAsync(userInfoRequest);

        Assert.Equal(HttpStatusCode.OK, userInfoResponse.StatusCode);
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

        Assert.Equal(HttpStatusCode.Redirect, denyResponse.StatusCode);
        Assert.Equal(
            "/device?result=denied",
            denyResponse.Headers.Location?.OriginalString);

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
