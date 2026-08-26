using System.Net;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.STS;
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
    public async Task Device_information_has_an_independent_enumeration_bucket()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:RateLimit:DeviceInformationPermitLimit"] = "2",
                ["Sufficit:Identity:RateLimit:DeviceInformationWindowSeconds"] = "60",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        using var first = await client.GetAsync(
            "/connect/device/info?user_code=AAAA-BBBB");
        using var second = await client.GetAsync(
            "/connect/device/info?user_code=CCCC-DDDD");
        using var limited = await client.GetAsync(
            "/connect/device/info?user_code=EEEE-FFFF");

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
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
        var verificationPath = $"/connect/device?user_code={Uri.EscapeDataString(userCode)}&launch_mode=popup";

        using var anonymousResponse = await client.GetAsync(verificationPath);
        Assert.Equal(HttpStatusCode.Redirect, anonymousResponse.StatusCode);
        Assert.Contains(
            "/account/login?ReturnUrl=",
            anonymousResponse.Headers.Location?.OriginalString,
            StringComparison.Ordinal);
        Assert.Contains(
            "launch_mode",
            anonymousResponse.Headers.Location?.OriginalString,
            StringComparison.Ordinal);

        await TestOnlyEndpoints.SignInAsync(client, TestDataSeeder.DefaultUsername);
        using var verificationResponse = await client.GetAsync(verificationPath);

        Assert.Equal(HttpStatusCode.Redirect, verificationResponse.StatusCode);
        var confirmationPath = verificationResponse.Headers.Location?.OriginalString;
        Assert.NotNull(confirmationPath);
        Assert.StartsWith("/device?", confirmationPath);
        Assert.Contains("device_context=", confirmationPath);
        Assert.Contains("launch_mode=popup", confirmationPath);

        var nativeVerificationPath = verificationPath
            .Replace("launch_mode=popup", "launch_mode=app", StringComparison.Ordinal)
            + "&return_uri="
            + Uri.EscapeDataString(TestDataSeeder.DeviceClientNativeReturnUri);
        using var nativeVerificationResponse = await client.GetAsync(nativeVerificationPath);
        Assert.Equal(HttpStatusCode.Redirect, nativeVerificationResponse.StatusCode);
        var nativeConfirmationPath = nativeVerificationResponse.Headers.Location?.OriginalString;
        Assert.NotNull(nativeConfirmationPath);
        Assert.Contains("launch_mode=app", nativeConfirmationPath);
        // The callback never travels in the clear: the STS hands the page an
        // encrypted ticket it minted after checking the client registration.
        Assert.DoesNotContain("return_uri=", nativeConfirmationPath);
        Assert.Contains("return_ticket=", nativeConfirmationPath);
        Assert.Equal(
            TestDataSeeder.DeviceClientNativeReturnUri,
            _factory.Services
                .GetRequiredService<INativeReturnUriTicketService>()
                .Unprotect(QueryHelpers.ParseQuery(
                    new Uri("http://localhost" + nativeConfirmationPath).Query)
                    ["return_ticket"]));

        // A callback the client never registered is refused outright, so the
        // page falls back to the neutral "you can close this tab" ending.
        var foreignVerificationPath = verificationPath
            .Replace("launch_mode=popup", "launch_mode=app", StringComparison.Ordinal)
            + "&return_uri="
            + Uri.EscapeDataString("attacker-app://auth-complete");
        using var foreignVerificationResponse =
            await client.GetAsync(foreignVerificationPath);
        Assert.Equal(HttpStatusCode.Redirect, foreignVerificationResponse.StatusCode);
        var foreignConfirmationPath =
            foreignVerificationResponse.Headers.Location?.OriginalString;
        Assert.NotNull(foreignConfirmationPath);
        Assert.DoesNotContain("return_ticket=", foreignConfirmationPath);
        Assert.DoesNotContain("launch_mode=app", foreignConfirmationPath);

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

        // The browser and polling devices are separate actors in RFC 8628.
        // Keep independent cookie jars so the race below exercises only the
        // device-code transition, not concurrent renewal of a browser cookie.
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var firstPollingClient = _factory.CreateClient();
        var secondPollingClient = _factory.CreateClient();

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

        var returnTickets = _factory.Services
            .GetRequiredService<INativeReturnUriTicketService>();
        using var approveResponse = await client.PostAsync("/connect/device", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["user_code"] = userCode,
                ["approved"] = "true",
                ["launch_mode"] = "app",
                ["return_ticket"] = returnTickets.Protect(
                    TestDataSeeder.DeviceClientNativeReturnUri),
                ["__RequestVerificationToken"] = antiforgeryToken,
            }));

        Assert.Equal(HttpStatusCode.Redirect, approveResponse.StatusCode);
        var approvedLocation = approveResponse.Headers.Location?.OriginalString;
        Assert.NotNull(approvedLocation);
        Assert.StartsWith("/device?result=approved&launch_mode=app&", approvedLocation);
        Assert.Equal(
            TestDataSeeder.DeviceClientNativeReturnUri,
            returnTickets.Unprotect(QueryHelpers.ParseQuery(
                new Uri("http://localhost" + approvedLocation).Query)["return_ticket"]));

        // --- Device side: race two final polls. Mobile/desktop clients often
        // have one timer tick already in flight when approval completes. One
        // request must win and the other must receive invalid_grant; neither
        // may escape the protocol pipeline as a Kestrel 500.
        var redemption = new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code",
            ["device_code"] = deviceCode,
            ["client_id"] = TestDataSeeder.DeviceClientId,
            ["client_secret"] = TestDataSeeder.DeviceClientSecret,
        };
        var polls = await Task.WhenAll(
            firstPollingClient.PostFormAsync("/connect/token", redemption),
            secondPollingClient.PostFormAsync("/connect/token", redemption));

        var (pollStatus, pollBody) = Assert.Single(
            polls, result => result.Status == HttpStatusCode.OK);
        var replay = Assert.Single(
            polls, result => result.Status == HttpStatusCode.BadRequest);

        Assert.Equal(HttpStatusCode.OK, pollStatus);
        Assert.Equal("invalid_grant", replay.Body.GetProperty("error").GetString());
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
        Assert.Contains("identity.mcp", grantedScopes);

        using var userInfoRequest = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        userInfoRequest.Headers.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
        using var userInfoResponse = await firstPollingClient.SendAsync(userInfoRequest);

        Assert.Equal(HttpStatusCode.OK, userInfoResponse.StatusCode);

        // A device code is single-use. Real clients can race one final poll
        // with the successful redemption, so replay must produce a protocol
        // error instead of reaching the sign-in pipeline with a principal
        // whose private device-code identifier has already been removed.
        var (replayStatus, replayBody) = await firstPollingClient.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code",
                ["device_code"] = deviceCode,
                ["client_id"] = TestDataSeeder.DeviceClientId,
                ["client_secret"] = TestDataSeeder.DeviceClientSecret,
            });

        Assert.Equal(HttpStatusCode.BadRequest, replayStatus);
        Assert.Equal("invalid_grant", replayBody.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Approving_the_ai_scope_provisions_personal_ai_access_once()
    {
        var username = $"device-ai-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#13";

        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(userManager, username, password);
        }

        var client = _factory.CreateClient(
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var (authStatus, authBody) = await client.PostFormAsync(
            "/connect/deviceauthorization",
            new Dictionary<string, string>
            {
                ["client_id"] = TestDataSeeder.DeviceClientId,
                ["client_secret"] = TestDataSeeder.DeviceClientSecret,
                ["scope"] = "openid offline_access directives sufficit_ai_openai_bridge",
            });
        Assert.Equal(HttpStatusCode.OK, authStatus);

        await TestOnlyEndpoints.SignInAsync(client, username);
        var antiforgeryToken = await TestOnlyEndpoints.GetAntiforgeryTokenAsync(client);
        using var approveResponse = await client.PostAsync(
            "/connect/device",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["user_code"] = authBody.GetProperty("user_code").GetString()!,
                ["approved"] = "true",
                ["__RequestVerificationToken"] = antiforgeryToken,
            }));
        Assert.Equal(HttpStatusCode.Redirect, approveResponse.StatusCode);

        var (pollStatus, pollBody) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code",
                ["device_code"] = authBody.GetProperty("device_code").GetString()!,
                ["client_id"] = TestDataSeeder.DeviceClientId,
                ["client_secret"] = TestDataSeeder.DeviceClientSecret,
            });
        Assert.Equal(HttpStatusCode.OK, pollStatus);
        var refreshToken = pollBody.GetProperty("refresh_token").GetString();
        Assert.False(string.IsNullOrWhiteSpace(refreshToken));

        var personalDirective = new Claim(
            "directive",
            "aiuser:00000000-0000-0000-0000-000000000000");
        using (var verificationScope = _factory.Services.CreateScope())
        {
            var verificationUserManager = verificationScope.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            var user = await verificationUserManager.FindByNameAsync(username);
            Assert.NotNull(user);
            var claims = await verificationUserManager.GetClaimsAsync(user!);
            Assert.Single(claims, claim =>
                claim.Type == personalDirective.Type
                && claim.Value == personalDirective.Value);

            // Simulate a refresh token issued before scope-based entitlement
            // provisioning existed. Redemption must repair the user's access.
            var removal = await verificationUserManager.RemoveClaimAsync(
                user!,
                personalDirective);
            Assert.True(removal.Succeeded);
        }

        var (refreshStatus, refreshBody) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken!,
                ["client_id"] = TestDataSeeder.DeviceClientId,
                ["client_secret"] = TestDataSeeder.DeviceClientSecret,
            });
        Assert.Equal(HttpStatusCode.OK, refreshStatus);
        Assert.Contains(
            "identity.mcp",
            refreshBody.GetProperty("scope").GetString()!
                .Split(' ', StringSplitOptions.RemoveEmptyEntries));

        using var repairedScope = _factory.Services.CreateScope();
        var repairedUserManager = repairedScope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();
        var repairedUser = await repairedUserManager.FindByNameAsync(username);
        Assert.NotNull(repairedUser);
        var repairedClaims = await repairedUserManager.GetClaimsAsync(repairedUser!);
        Assert.Single(repairedClaims, claim =>
            claim.Type == personalDirective.Type
            && claim.Value == personalDirective.Value);
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
