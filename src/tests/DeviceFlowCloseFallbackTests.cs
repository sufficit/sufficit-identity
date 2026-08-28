using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.STS;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// The device close fallback URL is per-client registration data in the
/// database (<c>device_close_fallback_url</c> extension metadata), never a
/// deployment setting and never a site baked into the generic UI. These tests
/// pin the three legs of that contract: the policy that validates what a
/// client may register, the ticket that carries it to the approved terminal
/// page, and the approval redirect that only a registered client gets.
/// </summary>
[Collection(StsCollection.Name)]
public sealed class DeviceFlowCloseFallbackTests
{
    private readonly SufficitIdentityTestFactory _factory;

    public DeviceFlowCloseFallbackTests(SufficitIdentityTestFactory factory) =>
        _factory = factory;

    [Theory]
    [InlineData("https://client.example/done", true)]
    [InlineData("  https://client.example/done  ", true)]
    [InlineData("http://client.example/done", false, "device_close_fallback_https_required")]
    [InlineData("client.example/done", false, "device_close_fallback_https_required")]
    [InlineData("https://client.example/done#top", false, "device_close_fallback_fragment")]
    [InlineData("https://user:pass@client.example/done", false, "device_close_fallback_userinfo")]
    [InlineData("javascript:alert(1)", false, "device_close_fallback_https_required")]
    public void Policy_validates_shape_only_and_requires_https(
        string candidate, bool valid, string? reasonCode = null)
    {
        var result = DeviceCloseFallbackPolicy.TryValidateRegistration(
            candidate,
            out var normalized,
            out var code,
            out _);

        Assert.Equal(valid, result);
        if (valid)
        {
            Assert.Equal(candidate.Trim(), normalized);
        }
        else
        {
            Assert.Equal(reasonCode, code);
        }
    }

    [Fact]
    public void Policy_read_drops_a_registration_that_no_longer_validates()
    {
        var properties = new Dictionary<string, JsonElement>
        {
            [DeviceCloseFallbackPolicy.PropertyKey] =
                JsonSerializer.SerializeToElement("http://stale.example/done"),
        };

        Assert.Null(DeviceCloseFallbackPolicy.Read(properties));
        Assert.Null(DeviceCloseFallbackPolicy.Read(null));
    }

    [Fact]
    public void Ticket_round_trips_and_rejects_tampering()
    {
        var tickets = new DataProtectionDeviceCloseFallbackTicketService(
            new EphemeralDataProtectionProvider());

        var ticket = tickets.Protect("https://client.example/done");

        Assert.Equal("https://client.example/done", tickets.Unprotect(ticket));
        Assert.Null(tickets.Unprotect(ticket + "tampered"));
        Assert.Null(tickets.Unprotect(null));
    }

    [Fact]
    public async Task Approved_redirect_carries_a_close_ticket_for_the_registered_client()
    {
        var username = "device-close-approved@example.net";
        string userCode;
        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider
                .GetRequiredService<Microsoft.AspNetCore.Identity.UserManager<Sufficit.Identity.Core.Entities.ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(userManager, username, "Passw0rd!123");
        }

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
                ["scope"] = "openid profile email",
            });
        Assert.Equal(HttpStatusCode.OK, authStatus);
        userCode = authBody.GetProperty("user_code").GetString()!;

        await TestOnlyEndpoints.SignInAsync(client, username);
        var antiforgeryToken = await TestOnlyEndpoints.GetAntiforgeryTokenAsync(client);

        using var approveResponse = await client.PostAsync("/connect/device",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["user_code"] = userCode,
                ["approved"] = "true",
                ["__RequestVerificationToken"] = antiforgeryToken,
            }));

        var approvedLocation = approveResponse.Headers.Location?.OriginalString;
        Assert.NotNull(approvedLocation);
        Assert.StartsWith("/device?result=approved", approvedLocation);

        // The seeded device client registered a fallback, so the redirect
        // carries it as a server-minted ticket — never a raw editable URL.
        var query = QueryHelpers.ParseQuery(
            new Uri("http://localhost" + approvedLocation).Query);
        var closeTickets = _factory.Services
            .GetRequiredService<IDeviceCloseFallbackTicketService>();
        Assert.Equal(
            "https://device-client.example/done",
            closeTickets.Unprotect(query["close_ticket"].ToString()));
    }

    [Fact]
    public async Task Denied_redirect_carries_no_close_ticket_even_when_registered()
    {
        var username = "device-close-denied@example.net";
        string userCode;
        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider
                .GetRequiredService<Microsoft.AspNetCore.Identity.UserManager<Sufficit.Identity.Core.Entities.ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(userManager, username, "Passw0rd!123");
        }

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
                ["scope"] = "openid profile email",
            });
        Assert.Equal(HttpStatusCode.OK, authStatus);
        userCode = authBody.GetProperty("user_code").GetString()!;

        await TestOnlyEndpoints.SignInAsync(client, username);
        var antiforgeryToken = await TestOnlyEndpoints.GetAntiforgeryTokenAsync(client);

        using var denyResponse = await client.PostAsync("/connect/device",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["user_code"] = userCode,
                ["approved"] = "false",
                ["__RequestVerificationToken"] = antiforgeryToken,
            }));

        // Denied stays put: the user may retry, so the tab must not redirect.
        Assert.Equal("/device?result=denied", denyResponse.Headers.Location?.OriginalString);
    }

    [Fact]
    public void Device_terminal_page_binds_the_fallback_from_the_server_ticket()
    {
        var repository = new DirectoryInfo(AppContext.BaseDirectory);
        while (repository is not null
            && !File.Exists(Path.Combine(repository.FullName, "Sufficit.Identity.sln")))
            repository = repository.Parent;
        Assert.True(repository is not null, "repository root not found");

        var page = File.ReadAllText(Path.Combine(
            repository!.FullName,
            "src", "ui", "Sufficit.Identity.UI", "Pages", "Device", "UserCode.razor"));

        // The attribute comes from the ticket the STS minted against the
        // client's registration; nothing site-specific lives in the UI.
        Assert.Contains(
            "data-device-close-fallback-url=\"@CloseFallbackUrl\"",
            page);
        Assert.DoesNotContain("sufficit.com.br", page, StringComparison.OrdinalIgnoreCase);
    }
}
