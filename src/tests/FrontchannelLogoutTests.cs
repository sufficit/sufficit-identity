using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.STS.Logout;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

[Collection(StsCollection.Name)]
public sealed class FrontchannelLogoutTests
{
    private readonly SufficitIdentityTestFactory _factory;

    public FrontchannelLogoutTests(SufficitIdentityTestFactory factory) => _factory = factory;

    [Fact]
    public async Task One_time_context_renders_registered_rp_iframes_without_inline_script()
    {
        const string contextId = "frontchannel-test-context";
        await using (var scope = _factory.Services.CreateAsyncScope())
        {
            var cache = scope.ServiceProvider.GetRequiredService<IDistributedCache>();
            await cache.SetStringAsync(
                "oidc:frontchannel-logout:" + contextId,
                "[\"https://rp.tests.local/logout?existing=1\"]");
        }

        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });

        using var response = await client.GetAsync(
            "/connect/frontchannel-logout?logout_context=" + contextId);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Contains(
            "frame-src https://rp.tests.local",
            response.Headers.GetValues("Content-Security-Policy").Single(),
            StringComparison.Ordinal);

        var html = await response.Content.ReadAsStringAsync();
        Assert.Contains(
            "src=\"https://rp.tests.local/logout?existing=1\"",
            html,
            StringComparison.Ordinal);
        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);

        using var replay = await client.GetAsync(
            "/connect/frontchannel-logout?logout_context=" + contextId);
        Assert.Equal(HttpStatusCode.Redirect, replay.StatusCode);
        Assert.Equal("/", replay.Headers.Location?.OriginalString);
    }

    [Fact]
    public async Task Dispatcher_resolves_frontchannel_uri_from_canonical_client_metadata()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>());
        await ((IAsyncLifetime)factory).InitializeAsync();

        string contextId;
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var applications = scope.ServiceProvider
                .GetRequiredService<IOpenIddictApplicationManager>();
            var authorizations = scope.ServiceProvider
                .GetRequiredService<IOpenIddictAuthorizationManager>();
            var user = await users.FindByNameAsync(TestDataSeeder.DefaultUsername)
                ?? throw new InvalidOperationException("Seeded user missing.");

            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = "frontchannel-test-client",
                ClientType = OpenIddictConstants.ClientTypes.Public,
                ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
            };
            descriptor.Settings["frontchannel_logout_uri"] =
                "https://rp.tests.local/frontchannel-logout?existing=1";
            descriptor.Settings["frontchannel_logout_session_required"] = "true";
            var application = await applications.CreateAsync(descriptor);
            var applicationId = await applications.GetIdAsync(application)
                ?? throw new InvalidOperationException("Application id missing.");
            await authorizations.CreateAsync(new OpenIddictAuthorizationDescriptor
            {
                ApplicationId = applicationId,
                CreationDate = DateTimeOffset.UtcNow,
                Status = OpenIddictConstants.Statuses.Valid,
                Subject = user.Id,
                Type = OpenIddictConstants.AuthorizationTypes.Permanent,
            });

            var dispatcher = scope.ServiceProvider
                .GetRequiredService<IFrontchannelLogoutDispatcher>();
            contextId = await dispatcher.PrepareAsync(
                    user.Id,
                    sessionId: "session-123",
                    CancellationToken.None)
                ?? throw new InvalidOperationException("Logout context missing.");
        }

        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });
        using var response = await client.GetAsync(
            "/connect/frontchannel-logout?logout_context=" + contextId);
        var html = await response.Content.ReadAsStringAsync();
        var decodedHtml = WebUtility.HtmlDecode(html);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains(
            "https://rp.tests.local/frontchannel-logout?existing=1",
            decodedHtml,
            StringComparison.Ordinal);
        Assert.Contains(
            "iss=https%3A%2F%2Fsts.tests.local",
            decodedHtml,
            StringComparison.Ordinal);
        Assert.Contains("sid=session-123", decodedHtml, StringComparison.Ordinal);
    }
}
