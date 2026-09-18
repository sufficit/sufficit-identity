using System.Globalization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Sessions;
using Sufficit.Identity.STS;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// The stamp read can only be skipped while a change-notification channel is
/// connected: a node that cannot hear about a revocation performed elsewhere
/// must keep reading (A9, closes V7). These tests pin both halves of that rule,
/// including the trade-off it buys — inside the window, on this node, a
/// rotation performed directly in the store is not seen until the window ends
/// or an invalidation arrives.
/// </summary>
[Collection(StsCollection.Name)]
public sealed class SessionValidityCacheIntegrationTests(
    SufficitIdentityTestFactory factory)
{
    [Fact]
    public async Task Without_a_connected_channel_the_stamp_is_read_every_time()
    {
        var ticket = await IssueTicketAsync(verifiedAt: DateTimeOffset.UtcNow);
        await RotateSecurityStampAsync(ticket);

        var context = await ValidateAsync(
            ticket,
            new InMemorySessionValidityCache(TimeSpan.FromSeconds(30)),
            new StubPublisher(Enabled: true, Connected: false));

        Assert.Null(context.Principal);
    }

    [Fact]
    public async Task With_a_connected_channel_a_recently_verified_session_skips_the_read()
    {
        var ticket = await IssueTicketAsync(verifiedAt: DateTimeOffset.UtcNow);
        var cache = new InMemorySessionValidityCache(TimeSpan.FromSeconds(30));
        cache.MarkVerified(await SubjectOfAsync(ticket));

        // The store says the session is gone; the cache says it was verified a
        // moment ago and nothing invalidated it, so this request is served
        // without touching the user row.
        await RotateSecurityStampAsync(ticket);

        var context = await ValidateAsync(
            ticket,
            cache,
            new StubPublisher(Enabled: true, Connected: true));

        Assert.NotNull(context.Principal);
    }

    [Fact]
    public async Task An_invalidation_brings_the_read_back_immediately()
    {
        var ticket = await IssueTicketAsync(verifiedAt: DateTimeOffset.UtcNow);
        var cache = new InMemorySessionValidityCache(TimeSpan.FromSeconds(30));
        var subject = await SubjectOfAsync(ticket);
        cache.MarkVerified(subject);
        await RotateSecurityStampAsync(ticket);

        // What a revocation on any node ends up calling, locally or through
        // the notification bridge.
        cache.Invalidate(subject);

        var context = await ValidateAsync(
            ticket,
            cache,
            new StubPublisher(Enabled: true, Connected: true));

        Assert.Null(context.Principal);
    }

    private async Task<string> SubjectOfAsync(AuthenticationTicket ticket)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();
        var user = await users.GetUserAsync(ticket.Principal);
        Assert.NotNull(user);
        return user!.Id;
    }

    private async Task<AuthenticationTicket> IssueTicketAsync(DateTimeOffset verifiedAt)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        SetHttpContext(services);
        var users = services.GetRequiredService<UserManager<ApplicationUser>>();
        var email = $"validity-cache-{Guid.NewGuid():N}@example.test";
        var user = new ApplicationUser
        {
            UserName = email,
            Email = email,
            EmailConfirmed = true,
        };
        Assert.True((await users.CreateAsync(
            user,
            TestDataSeeder.DefaultPassword)).Succeeded);

        var principal = await services
            .GetRequiredService<SignInManager<ApplicationUser>>()
            .CreateUserPrincipalAsync(user);
        var properties = new AuthenticationProperties
        {
            IssuedUtc = DateTimeOffset.UtcNow,
        };
        properties.Items[SessionSecurityStampValidator.UserVersionItem] =
            user.ConcurrencyStamp;
        properties.Items[SessionSecurityStampValidator.VerifiedAtItem] =
            verifiedAt.ToString("O", CultureInfo.InvariantCulture);
        return new AuthenticationTicket(
            principal,
            properties,
            IdentityConstants.ApplicationScheme);
    }

    private async Task RotateSecurityStampAsync(AuthenticationTicket ticket)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();
        var user = await users.GetUserAsync(ticket.Principal);
        Assert.NotNull(user);
        Assert.True((await users.UpdateSecurityStampAsync(user!)).Succeeded);
    }

    private async Task<CookieValidatePrincipalContext> ValidateAsync(
        AuthenticationTicket ticket,
        ISessionValidityCache cache,
        IUserSecurityChangePublisher publisher)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var httpContext = SetHttpContext(services);
        var validator = new SessionSecurityStampValidator(
            services.GetRequiredService<IOptions<SecurityStampValidatorOptions>>(),
            services.GetRequiredService<SignInManager<ApplicationUser>>(),
            services.GetRequiredService<ILoggerFactory>(),
            services.GetRequiredService<SufficitIdentityOptions>(),
            cache,
            publisher);

        var context = new CookieValidatePrincipalContext(
            httpContext,
            new AuthenticationScheme(
                IdentityConstants.ApplicationScheme,
                displayName: null,
                typeof(CookieAuthenticationHandler)),
            new CookieAuthenticationOptions { SlidingExpiration = true },
            ticket);

        await validator.ValidateAsync(context);
        return context;
    }

    private static HttpContext SetHttpContext(IServiceProvider services)
    {
        var httpContext = new DefaultHttpContext { RequestServices = services };
        services.GetRequiredService<IHttpContextAccessor>().HttpContext = httpContext;
        return httpContext;
    }

    private sealed record StubPublisher(bool Enabled, bool Connected)
        : IUserSecurityChangePublisher
    {
        public Task<bool> PublishAsync(string userId, CancellationToken cancellationToken) =>
            Task.FromResult(Connected);
    }
}
