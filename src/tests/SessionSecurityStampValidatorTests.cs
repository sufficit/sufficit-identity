using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.STS;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// The application cookie must lose access as soon as the security stamp
/// rotates, without paying a principal rebuild and ticket write on every
/// request while nothing about the user changed.
/// </summary>
[Collection(StsCollection.Name)]
public sealed class SessionSecurityStampValidatorTests(
    SufficitIdentityTestFactory factory)
{
    [Fact]
    public void Application_cookie_uses_the_session_validator()
    {
        using var scope = factory.Services.CreateScope();

        Assert.IsType<SessionSecurityStampValidator>(
            scope.ServiceProvider.GetRequiredService<ISecurityStampValidator>());
    }

    [Fact]
    public async Task Unchanged_user_is_accepted_without_rebuild_or_renewal()
    {
        var ticket = await IssueTicketAsync();

        var context = await ValidateAsync(ticket);

        Assert.Same(ticket.Principal, context.Principal);
        Assert.False(context.ShouldRenew);
    }

    [Fact]
    public async Task Rotated_security_stamp_rejects_the_session_immediately()
    {
        var ticket = await IssueTicketAsync();
        await MutateUserAsync(ticket, (users, user) => users.UpdateSecurityStampAsync(user));

        var context = await ValidateAsync(ticket);

        Assert.Null(context.Principal);
    }

    [Fact]
    public async Task User_change_without_stamp_rotation_refreshes_the_principal()
    {
        var ticket = await IssueTicketAsync();
        await MutateUserAsync(ticket, (users, user) =>
            users.AddClaimAsync(user, new Claim("test:refresh", "granted")));

        var context = await ValidateAsync(ticket);

        Assert.True(context.ShouldRenew);
        Assert.Equal("granted", context.Principal?.FindFirst("test:refresh")?.Value);
    }

    [Fact]
    public async Task Principal_older_than_the_refresh_interval_is_rebuilt()
    {
        var ticket = await IssueTicketAsync();
        ticket.Properties.IssuedUtc = DateTimeOffset.UtcNow.AddHours(-2);

        var context = await ValidateAsync(ticket);

        Assert.True(context.ShouldRenew);
        Assert.NotSame(ticket.Principal, context.Principal);
    }

    [Fact]
    public async Task Ticket_without_observed_version_is_refreshed_once()
    {
        var ticket = await IssueTicketAsync();
        ticket.Properties.Items.Remove(SessionSecurityStampValidator.UserVersionItem);

        var first = await ValidateAsync(ticket);
        Assert.True(first.ShouldRenew);

        var renewed = new AuthenticationTicket(
            first.Principal!,
            first.Properties,
            ticket.AuthenticationScheme);
        var second = await ValidateAsync(renewed);
        Assert.False(second.ShouldRenew);
    }

    private async Task<AuthenticationTicket> IssueTicketAsync()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        SetHttpContext(services);
        var users = services.GetRequiredService<UserManager<ApplicationUser>>();
        var email = $"stamp-validator-{Guid.NewGuid():N}@example.test";
        var user = new ApplicationUser
        {
            UserName = email,
            Email = email,
            EmailConfirmed = true,
        };
        Assert.True((await users.CreateAsync(
            user, TestDataSeeder.DefaultPassword)).Succeeded);

        var principal = await services
            .GetRequiredService<SignInManager<ApplicationUser>>()
            .CreateUserPrincipalAsync(user);
        var properties = new AuthenticationProperties
        {
            IssuedUtc = DateTimeOffset.UtcNow,
        };
        properties.Items[SessionSecurityStampValidator.UserVersionItem] =
            user.ConcurrencyStamp;
        return new AuthenticationTicket(
            principal,
            properties,
            IdentityConstants.ApplicationScheme);
    }

    private async Task MutateUserAsync(
        AuthenticationTicket ticket,
        Func<UserManager<ApplicationUser>, ApplicationUser, Task<IdentityResult>> mutation)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();
        var user = await users.GetUserAsync(ticket.Principal);
        Assert.NotNull(user);
        Assert.True((await mutation(users, user)).Succeeded);
    }

    private async Task<CookieValidatePrincipalContext> ValidateAsync(
        AuthenticationTicket ticket)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var httpContext = SetHttpContext(services);
        var context = new CookieValidatePrincipalContext(
            httpContext,
            new AuthenticationScheme(
                IdentityConstants.ApplicationScheme,
                displayName: null,
                typeof(CookieAuthenticationHandler)),
            new CookieAuthenticationOptions { SlidingExpiration = true },
            ticket);

        await services.GetRequiredService<ISecurityStampValidator>()
            .ValidateAsync(context);
        return context;
    }

    private static HttpContext SetHttpContext(IServiceProvider services)
    {
        var context = new DefaultHttpContext
        {
            RequestServices = services,
        };
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("sts.tests.local");
        services.GetRequiredService<IHttpContextAccessor>().HttpContext = context;
        return context;
    }
}
