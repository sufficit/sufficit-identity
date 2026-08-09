using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// A password reset is the flow a victim uses AFTER losing control of the
/// account, so an attacker's already-issued tokens and authorizations must not
/// survive it. ResetPasswordAsync rotates the security stamp (which invalidates
/// cookies) but does not revoke OpenIddict tokens/authorizations on its own.
/// </summary>
[Collection(StsCollection.Name)]
public sealed class PasswordResetRevocationTests(
    SufficitIdentityTestFactory factory)
{
    [Fact]
    public async Task Password_reset_revokes_existing_tokens_and_authorizations()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var accounts = services.GetRequiredService<IAccountOnboardingService>();
        var users = services.GetRequiredService<UserManager<ApplicationUser>>();
        var authorizations = services
            .GetRequiredService<IOpenIddictAuthorizationManager>();
        SetHttpContext(services);

        var email = $"reset-revocation-{Guid.NewGuid():N}@example.test";
        var user = new ApplicationUser
        {
            UserName = email,
            Email = email,
            EmailConfirmed = true,
        };
        Assert.True((await users.CreateAsync(
            user, TestDataSeeder.DefaultPassword)).Succeeded);

        // Stand in for the attacker's live grant: a valid authorization for the
        // account, which is what backs an issued refresh token.
        var applications = services
            .GetRequiredService<IOpenIddictApplicationManager>();
        var application = await applications.FindByClientIdAsync(
            TestDataSeeder.PasswordClientId)
            ?? throw new InvalidOperationException("Seeded application is missing.");
        var applicationId = await applications.GetIdAsync(application)
            ?? throw new InvalidOperationException("Seeded application has no id.");

        await authorizations.CreateAsync(new OpenIddictAuthorizationDescriptor
        {
            ApplicationId = applicationId,
            CreationDate = DateTimeOffset.UtcNow,
            Subject = user.Id,
            Status = OpenIddictConstants.Statuses.Valid,
            Type = OpenIddictConstants.AuthorizationTypes.Permanent,
        });

        var beforeStamp = await users.GetSecurityStampAsync(user);

        var resetToken = await users.GeneratePasswordResetTokenAsync(user);
        var reset = await accounts.ResetPasswordAsync(
            new AccountPasswordResetCommand(
                user.Id,
                EncodeToken(resetToken),
                "An0ther!Str0ng#Password27"));

        Assert.Equal(AccountPasswordResetStatus.Succeeded, reset.Status);

        // Security stamp rotated (cookie invalidation).
        var refreshed = await users.FindByIdAsync(user.Id);
        Assert.NotEqual(beforeStamp, await users.GetSecurityStampAsync(refreshed!));

        // And every authorization for the subject is no longer valid, so the
        // attacker's refresh tokens cannot be redeemed.
        var remaining = new List<object>();
        await foreach (var authorization in authorizations.FindBySubjectAsync(
            user.Id, CancellationToken.None))
        {
            var status = await authorizations.GetStatusAsync(authorization);
            if (string.Equals(
                status,
                OpenIddictConstants.Statuses.Valid,
                StringComparison.Ordinal))
            {
                remaining.Add(authorization);
            }
        }

        Assert.Empty(remaining);
    }

    private static string EncodeToken(string token) =>
        Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(
            System.Text.Encoding.UTF8.GetBytes(token));

    /// <summary>
    /// The onboarding service resolves absolute callback URLs through
    /// IHttpContextAccessor, so an ambient context is required exactly as in
    /// the other onboarding tests.
    /// </summary>
    private static void SetHttpContext(IServiceProvider services)
    {
        var context = new Microsoft.AspNetCore.Http.DefaultHttpContext
        {
            RequestServices = services,
        };
        context.Request.Scheme = "https";
        context.Request.Host =
            new Microsoft.AspNetCore.Http.HostString("sts.tests.local");
        services.GetRequiredService<
            Microsoft.AspNetCore.Http.IHttpContextAccessor>().HttpContext = context;
    }
}
