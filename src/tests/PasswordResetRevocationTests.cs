using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Tests.Infrastructure;
using System.Text;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

/// <summary>
/// A password reset is the account-recovery path, so it must not leave
/// previously issued OAuth credentials usable: rotating the security stamp
/// invalidates auth cookies, but refresh tokens and authorizations survive it
/// unless they are revoked explicitly.
/// </summary>
[Collection(StsCollection.Name)]
public sealed class PasswordResetRevocationTests(
    SufficitIdentityTestFactory factory)
{
    [Fact]
    public async Task Password_reset_revokes_previously_issued_tokens()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        SetHttpContext(services);

        var accounts = services.GetRequiredService<IAccountOnboardingService>();
        var users = services.GetRequiredService<UserManager<ApplicationUser>>();
        var applications = services
            .GetRequiredService<IOpenIddictApplicationManager>();
        var authorizations = services
            .GetRequiredService<IOpenIddictAuthorizationManager>();
        var tokens = services.GetRequiredService<IOpenIddictTokenManager>();

        // A confirmed account with an active refresh token, as if the user had
        // signed in before the compromise.
        var email = $"reset-revocation-{Guid.NewGuid():N}@example.test";
        var user = new ApplicationUser
        {
            UserName = email,
            Email = email,
            EmailConfirmed = true,
        };
        Assert.True((await users.CreateAsync(user, TestDataSeeder.DefaultPassword))
            .Succeeded);

        var application = await applications.FindByClientIdAsync(
                TestDataSeeder.AuthorizationCodeClientId)
            ?? throw new InvalidOperationException("Seeded application is missing.");
        var applicationId = await applications.GetIdAsync(application)
            ?? throw new InvalidOperationException("Application has no identifier.");

        var authorizationDescriptor = new OpenIddictAuthorizationDescriptor
        {
            ApplicationId = applicationId,
            CreationDate = DateTimeOffset.UtcNow,
            Status = Statuses.Valid,
            Subject = user.Id,
            Type = AuthorizationTypes.Permanent,
        };
        authorizationDescriptor.Scopes.Add(TestDataSeeder.ScopeName);
        var authorization = await authorizations.CreateAsync(authorizationDescriptor);
        var authorizationId = await authorizations.GetIdAsync(authorization)
            ?? throw new InvalidOperationException("Authorization has no identifier.");

        var token = await tokens.CreateAsync(new OpenIddictTokenDescriptor
        {
            ApplicationId = applicationId,
            AuthorizationId = authorizationId,
            CreationDate = DateTimeOffset.UtcNow,
            ExpirationDate = DateTimeOffset.UtcNow.AddHours(1),
            Status = Statuses.Valid,
            Subject = user.Id,
            Type = TokenTypeHints.RefreshToken,
        });
        var tokenId = await tokens.GetIdAsync(token)
            ?? throw new InvalidOperationException("Token has no identifier.");

        Assert.Equal(Statuses.Valid, await TokenStatusAsync(tokens, tokenId));

        // Recover the account through the email reset path.
        var resetToken = await users.GeneratePasswordResetTokenAsync(user);
        const string newPassword = "R3covered!Str0ng#Password31";
        var reset = await accounts.ResetPasswordAsync(
            new AccountPasswordResetCommand(
                user.Id,
                EncodeToken(resetToken),
                newPassword));

        Assert.Equal(AccountPasswordResetStatus.Succeeded, reset.Status);
        Assert.True(await users.CheckPasswordAsync(user, newPassword));

        // The pre-reset refresh token must no longer be usable.
        Assert.NotEqual(Statuses.Valid, await TokenStatusAsync(tokens, tokenId));
    }

    private static async Task<string?> TokenStatusAsync(
        IOpenIddictTokenManager manager,
        string id)
    {
        var token = await manager.FindByIdAsync(id);
        return token is null ? null : await manager.GetStatusAsync(token);
    }

    private static string EncodeToken(string token) =>
        WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

    private static void SetHttpContext(IServiceProvider services)
    {
        var context = new DefaultHttpContext
        {
            RequestServices = services,
        };
        // The onboarding service builds absolute callback URLs, so the request
        // needs a scheme and host.
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("sts.tests.local");
        services.GetRequiredService<IHttpContextAccessor>().HttpContext = context;
    }
}
