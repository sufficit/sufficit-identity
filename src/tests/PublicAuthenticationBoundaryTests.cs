using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.STS.Controllers;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

[Collection(StsCollection.Name)]
public sealed class PublicAuthenticationBoundaryTests(
    SufficitIdentityTestFactory factory)
{
    [Fact]
    public async Task Registration_confirmation_and_password_reset_round_trip()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var accounts = services.GetRequiredService<IAccountOnboardingService>();
        var users = services.GetRequiredService<UserManager<ApplicationUser>>();
        SetHttpContext(services);

        var email = $"onboarding-{Guid.NewGuid():N}@example.test";
        var policy = await accounts.GetRegistrationPolicyAsync();
        Assert.True(policy.Enabled);
        Assert.False(policy.RequiresUserName);

        var registration = await accounts.RegisterAsync(
            new AccountRegistrationCommand(
                null,
                email,
                TestDataSeeder.DefaultPassword));
        Assert.True(registration.Succeeded);
        Assert.True(registration.ConfirmationMessageSent);
        Assert.Empty(registration.Errors);

        var user = await users.FindByEmailAsync(email);
        Assert.NotNull(user);
        Assert.Equal(email, user.UserName);
        Assert.False(user.EmailConfirmed);

        var confirmationToken = await users
            .GenerateEmailConfirmationTokenAsync(user);
        var confirmation = await accounts.ConfirmEmailAsync(
            user.Id,
            EncodeToken(confirmationToken));
        Assert.Equal(
            AccountEmailConfirmationStatus.Succeeded,
            confirmation.Status);
        Assert.True((await users.FindByIdAsync(user.Id))!.EmailConfirmed);

        var request = await accounts.RequestPasswordResetAsync(email);
        Assert.True(request.Accepted);
        var resetToken = await users.GeneratePasswordResetTokenAsync(user);
        var encodedResetToken = EncodeToken(resetToken);
        var resetContext = await accounts.GetPasswordResetContextAsync(
            user.Id,
            encodedResetToken);
        var invalidResetContext = await accounts.GetPasswordResetContextAsync(
            user.Id,
            EncodeToken("not-a-password-reset-token"));
        Assert.True(resetContext.IsValid);
        Assert.Equal(email, resetContext.AccountLabel);
        Assert.False(invalidResetContext.IsValid);
        Assert.Null(invalidResetContext.AccountLabel);

        const string newPassword = "An0ther!Str0ng#Password27";
        var reset = await accounts.ResetPasswordAsync(
            new AccountPasswordResetCommand(
                user.Id,
                encodedResetToken,
                newPassword));
        Assert.Equal(AccountPasswordResetStatus.Succeeded, reset.Status);
        Assert.True(await users.CheckPasswordAsync(user, newPassword));
    }

    [Fact]
    public async Task Public_email_requests_do_not_disclose_account_existence()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var accounts = services.GetRequiredService<IAccountOnboardingService>();
        SetHttpContext(services);
        var missing = $"missing-{Guid.NewGuid():N}@example.test";

        var confirmation = await accounts
            .RequestEmailConfirmationAsync(missing);
        var reset = await accounts.RequestPasswordResetAsync(missing);
        var invalidConfirmation = await accounts.ConfirmEmailAsync(null, null);
        var invalidReset = await accounts.GetPasswordResetContextAsync(
            null,
            null);

        Assert.True(confirmation.Accepted);
        Assert.True(reset.Accepted);
        Assert.Equal(
            AccountEmailConfirmationStatus.InvalidRequest,
            invalidConfirmation.Status);
        Assert.False(invalidReset.IsValid);
        Assert.Null(invalidReset.AccountLabel);
    }

    [Fact]
    public async Task Registration_policy_fails_closed_when_disabled()
    {
        using var isolated = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Register:Enabled"] = "false",
            });
        await using var scope = isolated.Services.CreateAsyncScope();
        var accounts = scope.ServiceProvider
            .GetRequiredService<IAccountOnboardingService>();

        var policy = await accounts.GetRegistrationPolicyAsync();
        var registration = await accounts.RegisterAsync(
            new AccountRegistrationCommand(
                null,
                "disabled@example.test",
                TestDataSeeder.DefaultPassword));

        Assert.False(policy.Enabled);
        Assert.False(registration.Succeeded);
        Assert.Contains(
            registration.Errors,
            error => error.Code == "registration-disabled");
    }

    [Fact]
    public async Task Consent_service_projects_protocol_state_without_leaking_it()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var context = SetHttpContext(services);
        context.Request.QueryString = new QueryString(
            "?client_id=test-authcode"
            + "&scope=openid%20profile"
            + "&scope=openid"
            + "&state=opaque-state"
            + "&resource=https%3A%2F%2Fapi.example.test");
        var consent = services
            .GetRequiredService<IAuthorizationConsentService>();

        var result = await consent.GetCurrentAsync();

        Assert.True(result.IsValid);
        Assert.Equal(TestDataSeeder.AuthorizationCodeClientId, result.ClientId);
        Assert.Equal(TestDataSeeder.AuthorizationCodeClientId, result.ClientDisplayName);
        Assert.Equal(new[] { "openid", "profile" }, result.RequestedScopes);
        Assert.Contains(
            result.PassthroughParameters,
            parameter => parameter.Name == "state"
                && parameter.Value == "opaque-state");
        Assert.DoesNotContain(
            result.PassthroughParameters,
            parameter => string.Equals(
                parameter.Name,
                "scope",
                StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task External_sign_in_adapter_fails_closed_without_callback_state()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        SetHttpContext(services);
        var external = services.GetRequiredService<IExternalSignInService>();

        var challenge = await external.CreateChallengeAsync(
            "TestProvider",
            "/account/externallogincallback?returnUrl=%2F");
        var result = await external.CompleteAsync(
            new ClaimsPrincipal(new ClaimsIdentity()));

        Assert.Equal("TestProvider", challenge.AuthenticationScheme);
        Assert.Equal(
            "TestProvider",
            challenge.Properties["LoginProvider"]);
        Assert.Equal(ExternalSignInStatus.Unavailable, result.Status);
    }

    [Theory]
    [InlineData(
        ExternalSignInStatus.AccountLinkRequiresSignIn,
        "error=account_link_requires_signin")]
    [InlineData(
        ExternalSignInStatus.RegistrationDisabled,
        "error=registration_disabled")]
    [InlineData(
        ExternalSignInStatus.RequiresTwoFactor,
        "/account/loginwith2fa")]
    public async Task External_callback_maps_canonical_outcomes(
        ExternalSignInStatus status,
        string expectedLocation)
    {
        var external = new StubExternalSignInService
        {
            Completion = new ExternalSignInResult(status),
        };
        var controller = CreateController(external);

        var action = await controller.Callback(
            "https://offsite.example/redirect",
            CancellationToken.None);

        var redirect = Assert.IsType<RedirectResult>(action);
        Assert.Contains(
            expectedLocation,
            redirect.Url,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "offsite.example",
            redirect.Url,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task External_challenge_preserves_runtime_correlation_properties()
    {
        var external = new StubExternalSignInService
        {
            Challenge = new ExternalSignInChallenge(
                "TestProvider",
                "/account/externallogincallback?returnUrl=%2F",
                new Dictionary<string, string?>
                {
                    ["LoginProvider"] = "TestProvider",
                }),
        };
        var controller = CreateController(external);

        var action = await controller.Challenge(
            "TestProvider",
            "//offsite.example",
            CancellationToken.None);

        var challenge = Assert.IsType<ChallengeResult>(action);
        Assert.Equal("TestProvider", Assert.Single(challenge.AuthenticationSchemes));
        Assert.Equal(
            "TestProvider",
            challenge.Properties!.Items["LoginProvider"]);
        Assert.Equal("/", external.CallbackReturnUrl);
    }

    private static DefaultHttpContext SetHttpContext(
        IServiceProvider services)
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

    private static ExternalLoginController CreateController(
        IExternalSignInService externalSignInService) =>
        new(externalSignInService)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext(),
            },
        };

    private static string EncodeToken(string token) =>
        WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

    private sealed class StubExternalSignInService : IExternalSignInService
    {
        public ExternalSignInChallenge Challenge { get; init; } = new(
            "TestProvider",
            "/account/externallogincallback",
            new Dictionary<string, string?>());

        public ExternalSignInResult Completion { get; init; } = new(
            ExternalSignInStatus.Unavailable);

        public string? CallbackReturnUrl { get; private set; }

        public Task<ExternalSignInChallenge> CreateChallengeAsync(
            string provider,
            string callbackUri,
            CancellationToken cancellationToken = default)
        {
            CallbackReturnUrl = QueryHelpers.ParseQuery(
                new Uri("https://local.test" + callbackUri).Query)[
                    "returnUrl"];
            return Task.FromResult(Challenge);
        }

        public Task<ExternalSignInResult> CompleteAsync(
            ClaimsPrincipal currentPrincipal,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(Completion);
    }
}
