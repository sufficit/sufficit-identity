using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.STS;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Account pre-hijacking through an external provider that does not verify
/// email addresses.
/// </summary>
/// <remarks>
/// The attack these tests pin: an attacker registers the victim's address at a
/// provider that never asserts <c>email_verified</c> and signs in. If that
/// creates a local account bound to the attacker's external identity, the
/// victim later proves the address — through registration recovery or a
/// confirmation resend — and the attacker's binding survives, giving them a
/// session on the victim's account.
/// </remarks>
[Collection(StsCollection.Name)]
public sealed class ExternalIdentityLinkingTests(
    SufficitIdentityTestFactory factory)
{
    private const string UnverifyingProvider = "ProviderWithoutEmailProof";

    [Fact]
    public async Task Provider_asserted_verified_email_links_immediately()
    {
        var evaluation = await EvaluateAsync(
            new ExternalIdentityOptions(),
            emailAssertedVerified: true);

        Assert.Equal(
            ExternalIdentityLinkingDecision.Immediate,
            evaluation.Decision);
    }

    [Fact]
    public async Task Unverified_email_requires_proof_before_any_account_exists()
    {
        var evaluation = await EvaluateAsync(
            new ExternalIdentityOptions(),
            emailAssertedVerified: false);

        Assert.Equal(
            ExternalIdentityLinkingDecision.RequiresEmailVerification,
            evaluation.Decision);
    }

    [Fact]
    public async Task Operator_may_trust_a_named_provider_without_the_claim()
    {
        var options = new ExternalIdentityOptions
        {
            TrustedEmailProviders = { UnverifyingProvider },
        };

        var evaluation = await EvaluateAsync(
            options,
            emailAssertedVerified: false);

        Assert.Equal(
            ExternalIdentityLinkingDecision.Immediate,
            evaluation.Decision);
    }

    [Fact]
    public async Task Denied_provider_may_never_bootstrap_an_account()
    {
        var options = new ExternalIdentityOptions
        {
            RegistrationDeniedProviders = { UnverifyingProvider },
        };

        // Even a provider-asserted verified address does not override a deny.
        var evaluation = await EvaluateAsync(
            options,
            emailAssertedVerified: true);

        Assert.Equal(
            ExternalIdentityLinkingDecision.Denied,
            evaluation.Decision);
    }

    [Fact]
    public async Task Disabling_the_requirement_restores_immediate_linking()
    {
        var options = new ExternalIdentityOptions
        {
            RequireVerifiedEmail = false,
        };

        var evaluation = await EvaluateAsync(
            options,
            emailAssertedVerified: false);

        Assert.Equal(
            ExternalIdentityLinkingDecision.Immediate,
            evaluation.Decision);
    }

    [Fact]
    public async Task Composed_host_requires_proof_by_default()
    {
        // Wiring test: the protection is only real if the composed host
        // actually resolves the policy and defaults to requiring proof. A
        // registration that silently went missing would leave every unit test
        // above passing while the running server stayed vulnerable.
        await using var scope = factory.Services.CreateAsyncScope();
        var policy = scope.ServiceProvider
            .GetRequiredService<IExternalIdentityLinkingPolicy>();

        var evaluation = await policy.EvaluateAsync(
            new ExternalIdentityAssertion(
                UnverifyingProvider,
                "provider-subject",
                "Provider Without Email Proof",
                "victim@tests.local",
                EmailAssertedVerified: false));

        Assert.Equal(
            ExternalIdentityLinkingDecision.RequiresEmailVerification,
            evaluation.Decision);
    }

    [Fact]
    public async Task Pending_link_ticket_is_single_use()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var store = scope.ServiceProvider
            .GetRequiredService<PendingExternalIdentityStore>();
        var pending = new PendingExternalIdentity(
            UnverifyingProvider,
            Guid.NewGuid().ToString("N"),
            "Provider Without Email Proof",
            $"single-use-{Guid.NewGuid():N}@tests.local",
            PictureUrl: null);

        var ticket = await store.CreateAsync(pending, TimeSpan.FromMinutes(10));

        var first = await store.RedeemAsync(ticket);
        var second = await store.RedeemAsync(ticket);

        Assert.NotNull(first);
        Assert.Equal(pending.Email, first!.Email);
        Assert.Null(second);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-real-ticket")]
    public async Task Unknown_ticket_redeems_to_nothing(string? ticket)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var store = scope.ServiceProvider
            .GetRequiredService<PendingExternalIdentityStore>();

        Assert.Null(await store.RedeemAsync(ticket));
    }

    [Fact]
    public async Task Confirming_an_unproven_address_drops_external_bindings()
    {
        // Reproduces the data left behind by the vulnerable flow: an account
        // created unconfirmed with an external login already attached. When the
        // rightful owner proves the address, that binding must not survive.
        await using var scope = factory.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var users = services.GetRequiredService<UserManager<ApplicationUser>>();
        var onboarding = services
            .GetRequiredService<IAccountOnboardingService>();

        var email = $"pre-hijack-{Guid.NewGuid():N}@tests.local";
        var user = new ApplicationUser
        {
            UserName = email,
            Email = email,
            EmailConfirmed = false,
        };
        Assert.True((await users.CreateAsync(user)).Succeeded);
        Assert.True((await users.AddLoginAsync(
            user,
            new UserLoginInfo(
                UnverifyingProvider,
                "attacker-subject",
                UnverifyingProvider))).Succeeded);
        Assert.Single(await users.GetLoginsAsync(user));

        var token = await users.GenerateEmailConfirmationTokenAsync(user);
        var result = await onboarding.ConfirmEmailAsync(
            user.Id,
            EncodeToken(token));

        Assert.Equal(AccountEmailConfirmationStatus.Succeeded, result.Status);
        var reloaded = await users.FindByIdAsync(user.Id);
        Assert.NotNull(reloaded);
        Assert.True(await users.IsEmailConfirmedAsync(reloaded!));
        Assert.Empty(await users.GetLoginsAsync(reloaded!));
    }

    [Fact]
    public async Task Confirming_a_proven_address_keeps_external_bindings()
    {
        // The counterpart: an account whose address was already proven keeps
        // its links. Confirming again must not be a way to unlink a provider.
        await using var scope = factory.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var users = services.GetRequiredService<UserManager<ApplicationUser>>();
        var onboarding = services
            .GetRequiredService<IAccountOnboardingService>();

        var email = $"already-proven-{Guid.NewGuid():N}@tests.local";
        var user = new ApplicationUser
        {
            UserName = email,
            Email = email,
            EmailConfirmed = true,
        };
        Assert.True((await users.CreateAsync(user)).Succeeded);
        Assert.True((await users.AddLoginAsync(
            user,
            new UserLoginInfo(
                UnverifyingProvider,
                "legitimate-subject",
                UnverifyingProvider))).Succeeded);

        var token = await users.GenerateEmailConfirmationTokenAsync(user);
        await onboarding.ConfirmEmailAsync(user.Id, EncodeToken(token));

        var reloaded = await users.FindByIdAsync(user.Id);
        Assert.NotNull(reloaded);
        Assert.Single(await users.GetLoginsAsync(reloaded!));
    }

    private static async Task<ExternalIdentityLinkingEvaluation> EvaluateAsync(
        ExternalIdentityOptions options,
        bool emailAssertedVerified)
    {
        var policy = new ConfigurableExternalIdentityLinkingPolicy(
            options,
            NullLogger<ConfigurableExternalIdentityLinkingPolicy>.Instance);
        return await policy.EvaluateAsync(new ExternalIdentityAssertion(
            UnverifyingProvider,
            "provider-subject",
            "Provider Without Email Proof",
            "victim@tests.local",
            emailAssertedVerified));
    }

    private static string EncodeToken(string token) =>
        Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(
            System.Text.Encoding.UTF8.GetBytes(token));
}
