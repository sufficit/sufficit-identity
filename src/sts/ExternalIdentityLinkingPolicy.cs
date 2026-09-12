using Microsoft.Extensions.Logging;
using Sufficit.Identity.Application.Accounts;

namespace Sufficit.Identity.STS;

/// <summary>
/// Configuration-driven <see cref="IExternalIdentityLinkingPolicy"/>: the
/// provider's own <c>email_verified</c> assertion, an operator allow-list, and
/// a deny-list, in that order.
/// </summary>
/// <remarks>
/// The decision deliberately contains no provider names. Which schemes exist is
/// deployment configuration, and hard-coding "this provider verifies addresses"
/// would be wrong the day the provider changes its behaviour — or the day a
/// deployment federates something the code never heard of.
/// </remarks>
public sealed class ConfigurableExternalIdentityLinkingPolicy(
    ExternalIdentityOptions options,
    ILogger<ConfigurableExternalIdentityLinkingPolicy> logger)
    : IExternalIdentityLinkingPolicy
{
    public ValueTask<ExternalIdentityLinkingEvaluation> EvaluateAsync(
        ExternalIdentityAssertion assertion,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assertion);
        cancellationToken.ThrowIfCancellationRequested();

        if (options.RegistrationDeniedProviders.Contains(assertion.Provider))
        {
            logger.LogInformation(
                "External provider {Provider} is not allowed to bootstrap accounts.",
                assertion.Provider);
            return Evaluation(
                ExternalIdentityLinkingDecision.Denied,
                "provider-registration-denied");
        }

        // The protection is opt-out, not opt-in: a deployment that turns it off
        // is choosing to accept unproven addresses, and the posture check
        // reports that choice.
        if (!options.RequireVerifiedEmail)
        {
            return Evaluation(
                ExternalIdentityLinkingDecision.Immediate,
                "verification-not-required");
        }

        if (assertion.EmailAssertedVerified)
        {
            return Evaluation(
                ExternalIdentityLinkingDecision.Immediate,
                "provider-asserted-verified");
        }

        if (options.TrustedEmailProviders.Contains(assertion.Provider))
        {
            return Evaluation(
                ExternalIdentityLinkingDecision.Immediate,
                "provider-trusted-by-configuration");
        }

        logger.LogInformation(
            "External provider {Provider} did not assert a verified email; "
            + "requiring proof of possession before creating an account.",
            assertion.Provider);
        return Evaluation(
            ExternalIdentityLinkingDecision.RequiresEmailVerification,
            "email-not-asserted-verified");
    }

    private static ValueTask<ExternalIdentityLinkingEvaluation> Evaluation(
        ExternalIdentityLinkingDecision decision,
        string reason) =>
        ValueTask.FromResult(
            new ExternalIdentityLinkingEvaluation(decision, reason));
}
