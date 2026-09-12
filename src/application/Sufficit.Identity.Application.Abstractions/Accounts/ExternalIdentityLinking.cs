namespace Sufficit.Identity.Application.Accounts;

/// <summary>
/// What an external provider asserted about an identity, reduced to the facts
/// that decide whether a local account may be created and bound to it.
/// </summary>
/// <param name="Provider">Authentication scheme name, as registered.</param>
/// <param name="ProviderKey">Stable subject identifier at the provider.</param>
/// <param name="ProviderDisplayName">Human-readable provider name, if any.</param>
/// <param name="Email">The email address carried by the provider principal.</param>
/// <param name="EmailAssertedVerified">
/// Whether the provider itself asserted that it verified control of
/// <paramref name="Email"/>. This is the provider's claim, not a fact: several
/// widely deployed providers never emit it, and one that does may still be
/// asserting something it did not check.
/// </param>
public sealed record ExternalIdentityAssertion(
    string Provider,
    string ProviderKey,
    string? ProviderDisplayName,
    string Email,
    bool EmailAssertedVerified);

/// <summary>
/// Outcome of evaluating an external assertion that does not yet match a local
/// account.
/// </summary>
public enum ExternalIdentityLinkingDecision
{
    /// <summary>
    /// Control of the email address is established. The account may be created
    /// and bound to the external identity in the same request.
    /// </summary>
    Immediate,

    /// <summary>
    /// Control of the email address is NOT established. Nothing may be
    /// persisted until the address is proven, because binding first and proving
    /// later lets whoever started the flow keep the binding after the rightful
    /// owner proves the address.
    /// </summary>
    RequiresEmailVerification,

    /// <summary>
    /// The provider may authenticate existing linked accounts but may never
    /// bootstrap a new one.
    /// </summary>
    Denied,
}

/// <summary>
/// Decision plus the reason, which is logged and surfaced to diagnostics — an
/// operator debugging "why did this provider stop creating accounts" needs the
/// reason, not just the outcome.
/// </summary>
public sealed record ExternalIdentityLinkingEvaluation(
    ExternalIdentityLinkingDecision Decision,
    string? Reason = null);

/// <summary>
/// Decides whether an external identity is allowed to bootstrap a local
/// account without further proof.
/// </summary>
/// <remarks>
/// <para>
/// This exists as a policy boundary rather than an inline condition because the
/// answer is a deployment decision, not a protocol fact. A deployment whose only
/// provider is a corporate IdP it operates itself can reasonably trust that
/// provider's addresses; a deployment federating consumer providers cannot. The
/// same code must serve both without either one editing a conditional.
/// </para>
/// <para>
/// The security property this boundary protects is account pre-hijacking: if an
/// unverified address may create and bind an account, an attacker registers the
/// victim's address at a provider that does not verify it, and keeps the binding
/// after the victim later proves the address through any other path.
/// </para>
/// </remarks>
public interface IExternalIdentityLinkingPolicy
{
    ValueTask<ExternalIdentityLinkingEvaluation> EvaluateAsync(
        ExternalIdentityAssertion assertion,
        CancellationToken cancellationToken = default);
}
