using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.Scim;

/// <summary>
/// What a SCIM request is about to do, as far as authorization cares.
/// </summary>
public enum ScimOperation
{
    /// <summary>Listing or reading a resource.</summary>
    Read,

    /// <summary>Creating or updating a user or group.</summary>
    Provision,

    /// <summary>Setting a password on someone else's account.</summary>
    PasswordMutation,

    /// <summary>Adding to or removing from a group.</summary>
    MembershipMutation,

    /// <summary>Removing a user or a group.</summary>
    Delete,
}

public sealed record ScimOperationDecision(
    bool Allowed,
    string? ReasonCode = null)
{
    public static readonly ScimOperationDecision Allow = new(true);
}

/// <summary>
/// Decides each SCIM operation on its own terms.
/// </summary>
/// <remarks>
/// SCIM authorization used to be one answer for the whole surface: a client
/// that could provision could also delete every account and set anyone's
/// password, because all of it sat behind a single policy on the controller.
/// The operations differ in what they cost when the credential is wrong, so
/// they are decided separately.
/// </remarks>
public interface IScimOperationAuthorizationPolicy
{
    ScimOperationDecision Evaluate(ScimOperation operation, ClaimsPrincipal principal);
}

internal sealed class ScimOperationAuthorizationPolicy(
    IOptions<ScimOptions> optionsAccessor,
    ILogger<ScimOperationAuthorizationPolicy>? logger = null)
    : IScimOperationAuthorizationPolicy
{
    public ScimOperationDecision Evaluate(
        ScimOperation operation,
        ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        var options = optionsAccessor.Value;
        var reason = Refusal(operation, principal, options);
        if (reason is null)
        {
            return ScimOperationDecision.Allow;
        }

        var enforced = options.OperationPolicyMode
            == ScimClientPolicyMode.Enforce;
        logger?.LogWarning(
            "SCIM {Operation} by {Actor} {Outcome}: {Reason}.",
            operation,
            principal.FindFirst("client_id")?.Value
                ?? principal.FindFirst("sub")?.Value
                ?? "unknown",
            enforced ? "refused" : "would be refused",
            reason);
        return enforced
            ? new ScimOperationDecision(false, reason)
            : ScimOperationDecision.Allow;
    }

    private static string? Refusal(
        ScimOperation operation,
        ClaimsPrincipal principal,
        ScimOptions options)
    {
        if (operation is ScimOperation.Read or ScimOperation.Provision)
        {
            return null;
        }

        if (operation is ScimOperation.MembershipMutation
            && !options.RequirePermissionForMembership)
        {
            return null;
        }

        // Deleting an account and setting its password are the two operations
        // whose blast radius is the whole directory: one removes people, the
        // other becomes them. A client that provisions does not get either by
        // default.
        if (!string.IsNullOrWhiteSpace(options.DestructiveOperationScope)
            && !ScimAuthenticationContext.HasScope(
                principal,
                options.DestructiveOperationScope))
        {
            return "destructive_scope_missing";
        }

        if (ScimAuthenticationContext.IsClientCredentialsToken(principal))
        {
            // An application cannot present a second factor — it has no person
            // behind it. What it can do is prove the token is its own: a
            // sender-constrained token cannot be replayed by whoever copied it
            // out of a log or a misrouted response.
            return options.RequireSenderConstraintForDestructive
                && !HasSenderConstraint(principal)
                    ? "sender_constraint_required"
                    : null;
        }

        return options.RequireMfaForDestructive
            && !ScimAuthenticationContext.HasMfaEvidence(principal)
                ? "mfa_required"
                : null;
    }

    /// <summary>
    /// The token is bound to a key its holder must prove — mTLS
    /// (<c>x5t#S256</c>) or DPoP (<c>jkt</c>), RFC 8705 and RFC 9449.
    /// </summary>
    private static bool HasSenderConstraint(ClaimsPrincipal principal) =>
        principal.FindAll("cnf").Any(claim =>
            claim.Value.Contains("x5t#S256", StringComparison.Ordinal)
            || claim.Value.Contains("jkt", StringComparison.Ordinal))
        || principal.HasClaim(claim =>
            claim.Type is "cnf.jkt" or "cnf.x5t#S256");
}
