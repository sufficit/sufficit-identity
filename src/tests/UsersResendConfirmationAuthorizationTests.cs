using System.Security.Claims;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// F-8 (eval 2026-08-14): resending an account-confirmation email is an
/// outbound mail action and must be gated by its own capability. The
/// endpoint previously rode on <c>identity.users.read</c> (via GetAsync), so
/// a read-only operator could trigger unlimited account emails — a
/// mail-bombing vector — with no audit row for the send itself.
/// </summary>
public sealed class UsersResendConfirmationAuthorizationTests
{
    [Fact]
    public void Resend_confirmation_is_a_distinct_capability_in_the_catalog()
    {
        // The presentation and authorization surfaces both enumerate
        // ManagementCapabilities.All; membership here keeps the operator
        // consoles, entitlement resolver and audit trail in agreement.
        Assert.Contains(
            ManagementCapabilities.UsersResendConfirmation,
            ManagementCapabilities.All);
    }

    [Fact]
    public async Task Users_read_only_operator_cannot_resend_confirmation_emails()
    {
        var evaluator = CreateEvaluator();

        var decision = await evaluator.EvaluateAsync(
            PrincipalWithClaims(new Claim(
                "permission",
                ManagementCapabilities.UsersRead)),
            ManagementCapabilities.UsersResendConfirmation,
            new ManagementResource(ManagementResourceTypes.User, "user-1"));

        Assert.Equal(
            ManagementAuthorizationOutcome.Denied,
            decision.Outcome);
        Assert.Equal("capability_not_granted", decision.ReasonCode);
    }

    [Fact]
    public async Task Explicit_resend_permission_allows_the_action()
    {
        var evaluator = CreateEvaluator();

        var decision = await evaluator.EvaluateAsync(
            PrincipalWithClaims(new Claim(
                "permission",
                ManagementCapabilities.UsersResendConfirmation)),
            ManagementCapabilities.UsersResendConfirmation,
            new ManagementResource(ManagementResourceTypes.User, "user-1"));

        Assert.True(decision.IsAllowed);
    }

    private static CapabilityManagementAuthorizationEvaluator CreateEvaluator()
    {
        var options = Options.Create(new ManagementOptions
        {
            // MFA step-up is orthogonal to the capability split under test;
            // these synthetic principals carry no amr evidence.
            RequireMfa = false,
            Authorization = new ManagementAuthorizationOptions
            {
                CapabilityClaimTypes = ["permission"],
            }
        });
        return new CapabilityManagementAuthorizationEvaluator(
            new ScopeAndRoleManagementEntitlementResolver(options),
            new ConfigurationManagementAccessPolicyProvider(options),
            new AllowingObjectAccessPolicy());
    }

    private static ClaimsPrincipal PrincipalWithClaims(params Claim[] claims) =>
        new(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, "operator-1"),
                .. claims
            ],
            authenticationType: "test",
            nameType: ClaimTypes.Name,
            roleType: ClaimTypes.Role));

    private sealed class AllowingObjectAccessPolicy
        : IManagementObjectAccessPolicy
    {
        public ValueTask<ManagementAuthorizationDecision> EvaluateAsync(
            ClaimsPrincipal principal,
            string capability,
            ManagementResource resource,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(ManagementAuthorizationDecision.Allowed());
    }
}
