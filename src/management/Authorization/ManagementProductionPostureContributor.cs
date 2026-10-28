using Microsoft.Extensions.Options;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.Management.Authorization;

public sealed class ManagementProductionPostureContributor(
    IOptions<ManagementOptions> optionsAccessor)
    : IProductionPostureContributor
{
    public IEnumerable<ProductionPostureFinding> Evaluate()
    {
        var options = optionsAccessor.Value;
        if (!options.Enabled)
        {
            yield break;
        }

        if (!options.RequireAuthorization)
        {
            yield return new(
                "management-authorization-disabled",
                "Management API authorization is disabled and its policy permits every request.",
                "Set Sufficit:Identity:Management:RequireAuthorization=true.");
        }

        var protectedPrincipals = options.Authorization.ProtectedPrincipals;
        if (protectedPrincipals.Mode == ManagementPolicyEnforcementMode.Observe)
        {
            yield return new(
                "management-protected-principal-observe",
                "Protected-principal mutation policy is in Observe mode and would-be denials are permitted.",
                "Set Management:Authorization:ProtectedPrincipals:Mode=Enforce after tier inventory.",
                protectedPrincipals.AcknowledgeObserveInProduction);
        }

        // Plan A2. Without privileged scopes the mode decides nothing (the
        // reserved floor is enforced in both), so only a deployment that
        // declared some is reported. Advisory: Observe is the documented
        // rollout step, and switching to Enforce needs the denial inventory
        // the audit rows provide.
        var scopeGrants = options.ClientScopeGrants;
        if (scopeGrants.Mode == ClientDefinitionRolloutMode.Observe
            && scopeGrants.PrivilegedScopes is { Count: > 0 })
        {
            yield return new(
                "management-client-scope-grants-observe",
                "The operator-aware client scope-grant decision is in Observe mode: "
                + "an operator lacking a privileged scope's capability can still grant it, "
                + "and only an audit row (operationOutcome=observed) records it.",
                "Reconcile the observed scope-grant denials, then set "
                + "Sufficit:Identity:Management:ClientScopeGrants:Mode=Enforce.",
                Severity: ProductionPostureSeverity.Advisory);
        }
    }
}
