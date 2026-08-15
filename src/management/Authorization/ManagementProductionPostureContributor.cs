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
    }
}
