using Microsoft.Extensions.Options;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.Scim;

public sealed class ScimProductionPostureContributor(
    IOptions<ScimOptions> optionsAccessor)
    : IProductionPostureContributor
{
    public IEnumerable<ProductionPostureFinding> Evaluate()
    {
        var options = optionsAccessor.Value;
        if (!options.Enabled)
        {
            yield break;
        }

        if (!options.RequireAllowedClient)
        {
            yield return new(
                "scim-client-allow-list-disabled",
                "SCIM client allow-list enforcement is disabled for a full-directory-trust surface.",
                "Set Sufficit:Identity:Scim:RequireAllowedClient=true and provision dedicated clients.");
            yield break;
        }

        if (options.ClientPolicyMode == ScimClientPolicyMode.Observe)
        {
            yield return new(
                "scim-client-policy-observe",
                "SCIM client allow-list is in Observe mode and unlisted clients are permitted.",
                "Inventory provisioning callers and set Scim:ClientPolicyMode=Enforce.");
        }
    }
}
