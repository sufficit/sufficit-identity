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
        }

        // Empty is the documented fail-closed default, so this is not a hole:
        // every request is refused. It is a deployment that turned SCIM on and
        // cannot use it, which otherwise shows up only as 403s at the
        // provisioning client, on the other side of the integration.
        if (options.RequireAllowedClient
            && options.ClientPolicyMode == ScimClientPolicyMode.Enforce
            && !options.AllowedClientIds.Any(
                clientId => !string.IsNullOrWhiteSpace(clientId)))
        {
            yield return new(
                "scim-client-allow-list-empty",
                "SCIM is enabled with an empty client allow-list, so every "
                + "provisioning request is refused.",
                "List the dedicated provisioning clients under "
                + "Sufficit:Identity:Scim:AllowedClientIds, or disable SCIM "
                + "until one exists.",
                Severity: ProductionPostureSeverity.Advisory);
        }

        if (options.ClientPolicyMode == ScimClientPolicyMode.Observe)
        {
            yield return new(
                "scim-client-policy-observe",
                "SCIM client allow-list is in Observe mode and unlisted clients are permitted.",
                "Inventory provisioning callers and set Scim:ClientPolicyMode=Enforce.");
        }

        if (!options.RequireMfa)
        {
            yield return new(
                "scim-mfa-disabled",
                "SCIM accepts a password-only authentication context for the sensitive scim scope.",
                "Set Sufficit:Identity:Scim:RequireMfa=true, or document a time-bounded security exception.");
        }
    }
}
