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

        var objectAccess = options.Authorization.ObjectAccess;
        if (objectAccess.Mode == ManagementPolicyEnforcementMode.Observe)
        {
            yield return new(
                "management-object-access-observe",
                "Management object/tenant authorization is in Observe mode and would-be denials are permitted.",
                "Set Management:Authorization:ObjectAccess:Mode=Enforce after tenant inventory.",
                objectAccess.AcknowledgeObserveInProduction);
        }

        var tenantAccess = options.Authorization.TenantAccess;
        var subjectTenants = tenantAccess.SubjectTenants
            ?? new Dictionary<string, string[]>(StringComparer.Ordinal);
        if (subjectTenants.Count is 0)
        {
            yield return new(
                "management-tenant-authority-empty",
                "Management has no deployment-controlled operator-to-tenant assignments.",
                "Configure Management:Authorization:TenantAccess:SubjectTenants for every authorized operator subject.");
        }

        var invalidTenantConfiguration =
            !ConfigurationManagementTenantResolver.IsValidTenantId(
                tenantAccess.ProviderTenantId)
            || subjectTenants.Any(assignment =>
                string.IsNullOrWhiteSpace(assignment.Key)
                || assignment.Value is null
                || assignment.Value.Length is 0
                || assignment.Value.Any(tenantId =>
                    !ConfigurationManagementTenantResolver.IsValidTenantId(
                        tenantId)));
        if (invalidTenantConfiguration)
        {
            yield return new(
                "management-tenant-configuration-invalid",
                "Management tenant authority contains an invalid subject or tenant identifier.",
                "Use stable non-empty subjects and tenant identifiers without whitespace or control characters; the claim is fixed as identity:tenant.");
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
