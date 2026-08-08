using System.Linq;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.STS;
using Sufficit.Identity.STS.Security;
using Xunit;
// Disambiguate: ManagementOptions exists in both Sufficit.Identity.STS and
// Sufficit.Identity.Management. The posture check inspects the management-layer
// one (with the Authorization policy modes).
using ManagementOptions = global::Sufficit.Identity.Management.ManagementOptions;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Covers the consolidated production posture check: each permissive default is
/// flagged unless hardened or explicitly acknowledged, and a fully hardened
/// configuration produces no findings.
/// </summary>
public sealed class ProductionPostureCheckTests
{
    private static bool Has(
        System.Collections.Generic.IReadOnlyList<ProductionPostureFinding> findings,
        string id)
        => findings.Any(f => f.Id == id);

    [Fact]
    public void Default_options_flag_csp_report_only()
    {
        // A bare SufficitIdentityOptions ships CSP in report-only mode.
        var findings = ProductionPostureCheck.Evaluate(
            new SufficitIdentityOptions(),
            management: null,
            distributedCacheIsMemoryFallback: false);

        Assert.True(Has(findings, "csp-report-only"));
    }

    [Fact]
    public void Acknowledged_csp_report_only_is_not_flagged()
    {
        var options = new SufficitIdentityOptions
        {
            Csp = new CspOptions { ReportOnly = true, AcknowledgeReportOnly = true },
        };

        var findings = ProductionPostureCheck.Evaluate(
            options, management: null, distributedCacheIsMemoryFallback: false);

        Assert.False(Has(findings, "csp-report-only"));
    }

    [Fact]
    public void Enforced_csp_is_not_flagged()
    {
        var options = new SufficitIdentityOptions
        {
            Csp = new CspOptions { ReportOnly = false },
        };

        var findings = ProductionPostureCheck.Evaluate(
            options, management: null, distributedCacheIsMemoryFallback: false);

        Assert.False(Has(findings, "csp-report-only"));
    }

    [Fact]
    public void Management_observe_modes_are_flagged_when_enabled()
    {
        var management = new ManagementOptions
        {
            Enabled = true,
            Authorization = new ManagementAuthorizationOptions
            {
                ObjectAccess = new ManagementObjectAccessOptions
                {
                    Mode = ManagementPolicyEnforcementMode.Observe,
                },
                ProtectedPrincipals = new ProtectedPrincipalAccessOptions
                {
                    Mode = ManagementPolicyEnforcementMode.Observe,
                },
            },
        };

        var findings = ProductionPostureCheck.Evaluate(
            new SufficitIdentityOptions
            {
                Csp = new CspOptions { ReportOnly = false },
            },
            management,
            distributedCacheIsMemoryFallback: false);

        Assert.True(Has(findings, "management-object-access-observe"));
        Assert.True(Has(findings, "management-protected-principal-observe"));
    }

    [Fact]
    public void Management_observe_modes_are_not_flagged_when_management_disabled()
    {
        // Management disabled → its policies do not apply.
        var management = new ManagementOptions
        {
            Enabled = false,
            Authorization = new ManagementAuthorizationOptions
            {
                ObjectAccess = new ManagementObjectAccessOptions
                {
                    Mode = ManagementPolicyEnforcementMode.Observe,
                },
            },
        };

        var findings = ProductionPostureCheck.Evaluate(
            new SufficitIdentityOptions { Csp = new CspOptions { ReportOnly = false } },
            management,
            distributedCacheIsMemoryFallback: false);

        Assert.False(Has(findings, "management-object-access-observe"));
    }

    [Fact]
    public void Enforced_or_acknowledged_management_modes_are_not_flagged()
    {
        var management = new ManagementOptions
        {
            Enabled = true,
            Authorization = new ManagementAuthorizationOptions
            {
                ObjectAccess = new ManagementObjectAccessOptions
                {
                    Mode = ManagementPolicyEnforcementMode.Enforce,
                },
                ProtectedPrincipals = new ProtectedPrincipalAccessOptions
                {
                    Mode = ManagementPolicyEnforcementMode.Observe,
                    AcknowledgeObserveInProduction = true,
                },
            },
        };

        var findings = ProductionPostureCheck.Evaluate(
            new SufficitIdentityOptions { Csp = new CspOptions { ReportOnly = false } },
            management,
            distributedCacheIsMemoryFallback: false);

        Assert.False(Has(findings, "management-object-access-observe"));
        Assert.False(Has(findings, "management-protected-principal-observe"));
    }

    [Fact]
    public void Dpop_replay_cache_flagged_only_when_shared_required_and_memory_fallback()
    {
        var options = new SufficitIdentityOptions
        {
            Csp = new CspOptions { ReportOnly = false },
            Dpop = new DpopOptions { Enabled = true },
            DistributedCache = new DistributedCacheOptions { RequireShared = true },
        };

        // Memory fallback + RequireShared + DPoP enabled → flagged.
        Assert.True(Has(
            ProductionPostureCheck.Evaluate(options, null, distributedCacheIsMemoryFallback: true),
            "dpop-replay-cache-not-shared"));

        // A real shared cache (not memory fallback) → not flagged.
        Assert.False(Has(
            ProductionPostureCheck.Evaluate(options, null, distributedCacheIsMemoryFallback: false),
            "dpop-replay-cache-not-shared"));
    }

    [Fact]
    public void Fapi2_signed_jarm_without_encryption_is_not_a_posture_finding()
    {
        var options = new SufficitIdentityOptions
        {
            Csp = new CspOptions { ReportOnly = false },
            Fapi2 = new Fapi2Options
            {
                Enabled = true,
                ClientIds = new System.Collections.Generic.HashSet<string>(
                    System.StringComparer.Ordinal) { "fapi-client" },
            },
            Jarm = new JarmOptions
            {
                Enabled = true,
                Encryption = new JarmEncryptionOptions { Enabled = false },
            },
        };

        Assert.Empty(ProductionPostureCheck.Evaluate(options, null, false));
    }

    [Fact]
    public void Fully_hardened_configuration_produces_no_findings()
    {
        var options = new SufficitIdentityOptions
        {
            Csp = new CspOptions { ReportOnly = false },
            DistributedCache = new DistributedCacheOptions { RequireShared = false },
        };
        var management = new ManagementOptions
        {
            Enabled = true,
            Authorization = new ManagementAuthorizationOptions
            {
                ObjectAccess = new ManagementObjectAccessOptions
                {
                    Mode = ManagementPolicyEnforcementMode.Enforce,
                },
                ProtectedPrincipals = new ProtectedPrincipalAccessOptions
                {
                    Mode = ManagementPolicyEnforcementMode.Enforce,
                },
            },
        };

        var findings = ProductionPostureCheck.Evaluate(
            options, management, distributedCacheIsMemoryFallback: false);

        Assert.Empty(findings);
    }
}
