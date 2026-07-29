using System.Security.Claims;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class ManagementApplicationAuthorizationTests
{
    [Fact]
    public async Task Administrator_receives_global_management_capabilities()
    {
        var evaluator = CreateEvaluator();
        var principal = PrincipalWithRole("administrator");

        foreach (var capability in new[]
                 {
                     ManagementCapabilities.ClientsRead,
                     ManagementCapabilities.ClientsCreate,
                     ManagementCapabilities.ClientsDelete,
                     ManagementCapabilities.BrandingRead,
                     ManagementCapabilities.BrandingManage,
                     ManagementCapabilities.AuditRead,
                 })
        {
            var decision = await evaluator.EvaluateAsync(
                principal,
                capability,
                new ManagementResource(ManagementResourceTypes.Client));
            Assert.True(decision.IsAllowed, capability);
        }
    }

    [Fact]
    public async Task Manager_is_denied_global_client_capabilities()
    {
        var decision = await CreateEvaluator().EvaluateAsync(
            PrincipalWithRole("manager"),
            ManagementCapabilities.ClientsCreate,
            new ManagementResource(ManagementResourceTypes.Client));

        Assert.Equal(ManagementAuthorizationOutcome.Denied, decision.Outcome);
        Assert.Equal("capability_not_granted", decision.ReasonCode);
    }

    [Fact]
    public async Task Configured_mfa_returns_step_up_until_evidence_is_present()
    {
        var evaluator = CreateEvaluator(requireMfa: true);

        var withoutMfa = await evaluator.EvaluateAsync(
            PrincipalWithRole("administrator"),
            ManagementCapabilities.ClientsDelete,
            new ManagementResource(ManagementResourceTypes.Client));
        var withMfa = await evaluator.EvaluateAsync(
            PrincipalWithRole("administrator", new Claim("amr", "pwd mfa")),
            ManagementCapabilities.ClientsDelete,
            new ManagementResource(ManagementResourceTypes.Client));

        Assert.Equal(
            ManagementAuthorizationOutcome.StepUpRequired,
            withoutMfa.Outcome);
        Assert.True(withMfa.IsAllowed);
    }

    private static RoleBasedManagementAuthorizationEvaluator CreateEvaluator(
        bool requireMfa = false) =>
        new(Options.Create(new ManagementOptions
        {
            RequireMfa = requireMfa
        }));

    private static ClaimsPrincipal PrincipalWithRole(
        string role,
        params Claim[] additionalClaims) =>
        new(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, "operator-1"),
                new Claim(ClaimTypes.Role, role),
                .. additionalClaims
            ],
            authenticationType: "test",
            nameType: ClaimTypes.Name,
            roleType: ClaimTypes.Role));
}
