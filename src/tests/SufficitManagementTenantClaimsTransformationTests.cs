using System.Security.Claims;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Server.Management;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class SufficitManagementTenantClaimsTransformationTests
{
    [Fact]
    public async Task Trusted_resolution_projects_colon_separated_tenant_claim()
    {
        var principal = PrincipalWithClaims(
            new Claim("sub", "operator-1"),
            new Claim(ClaimTypes.Role, "administrator"));
        var transformation = CreateTransformation("global", "tenant-a");

        await transformation.TransformAsync(principal);

        Assert.Equal(
            ["global", "tenant-a"],
            principal.FindAll("identity:tenant")
                .Select(claim => claim.Value)
                .Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task Administrator_without_trusted_assignment_receives_no_tenant()
    {
        var principal = PrincipalWithClaims(
            new Claim("sub", "operator-without-assignment"),
            new Claim(ClaimTypes.Role, "administrator"),
            new Claim("permission", ManagementCapabilities.UsersRead));
        var transformation = CreateTransformation();

        await transformation.TransformAsync(principal);

        Assert.DoesNotContain(
            principal.Claims,
            claim => claim.Type == "identity:tenant");
    }

    [Fact]
    public async Task Caller_supplied_tenant_is_replaced_by_trusted_assignment()
    {
        var principal = PrincipalWithClaims(
            new Claim("sub", "operator-1"),
            new Claim("identity:tenant", "attacker-tenant"));
        var transformation = CreateTransformation("tenant-a");

        await transformation.TransformAsync(principal);

        Assert.Single(principal.FindAll("identity:tenant"));
        Assert.Contains(
            principal.FindAll("identity:tenant"),
            claim => claim.Value == "tenant-a"
                && claim.Issuer == "Sufficit.Identity.Management");
    }

    [Fact]
    public async Task Anonymous_principal_is_left_unchanged()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        var transformation = CreateTransformation("global");

        await transformation.TransformAsync(principal);

        Assert.Empty(principal.Claims);
    }

    [Fact]
    public async Task Configuration_resolver_matches_stable_subject_exactly()
    {
        var options = Options.Create(new ManagementOptions
        {
            Authorization = new ManagementAuthorizationOptions
            {
                TenantAccess = new ManagementTenantAccessOptions
                {
                    SubjectTenants = new Dictionary<string, string[]>(
                        StringComparer.Ordinal)
                    {
                        ["operator-1"] = ["global", "tenant-a"],
                    },
                },
            },
        });
        var resolver = new ConfigurationManagementTenantResolver(options);

        var assigned = await resolver.ResolveAsync(PrincipalWithClaims(
            new Claim("sub", "operator-1")));
        var wrongCase = await resolver.ResolveAsync(PrincipalWithClaims(
            new Claim("sub", "OPERATOR-1"),
            new Claim(ClaimTypes.Role, "administrator")));

        Assert.Equal(
            ["global", "tenant-a"],
            assigned.TenantIds.Order(StringComparer.Ordinal));
        Assert.Empty(wrongCase.TenantIds);
    }

    private static SufficitManagementTenantClaimsTransformation
        CreateTransformation(params string[] tenants) =>
        new(new StubTenantResolver(tenants));

    private static ClaimsPrincipal PrincipalWithClaims(
        params Claim[] claims) =>
        new(new ClaimsIdentity(
            claims,
            authenticationType: "test",
            nameType: ClaimTypes.Name,
            roleType: ClaimTypes.Role));

    private sealed class StubTenantResolver(
        IReadOnlyCollection<string> tenants) : IManagementTenantResolver
    {
        public ValueTask<ManagementTenantAccess> ResolveAsync(
            ClaimsPrincipal principal,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(new ManagementTenantAccess(
                tenants.ToHashSet(StringComparer.Ordinal)));
    }
}
