using System.Security.Claims;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Server.Management;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class SufficitManagementContextClaimsTransformationTests
{
    [Fact]
    public async Task Authorized_management_principal_receives_global_context()
    {
        var principal = PrincipalWithClaims(
            new Claim(ClaimTypes.Role, "administrator"));
        var transformation = CreateTransformation(
            ManagementCapabilities.UsersRead);

        await transformation.TransformAsync(principal);

        Assert.Contains(
            principal.FindAll("identity_context"),
            claim => claim.Value == "global");
    }

    [Fact]
    public async Task Authentication_or_oauth_scope_alone_does_not_receive_context()
    {
        var principal = PrincipalWithClaims(
            new Claim("scope", "identity.management"));
        var transformation = CreateTransformation();

        await transformation.TransformAsync(principal);

        Assert.DoesNotContain(
            principal.Claims,
            claim => claim.Type == "identity_context");
    }

    [Fact]
    public async Task Existing_non_global_context_is_not_replaced()
    {
        var principal = PrincipalWithClaims(
            new Claim("identity_context", "tenant-a"));
        var transformation = CreateTransformation(
            ManagementCapabilities.UsersRead);

        await transformation.TransformAsync(principal);

        Assert.Single(principal.FindAll("identity_context"));
        Assert.Contains(
            principal.FindAll("identity_context"),
            claim => claim.Value == "tenant-a");
    }

    [Fact]
    public async Task Anonymous_principal_is_left_unchanged()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        var transformation = CreateTransformation(
            ManagementCapabilities.UsersRead);

        await transformation.TransformAsync(principal);

        Assert.Empty(principal.Claims);
    }

    private static SufficitManagementContextClaimsTransformation
        CreateTransformation(params string[] capabilities) =>
        new(
            new StubEntitlementResolver(capabilities),
            Options.Create(new ManagementOptions()));

    private static ClaimsPrincipal PrincipalWithClaims(
        params Claim[] claims) =>
        new(new ClaimsIdentity(
            claims,
            authenticationType: "test",
            nameType: ClaimTypes.Name,
            roleType: ClaimTypes.Role));

    private sealed class StubEntitlementResolver(
        IReadOnlyCollection<string> capabilities)
        : IManagementEntitlementResolver
    {
        public ValueTask<ManagementEntitlements> ResolveAsync(
            ClaimsPrincipal principal,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(
                new ManagementEntitlements(
                    new HashSet<string>(capabilities,
                        StringComparer.Ordinal)));
    }
}
