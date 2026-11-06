using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Scim;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class ScimMfaEvidenceTests
{
    public static IEnumerable<object[]> EvidenceCases()
    {
        foreach (var remembered in new[] { false, true })
        {
            foreach (var method in new[] { "mfa", "otp", "hwk", "sms", "vcm", "fpt", "eye", "voice", "retina" })
            {
                yield return new object[] { new[] { "pwd", method }, remembered, true };
                yield return new object[] { new[] { $"  pwd   {method}  " }, remembered, true };
            }
            foreach (var method in new[] { "", "pwd", "MFA", "passkey", "unknown", "not-mfa" })
                yield return new object[] { new[] { method }, remembered, false };
            yield return new object[] { Array.Empty<string>(), remembered, false };
        }
    }

    [Theory]
    [MemberData(nameof(EvidenceCases))]
    public async Task HandlerAndAuditReaderPreserveSharedPolicy(
        string[] methods, bool remembered, bool expected)
    {
        var claims = methods.Select(value => new Claim("amr", value)).ToList();
        if (remembered)
            claims.Add(new Claim(MfaEvidencePolicy.RememberedSecondFactorClaimType, "true"));
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));
        var requirement = new ScimMfaRequirement();
        var context = new AuthorizationHandlerContext(new[] { requirement }, principal, null);
        await new ScimMfaHandler().HandleAsync(context);

        Assert.Equal(expected, context.HasSucceeded);
        // The denial audit and destructive-operation policy use this same reader.
        Assert.Equal(expected, ScimAuthenticationContext.HasMfaEvidence(principal));
        Assert.Equal(expected, MfaEvidencePolicy.HasMfaEvidence(principal));
        Assert.Equal(expected && !remembered, MfaEvidencePolicy.HasFreshMfaEvidence(principal));
    }
}
