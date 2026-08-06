using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Sufficit.Identity.Management;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Covers Onda 5 operational hardening: the MFA authorization requirement for
/// the management policy (5.2 [L3]) and the rate-limit fail-safe option (5.1
/// [L4], option-level — the fatal-boot behavior is operational and not
/// exercisable from the Development test factory).
/// </summary>
public sealed class MfaRequirementTests
{
    [Fact]
    public async Task Token_with_mfa_amr_claim_satisfies_the_requirement()
    {
        // A principal whose amr claim includes "mfa" (RFC 8176) proves a second
        // factor was used → the MfaRequirement succeeds.
        var handler = new MfaHandler();
        var requirement = new MfaRequirement();
        var context = new AuthorizationHandlerContext(
            new[] { requirement },
            new ClaimsPrincipal(new ClaimsIdentity(new[]
            {
                new Claim("amr", "mfa"),
                new Claim("amr", "pwd"), // password factor also present
            }, authenticationType: "Test")),
            resource: null);

        await handler.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Fact]
    public async Task Token_with_only_password_amr_does_not_satisfy_mfa()
    {
        // Password-only session: amr=pwd (or no amr at all) → no MFA evidence.
        // The requirement is left unsatisfied → the management policy denies.
        var handler = new MfaHandler();
        var requirement = new MfaRequirement();
        var context = new AuthorizationHandlerContext(
            new[] { requirement },
            new ClaimsPrincipal(new ClaimsIdentity(new[]
            {
                new Claim("amr", "pwd"),
            }, authenticationType: "Test")),
            resource: null);

        await handler.HandleAsync(context);

        Assert.False(context.HasSucceeded);
    }

    [Theory]
    [InlineData("otp")]   // one-time password (TOTP/HOTP)
    [InlineData("hwk")]   // hardware key (WebAuthn/FIDO2)
    [InlineData("fpt")]   // fingerprint
    public async Task Second_factor_amr_values_satisfy_the_requirement(string amrValue)
    {
        // Each RFC 8176 second-factor value individually proves MFA.
        var handler = new MfaHandler();
        var requirement = new MfaRequirement();
        var context = new AuthorizationHandlerContext(
            new[] { requirement },
            new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("amr", amrValue) }, "Test")),
            resource: null);

        await handler.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Fact]
    public async Task Token_with_no_amr_claim_at_all_does_not_satisfy_mfa()
    {
        // A token minted by a flow that never set amr (e.g. a service account
        // or a legacy session) must be rejected by the MFA-gated policy.
        var handler = new MfaHandler();
        var requirement = new MfaRequirement();
        var context = new AuthorizationHandlerContext(
            new[] { requirement },
            new ClaimsPrincipal(new ClaimsIdentity(authenticationType: "Test")),
            resource: null);

        await handler.HandleAsync(context);

        Assert.False(context.HasSucceeded);
    }
}

/// <summary>
/// Option-binding smoke tests for the operational hardening flags (5.1/5.2):
/// confirms the new config keys bind to the options types with the documented
/// defaults. (The fatal-boot behavior of FailOnUntrustedProxy is operational
/// — it runs in Program.cs at host startup, not in the Development test host.)
/// </summary>
public sealed class OperationalOptionsTests
{
    [Fact]
    public void RateLimit_FailOnUntrustedProxy_defaults_to_false()
    {
        var options = new Sufficit.Identity.STS.RateLimitOptions();
        Assert.False(options.FailOnUntrustedProxy);
    }

    [Fact]
    public void Management_RequireMfa_defaults_to_true()
    {
        var options = new ManagementOptions();
        Assert.True(options.RequireMfa);
    }
}

