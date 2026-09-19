using System.Security.Claims;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorization;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// A trusted-device cookie satisfies Management and does not mint credentials
/// (owner's decision, 2026-09-20; the first half is 9957d6d from 2026-08-14).
/// </summary>
public sealed class RememberedSecondFactorTests : IDisposable
{
    private readonly SqliteConnection _connection = new("DataSource=:memory:");
    private readonly ServiceProvider _provider;

    public RememberedSecondFactorTests()
    {
        _connection.Open();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddMemoryCache();
        services.AddDbContextFactory<AppDbContext>(db =>
        {
            db.UseSqlite(_connection);
            db.UseOpenIddict();
        });
        _provider = services.BuildServiceProvider();
        using var database = _provider
            .GetRequiredService<IDbContextFactory<AppDbContext>>()
            .CreateDbContext();
        database.Database.EnsureCreated();
    }

    public void Dispose()
    {
        _provider.Dispose();
        _connection.Dispose();
    }

    private static ClaimsPrincipal Operator(bool remembered) =>
        new(new ClaimsIdentity(
            remembered
                ? [
                    new Claim("sub", "operator"),
                    new Claim("amr", "pwd mfa"),
                    new Claim(
                        MfaEvidencePolicy.RememberedSecondFactorClaimType,
                        "true"),
                ]
                : [new Claim("sub", "operator"), new Claim("amr", "pwd mfa")],
            "test"));

    private ManagementOperationGuard Guard(bool requireMfa = true) =>
        new(
            new AlwaysAllowedEvaluator(),
            _provider.GetRequiredService<IDbContextFactory<AppDbContext>>()
                .CreateDbContext(),
            _provider.GetRequiredService<IMemoryCache>(),
            NullLogger<ManagementOperationGuard>.Instance,
            Options.Create(new ManagementOptions { RequireMfa = requireMfa }));

    private static ManagementRequestContext Context(ClaimsPrincipal principal) =>
        new(principal, Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task A_remembered_device_still_operates_management()
    {
        // The half that stays: an operator does not repeat the second factor
        // to read a page or change a setting.
        var decision = await Guard().DemandAsync(
            Context(Operator(remembered: true)),
            ManagementCapabilities.UsersRead,
            new ManagementResource(ManagementResourceTypes.User, "user-1"),
            CancellationToken.None);

        Assert.True(decision.IsAllowed);
    }

    [Fact]
    public async Task A_remembered_device_does_not_mint_a_credential()
    {
        // A token outlives the browser that asked for it.
        var refusal = await Assert.ThrowsAsync<ManagementAccessException>(() =>
            Guard().DemandAsync(
                Context(Operator(remembered: true)),
                ManagementCapabilities.ManagementTokensIssue,
                new ManagementResource(ManagementResourceTypes.OperatorTokenCollection),
                CancellationToken.None,
                mintsCredential: true));

        Assert.Equal(
            ManagementAuthorizationOutcome.StepUpRequired,
            refusal.Decision.Outcome);
        Assert.Equal("fresh_mfa_required", refusal.Decision.ReasonCode);
    }

    [Fact]
    public async Task A_second_factor_from_this_session_mints_a_credential()
    {
        var decision = await Guard().DemandAsync(
            Context(Operator(remembered: false)),
            ManagementCapabilities.ManagementTokensIssue,
            new ManagementResource(ManagementResourceTypes.OperatorTokenCollection),
            CancellationToken.None,
            mintsCredential: true);

        Assert.True(decision.IsAllowed);
    }

    [Fact]
    public async Task A_deployment_that_does_not_require_mfa_is_left_alone()
    {
        // There is no second factor to insist on being fresh; refusing here
        // would be stricter than the deployment asked to be.
        var decision = await Guard(requireMfa: false).DemandAsync(
            Context(Operator(remembered: true)),
            ManagementCapabilities.ManagementTokensIssue,
            new ManagementResource(ManagementResourceTypes.OperatorTokenCollection),
            CancellationToken.None,
            mintsCredential: true);

        Assert.True(decision.IsAllowed);
    }

    [Theory]
    [InlineData("pwd mfa", false, true, true)]
    [InlineData("pwd mfa", true, true, false)]
    [InlineData("pwd", false, false, false)]
    public void Evidence_policy_separates_present_from_fresh(
        string amr,
        bool remembered,
        bool hasMfa,
        bool hasFreshMfa)
    {
        var claims = new List<Claim> { new("amr", amr) };
        if (remembered)
        {
            claims.Add(new Claim(
                MfaEvidencePolicy.RememberedSecondFactorClaimType,
                "true"));
        }

        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));

        Assert.Equal(hasMfa, MfaEvidencePolicy.HasMfaEvidence(principal));
        Assert.Equal(hasFreshMfa, MfaEvidencePolicy.HasFreshMfaEvidence(principal));
    }

    [Fact]
    public void The_marker_survives_a_round_trip_through_claims()
    {
        // The measurement at the authorize endpoint, and the refusal at the
        // mint, both read this marker off the session principal rather than
        // off the sign-in that set it — a renewed cookie has to still carry it.
        var renewed = new ClaimsPrincipal(new ClaimsIdentity(
            Operator(remembered: true).Claims.ToList(),
            "renewed"));

        Assert.True(MfaEvidencePolicy.IsSecondFactorRemembered(renewed));
        Assert.True(MfaEvidencePolicy.HasMfaEvidence(renewed));
        Assert.False(MfaEvidencePolicy.HasFreshMfaEvidence(renewed));
    }

    private sealed class AlwaysAllowedEvaluator : IManagementAuthorizationEvaluator
    {
        public ValueTask<ManagementAuthorizationDecision> EvaluateAsync(
            ClaimsPrincipal principal,
            string capability,
            ManagementResource resource,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(ManagementAuthorizationDecision.Allowed());
    }
}
