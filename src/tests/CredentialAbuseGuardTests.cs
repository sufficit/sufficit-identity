using Microsoft.Extensions.Logging.Abstractions;
using Sufficit.Identity.STS.Security;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class CredentialAbuseGuardTests
{
    private static CredentialAbuseGuard Guard(CredentialAbuseMode mode, ICredentialFailureCounter? counter = null) =>
        new(counter ?? new InMemoryCredentialFailureCounter(TimeProvider.System),
            new CredentialAbuseOptions
            {
                Mode = mode, AccountDelayAfter = 3, MaxDelaySeconds = 8, AccountVerificationAfter = 5,
                IpVerificationAfter = 20, IpBlockAfter = 200,
            },
            CredentialAbuseAccountKey.Create("test-key", "https://identity.example"),
            NullLogger<CredentialAbuseGuard>.Instance);

    [Theory]
    [InlineData(0, 0, CredentialAbuseAction.Allow, 0)]
    [InlineData(2, 19, CredentialAbuseAction.Allow, 0)]
    [InlineData(3, 0, CredentialAbuseAction.Delay, 1)]
    [InlineData(4, 0, CredentialAbuseAction.Delay, 2)]
    [InlineData(5, 0, CredentialAbuseAction.RequireVerification, 0)]
    [InlineData(0, 20, CredentialAbuseAction.RequireVerification, 0)]
    [InlineData(0, 200, CredentialAbuseAction.Block, 0)]
    public void Decisions_escalate_from_delay_to_verification_to_block(long account, long ip, CredentialAbuseAction action, int delaySeconds)
    {
        var decision = Guard(CredentialAbuseMode.Enforce).Decide(account, ip);

        Assert.Equal(action, decision.Action);
        Assert.Equal(TimeSpan.FromSeconds(delaySeconds), decision.Delay);
    }

    [Fact]
    public void The_delay_never_exceeds_its_ceiling()
    {
        var guard = new CredentialAbuseGuard(new InMemoryCredentialFailureCounter(TimeProvider.System),
            new CredentialAbuseOptions { Mode = CredentialAbuseMode.Enforce, AccountDelayAfter = 3, MaxDelaySeconds = 8, AccountVerificationAfter = 100 },
            CredentialAbuseAccountKey.Create("test-key", "https://identity.example"),
            NullLogger<CredentialAbuseGuard>.Instance);

        Assert.Equal(TimeSpan.FromSeconds(8), guard.Decide(3 + 10, 0).Delay);
    }

    [Fact]
    public async Task Failures_are_shared_by_account_whatever_the_case_and_cleared_by_a_success()
    {
        var guard = Guard(CredentialAbuseMode.Enforce);
        for (var i = 0; i < 3; i++)
            await guard.RecordFailureAsync(i % 2 == 0 ? "Maria@Example.com" : " maria@example.com", $"203.0.113.{i}", default);

        Assert.Equal(CredentialAbuseAction.Delay, (await guard.EvaluateAsync("MARIA@EXAMPLE.COM", "198.51.100.1", default)).Action);

        await guard.RecordSuccessAsync("maria@example.com", default);
        Assert.Equal(CredentialAbuseAction.Allow, (await guard.EvaluateAsync("maria@example.com", "198.51.100.1", default)).Action);
    }

    [Fact]
    public async Task A_spray_across_accounts_is_caught_by_the_ip()
    {
        var guard = Guard(CredentialAbuseMode.Enforce);
        for (var i = 0; i < 20; i++)
            await guard.RecordFailureAsync($"user{i}", "203.0.113.9", default);

        Assert.Equal(CredentialAbuseAction.RequireVerification,
            (await guard.EvaluateAsync("someone-new", "203.0.113.9", default)).Action);
        Assert.Equal(CredentialAbuseAction.Allow,
            (await guard.EvaluateAsync("someone-new", "198.51.100.1", default)).Action);
    }

    [Fact]
    public async Task Observe_counts_but_never_changes_the_answer()
    {
        var guard = Guard(CredentialAbuseMode.Observe);
        for (var i = 0; i < 6; i++)
            await guard.RecordFailureAsync("victim", "203.0.113.1", default);

        var decision = await guard.EvaluateAsync("victim", "203.0.113.1", default);
        Assert.Equal(CredentialAbuseAction.Allow, decision.Action);
        Assert.Equal(6, decision.AccountFailures);
    }

    [Fact]
    public async Task An_unavailable_store_never_blocks_a_sign_in()
    {
        var guard = Guard(CredentialAbuseMode.Enforce, new FailingCounter());

        Assert.Equal(CredentialAbuseAction.Allow, (await guard.EvaluateAsync("anyone", "203.0.113.1", default)).Action);
        await guard.RecordFailureAsync("anyone", "203.0.113.1", default);
    }

    [Fact]
    public void The_store_never_holds_the_account_name()
    {
        var hash = Guard(CredentialAbuseMode.Enforce).AccountHash("maria@example.com");

        Assert.DoesNotContain("maria", hash, StringComparison.OrdinalIgnoreCase);
        Assert.NotEqual(hash, Guard(CredentialAbuseMode.Enforce).AccountHash("maria@example.org"));
    }

    [Fact]
    public async Task A_count_ends_with_its_window()
    {
        var time = new ManualTime(DateTimeOffset.UtcNow);
        var counter = new InMemoryCredentialFailureCounter(time);
        await counter.IncrementAsync("k", TimeSpan.FromMinutes(15), default);
        await counter.IncrementAsync("k", TimeSpan.FromMinutes(15), default);

        time.Advance(TimeSpan.FromMinutes(16));

        Assert.Equal(0, await counter.GetAsync("k", default));
        Assert.Equal(1, await counter.IncrementAsync("k", TimeSpan.FromMinutes(15), default));
    }

    private sealed class ManualTime(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan by) => _now += by;
    }

    private sealed class FailingCounter : ICredentialFailureCounter
    {
        public Task<long> GetAsync(string key, CancellationToken cancellationToken) => throw new TimeoutException();
        public Task<long> IncrementAsync(string key, TimeSpan window, CancellationToken cancellationToken) => throw new TimeoutException();
        public Task ResetAsync(string key, CancellationToken cancellationToken) => throw new TimeoutException();
    }
}
