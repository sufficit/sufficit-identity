using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;

namespace Sufficit.Identity.STS.Security;

public enum CredentialAbuseMode
{
    /// <summary>Nothing is counted.</summary>
    Off,

    /// <summary>Counts and reports what it would do; never changes an answer.</summary>
    Observe,

    /// <summary>Applies the decision.</summary>
    Enforce,
}

/// <summary>
/// Password-guessing protection shared by every replica (plan D6), bound from
/// <c>Sufficit:Identity:AbuseProtection</c>. Failures are counted per account
/// and per client IP over a window; the account is never stored, only an HMAC
/// of its normalized name.
/// </summary>
public sealed class CredentialAbuseOptions
{
    public CredentialAbuseMode Mode { get; init; } = CredentialAbuseMode.Observe;

    /// <summary>How long a failure counts. At least 15 minutes.</summary>
    public int WindowMinutes { get; init; } = 15;

    /// <summary>Account failures after which each attempt waits, doubling up to <see cref="MaxDelaySeconds"/>.</summary>
    public int AccountDelayAfter { get; init; } = 3;

    public int MaxDelaySeconds { get; init; } = 8;

    /// <summary>Account failures after which the sign-in needs human verification.</summary>
    public int AccountVerificationAfter { get; init; } = 5;

    /// <summary>Failures from one IP, across accounts (password spraying), after which it needs human verification.</summary>
    public int IpVerificationAfter { get; init; } = 20;

    /// <summary>Failures from one IP after which its attempts are refused outright until the window passes.</summary>
    public int IpBlockAfter { get; init; } = 200;

    public TimeSpan Window => TimeSpan.FromMinutes(Math.Max(15, WindowMinutes));
}

public enum CredentialAbuseAction
{
    Allow,
    Delay,
    RequireVerification,
    Block,
}

public sealed record CredentialAbuseDecision(
    CredentialAbuseAction Action,
    TimeSpan Delay,
    long AccountFailures,
    long IpFailures)
{
    public static CredentialAbuseDecision Allowed { get; } = new(CredentialAbuseAction.Allow, TimeSpan.Zero, 0, 0);
}

/// <summary>Failure counters with a fixed window from the first failure.</summary>
public interface ICredentialFailureCounter
{
    Task<long> GetAsync(string key, CancellationToken cancellationToken);

    Task<long> IncrementAsync(string key, TimeSpan window, CancellationToken cancellationToken);

    Task ResetAsync(string key, CancellationToken cancellationToken);
}

/// <summary>Counters in the shared Redis, so every replica sees the same attempts.</summary>
internal sealed class RedisCredentialFailureCounter(IConnectionMultiplexer redis) : ICredentialFailureCounter
{
    public async Task<long> GetAsync(string key, CancellationToken cancellationToken)
    {
        var value = await redis.GetDatabase().StringGetAsync(key);
        return value.TryParse(out long count) ? count : 0;
    }

    public async Task<long> IncrementAsync(string key, TimeSpan window, CancellationToken cancellationToken)
    {
        var database = redis.GetDatabase();
        var count = await database.StringIncrementAsync(key);
        if (count == 1)
            await database.KeyExpireAsync(key, window);
        return count;
    }

    public Task ResetAsync(string key, CancellationToken cancellationToken) =>
        redis.GetDatabase().KeyDeleteAsync(key);
}

/// <summary>Single-process counters, for a host without the shared cache.</summary>
internal sealed class InMemoryCredentialFailureCounter(TimeProvider time) : ICredentialFailureCounter
{
    private const int Capacity = 100_000;
    private readonly ConcurrentDictionary<string, (long Count, DateTimeOffset Expires)> _counters = new(StringComparer.Ordinal);

    public Task<long> GetAsync(string key, CancellationToken cancellationToken) =>
        Task.FromResult(_counters.TryGetValue(key, out var entry) && entry.Expires > time.GetUtcNow() ? entry.Count : 0L);

    public Task<long> IncrementAsync(string key, TimeSpan window, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        if (_counters.Count >= Capacity)
            foreach (var expired in _counters.Where(entry => entry.Value.Expires <= now).Select(entry => entry.Key).ToArray())
                _counters.TryRemove(expired, out _);
        var updated = _counters.AddOrUpdate(key,
            _ => (1, now + window),
            (_, current) => current.Expires > now ? (current.Count + 1, current.Expires) : (1, now + window));
        return Task.FromResult(updated.Count);
    }

    public Task ResetAsync(string key, CancellationToken cancellationToken)
    {
        _counters.TryRemove(key, out _);
        return Task.CompletedTask;
    }
}

/// <summary>
/// Decides, before a password is checked, whether the attempt goes ahead,
/// waits, needs human verification or is refused; and records its outcome.
/// A storage failure never blocks a sign-in: the guard fails open and says so.
/// </summary>
public sealed class CredentialAbuseGuard
{
    private const string KeyPrefix = "sufficit:identity:abuse:";
    private readonly ICredentialFailureCounter _counter;
    private readonly CredentialAbuseOptions _options;
    private readonly byte[] _accountKey;
    private readonly ISecurityDecisionTelemetry? _telemetry;
    private readonly ILogger<CredentialAbuseGuard> _logger;

    public CredentialAbuseGuard(
        ICredentialFailureCounter counter,
        CredentialAbuseOptions options,
        CredentialAbuseAccountKey accountKey,
        ILogger<CredentialAbuseGuard> logger,
        ISecurityDecisionTelemetry? telemetry = null)
    {
        _counter = counter;
        _options = options;
        _accountKey = accountKey.Value;
        _logger = logger;
        _telemetry = telemetry;
    }

    public CredentialAbuseMode Mode => _options.Mode;

    public async Task<CredentialAbuseDecision> EvaluateAsync(string account, string? ip, CancellationToken cancellationToken)
    {
        if (_options.Mode == CredentialAbuseMode.Off)
            return CredentialAbuseDecision.Allowed;

        long accountFailures, ipFailures;
        try
        {
            accountFailures = await _counter.GetAsync(AccountKey(account), cancellationToken);
            ipFailures = string.IsNullOrEmpty(ip) ? 0 : await _counter.GetAsync(IpKey(ip), cancellationToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            _logger.LogWarning(exception, "Credential abuse counters unavailable; the sign-in proceeds unprotected.");
            _telemetry?.Record("credential_abuse", Describe(), false, false, ["store_unavailable"]);
            return CredentialAbuseDecision.Allowed;
        }

        var decision = Decide(accountFailures, ipFailures);
        if (decision.Action != CredentialAbuseAction.Allow)
        {
            var enforced = _options.Mode == CredentialAbuseMode.Enforce;
            _telemetry?.Record("credential_abuse", Describe(), wouldReject: true, rejected: enforced,
                [decision.Action.ToString().ToLowerInvariant()]);
            _logger.LogInformation(
                "Credential abuse ({Mode}): {Action} for account {AccountRef} from {Ip}; failures account={AccountFailures} ip={IpFailures}.",
                Describe(), decision.Action, AccountReference(account), ip, accountFailures, ipFailures);
        }

        return _options.Mode == CredentialAbuseMode.Enforce ? decision : decision with { Action = CredentialAbuseAction.Allow };
    }

    internal CredentialAbuseDecision Decide(long accountFailures, long ipFailures)
    {
        if (ipFailures >= _options.IpBlockAfter)
            return new(CredentialAbuseAction.Block, TimeSpan.Zero, accountFailures, ipFailures);
        if (accountFailures >= _options.AccountVerificationAfter || ipFailures >= _options.IpVerificationAfter)
            return new(CredentialAbuseAction.RequireVerification, TimeSpan.Zero, accountFailures, ipFailures);
        if (accountFailures >= _options.AccountDelayAfter)
        {
            var exponent = (int)Math.Min(accountFailures - _options.AccountDelayAfter, 10);
            var seconds = Math.Min(1 << exponent, Math.Max(1, _options.MaxDelaySeconds));
            return new(CredentialAbuseAction.Delay, TimeSpan.FromSeconds(seconds), accountFailures, ipFailures);
        }
        return new(CredentialAbuseAction.Allow, TimeSpan.Zero, accountFailures, ipFailures);
    }

    public Task RecordFailureAsync(string account, string? ip, CancellationToken cancellationToken) =>
        SafelyAsync(async () =>
        {
            await _counter.IncrementAsync(AccountKey(account), _options.Window, cancellationToken);
            if (!string.IsNullOrEmpty(ip))
                await _counter.IncrementAsync(IpKey(ip), _options.Window, cancellationToken);
        });

    /// <summary>A successful password clears the account's count; the IP's stays (one success does not excuse a spray).</summary>
    public Task RecordSuccessAsync(string account, CancellationToken cancellationToken) =>
        SafelyAsync(() => _counter.ResetAsync(AccountKey(account), cancellationToken));

    private async Task SafelyAsync(Func<Task> action)
    {
        if (_options.Mode == CredentialAbuseMode.Off) return;
        try
        {
            await action();
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            _logger.LogWarning(exception, "Credential abuse counters could not be updated.");
        }
    }

    private string Describe() => _options.Mode.ToString().ToLowerInvariant();

    private string AccountKey(string account) => KeyPrefix + "account:" + AccountHash(account);

    private static string IpKey(string ip) => KeyPrefix + "ip:" + ip;

    /// <summary>HMAC of the normalized account name: the counter store never holds the name.</summary>
    internal string AccountHash(string account) =>
        WebEncoders.Base64UrlEncode(HMACSHA256.HashData(_accountKey,
            Encoding.UTF8.GetBytes(account.Trim().ToUpperInvariant())));

    private string AccountReference(string account) => AccountHash(account)[..8];
}

/// <summary>Key of the account HMAC, the same on every replica.</summary>
public sealed record CredentialAbuseAccountKey(byte[] Value, bool Derived = false)
{
    public const string SecretName = "identity/abuse-protection/account-key";

    /// <summary>
    /// The deployment secret when present; otherwise one derived from the
    /// issuer, which still keeps names out of the store but is guessable by
    /// whoever knows the issuer.
    /// </summary>
    public static CredentialAbuseAccountKey Create(string? secret, string issuer) =>
        string.IsNullOrWhiteSpace(secret)
            ? new(SHA256.HashData(Encoding.UTF8.GetBytes("sufficit-identity-abuse|" + issuer)), Derived: true)
            : new(SHA256.HashData(Encoding.UTF8.GetBytes(secret)));
}
