using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.STS;

/// <summary>
/// Password validator that checks new/changed passwords against the
/// HaveIBeenPwned k-anonymity range API (v3). Only the first 5 hex chars of
/// the SHA-1 hash are sent to the API; the client (this validator) filters
/// the returned suffix list locally. The plaintext password never leaves
/// the STS. Implements <see cref="IPasswordValidator{TUser}"/> so ASP.NET
/// Identity's built-in validation pipeline calls it automatically on
/// CreateAsync, ChangePasswordAsync and ResetPasswordAsync.
/// </summary>
/// <remarks>
/// <b>Latency/availability.</b> The validator makes one HTTP GET per
/// password validation. When the check cannot complete, the configured
/// <see cref="BreachedPasswordFailureMode"/> decides: FailOpen (default)
/// accepts the password so an outage of the external API does not block
/// user operations; FailClosed rejects it until the check succeeds.
/// </remarks>
public sealed class BreachedPasswordValidator : IPasswordValidator<ApplicationUser>
{
    private const string HibpRangeApiUrl = "https://api.pwnedpasswords.com/range/";
    private readonly HttpClient _httpClient;
    private readonly ILogger<BreachedPasswordValidator> _logger;
    private readonly BreachedPasswordFailureMode _failureMode;
    private readonly BreachedPasswordKnowledge _knowledge;
    private readonly ISecurityDecisionTelemetry _telemetry;

    [Microsoft.Extensions.DependencyInjection.ActivatorUtilitiesConstructor]
    public BreachedPasswordValidator(
        HttpClient httpClient,
        ILogger<BreachedPasswordValidator> logger,
        SufficitIdentityOptions options,
        BreachedPasswordKnowledge knowledge,
        ISecurityDecisionTelemetry telemetry)
        : this(
            httpClient,
            logger,
            options.Password.BreachedCheckFailureMode,
            knowledge,
            telemetry)
    {
    }

    public BreachedPasswordValidator(HttpClient httpClient, ILogger<BreachedPasswordValidator> logger)
        : this(httpClient, logger, BreachedPasswordFailureMode.FailOpen)
    {
    }

    public BreachedPasswordValidator(
        HttpClient httpClient,
        ILogger<BreachedPasswordValidator> logger,
        BreachedPasswordFailureMode failureMode,
        BreachedPasswordKnowledge? knowledge = null,
        ISecurityDecisionTelemetry? telemetry = null)
    {
        _failureMode = failureMode;
        _knowledge = knowledge
            ?? new BreachedPasswordKnowledge(new PasswordPolicyOptions());
        _telemetry = telemetry ?? new SecurityDecisionTelemetry();
        _httpClient = httpClient;
        // Only set defaults if the HttpClient hasn't been pre-configured
        // (e.g. by a test with a custom BaseAddress/handler).
        if (_httpClient.BaseAddress is null)
        {
            _httpClient.BaseAddress = new Uri(HibpRangeApiUrl);
        }
        _httpClient.DefaultRequestHeaders.UserAgent.Add(
            new ProductInfoHeaderValue("Sufficit-Identity", "1.0"));
        _httpClient.Timeout = TimeSpan.FromSeconds(5);
        _logger = logger;
    }

    public async Task<IdentityResult> ValidateAsync(
        UserManager<ApplicationUser> manager,
        ApplicationUser user,
        string? password)
    {
        if (string.IsNullOrEmpty(password))
        {
            return IdentityResult.Success;
        }

        var (prefix, suffix) = HashPassword(password);

        // An answer already given covers every password sharing this prefix,
        // so a repeat costs nothing and an outage does not reach it.
        if (_knowledge.TryGetRange(prefix) is { } cached)
        {
            _telemetry.Record(
                "breached_password_check",
                _failureMode.ToString(),
                wouldReject: cached.Contains(suffix),
                rejected: cached.Contains(suffix),
                ["served_from_cache"]);
            return cached.Contains(suffix) ? Breached() : IdentityResult.Success;
        }

        try
        {
            var response = await _httpClient.GetAsync(prefix);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning(
                    "HIBP range API returned {Status}; breached-password check did not complete ({FailureMode}).",
                    (int)response.StatusCode,
                    _failureMode);
                return CheckUnavailable(password, "upstream_status");
            }

            var body = await response.Content.ReadAsStringAsync();
            var suffixes = ParseRange(body);
            if (suffixes is null)
            {
                // A body that is not a range listing means the check did not
                // happen, whatever the status code said. Treating it as "no
                // match" would silently turn every password into a pass.
                _logger.LogWarning(
                    "HIBP range API returned an unreadable body; breached-password "
                    + "check did not complete ({FailureMode}).",
                    _failureMode);
                return CheckUnavailable(password, "upstream_malformed");
            }

            _knowledge.StoreRange(prefix, suffixes);
            var breached = suffixes.Contains(suffix);
            _telemetry.Record(
                "breached_password_check",
                _failureMode.ToString(),
                wouldReject: breached,
                rejected: breached,
                ["completed"]);
            return breached ? Breached() : IdentityResult.Success;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            _logger.LogWarning(exception,
                "Breached-password check failed ({FailureMode}).",
                _failureMode);
            return CheckUnavailable(password, "upstream_unreachable");
        }
    }

    private static IdentityResult Breached() =>
        IdentityResult.Failed(new IdentityError
        {
            Code = "PasswordBreached",
            Description = "This password has appeared in a known data breach. Choose a different password.",
        });

    /// <summary>
    /// The suffix set of a range response, or <see langword="null"/> when the
    /// body is not one.
    /// </summary>
    private static HashSet<string>? ParseRange(string body)
    {
        var suffixes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in body.AsSpan().EnumerateLines())
        {
            if (line.IsWhiteSpace())
            {
                continue;
            }

            var colon = line.IndexOf(':');
            // Every line is "SUFFIX:COUNT", and the suffix is the 35 hex
            // characters that follow the 5 sent as the prefix.
            if (colon != 35 || !IsHex(line[..colon]))
            {
                return null;
            }

            suffixes.Add(new string(line[..colon]));
        }

        return suffixes.Count == 0 ? null : suffixes;
    }

    private static bool IsHex(ReadOnlySpan<char> value)
    {
        foreach (var character in value)
        {
            if (!char.IsAsciiHexDigit(character))
            {
                return false;
            }
        }

        return true;
    }

    private IdentityResult CheckUnavailable(string password, string reason)
    {
        // LocalFallback answers from what is known here rather than choosing
        // between letting a known-breached password through and stopping every
        // password change in the deployment.
        var locallyBreached =
            _failureMode == BreachedPasswordFailureMode.LocalFallback
            && _knowledge.IsLocallyKnownBreached(password);
        var rejected = locallyBreached
            || _failureMode == BreachedPasswordFailureMode.FailClosed;

        _telemetry.Record(
            "breached_password_check",
            _failureMode.ToString(),
            wouldReject: true,
            rejected: rejected,
            [reason, locallyBreached ? "local_fallback_match" : "degraded"]);

        if (locallyBreached)
        {
            return Breached();
        }

        return _failureMode == BreachedPasswordFailureMode.FailClosed
            ? IdentityResult.Failed(new IdentityError
            {
                Code = "PasswordBreachCheckUnavailable",
                Description = "The password could not be checked against known data breaches. Try again later.",
            })
            : IdentityResult.Success;
    }

    /// <summary>
    /// Returns the (prefix, suffix) of the SHA-1 hash: first 5 hex chars as
    /// prefix (sent to API), rest as suffix (compared locally). k-anonymity
    /// means the API never learns enough to reconstruct the password.
    /// </summary>
    private static (string Prefix, string Suffix) HashPassword(string password)
    {
        var hash = SHA1.HashData(Encoding.UTF8.GetBytes(password));
        var hex = Convert.ToHexString(hash);
        return (hex[..5], hex[5..]);
    }
}
