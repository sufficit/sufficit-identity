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

    [Microsoft.Extensions.DependencyInjection.ActivatorUtilitiesConstructor]
    public BreachedPasswordValidator(
        HttpClient httpClient,
        ILogger<BreachedPasswordValidator> logger,
        SufficitIdentityOptions options)
        : this(httpClient, logger, options.Password.BreachedCheckFailureMode)
    {
    }

    public BreachedPasswordValidator(HttpClient httpClient, ILogger<BreachedPasswordValidator> logger)
        : this(httpClient, logger, BreachedPasswordFailureMode.FailOpen)
    {
    }

    public BreachedPasswordValidator(
        HttpClient httpClient,
        ILogger<BreachedPasswordValidator> logger,
        BreachedPasswordFailureMode failureMode)
    {
        _failureMode = failureMode;
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

        try
        {
            var (prefix, suffix) = HashPassword(password);
            var response = await _httpClient.GetAsync(prefix);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning(
                    "HIBP range API returned {Status}; breached-password check did not complete ({FailureMode}).",
                    (int)response.StatusCode,
                    _failureMode);
                return CheckUnavailable();
            }

            var body = await response.Content.ReadAsStringAsync();
            // Response format: "SUFFIX:COUNT\r\nSUFFIX:COUNT\r\n..."
            foreach (var line in body.AsSpan().EnumerateLines())
            {
                var colon = line.IndexOf(':');
                if (colon > 0 && line[..colon].SequenceEqual(suffix))
                {
                    return IdentityResult.Failed(new IdentityError
                    {
                        Code = "PasswordBreached",
                        Description = "This password has appeared in a known data breach. Choose a different password.",
                    });
                }
            }

            return IdentityResult.Success;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            _logger.LogWarning(exception,
                "Breached-password check failed ({FailureMode}).",
                _failureMode);
            return CheckUnavailable();
        }
    }

    private IdentityResult CheckUnavailable() =>
        _failureMode == BreachedPasswordFailureMode.FailClosed
            ? IdentityResult.Failed(new IdentityError
            {
                Code = "PasswordBreachCheckUnavailable",
                Description = "The password could not be checked against known data breaches. Try again later.",
            })
            : IdentityResult.Success;

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
