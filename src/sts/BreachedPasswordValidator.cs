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
/// password validation. If the HIBP API is unreachable, the validator
/// PASSES the password (fail-open) rather than blocking all user
/// operations — consistent with the documented <c>RejectBreached</c>
/// opt-in posture. Flip to fail-closed only in regulated environments
/// where availability of HIBP is guaranteed.
/// </remarks>
public sealed class BreachedPasswordValidator : IPasswordValidator<ApplicationUser>
{
    private const string HibpRangeApiUrl = "https://api.pwnedpasswords.com/range/";
    private readonly HttpClient _httpClient;
    private readonly ILogger<BreachedPasswordValidator> _logger;

    public BreachedPasswordValidator(HttpClient httpClient, ILogger<BreachedPasswordValidator> logger)
    {
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
                // API unavailable — fail-open (let the password through).
                _logger.LogWarning(
                    "HIBP range API returned {Status}; skipping breached-password check.",
                    (int)response.StatusCode);
                return IdentityResult.Success;
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
            // Network/timeout/parse failure — fail-open.
            _logger.LogWarning(exception,
                "Breached-password check failed; skipping validation.");
            return IdentityResult.Success;
        }
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
