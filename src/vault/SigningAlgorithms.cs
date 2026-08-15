using System.Text.Json;

namespace Sufficit.Identity.Vault;

/// <summary>
/// Signing-algorithm agility for vault-managed signing keys (A6, eval
/// 2026-08-14). Each key VERSION carries its algorithm inside the stored
/// public JWK (<c>alg</c> member), so rotation can move between families
/// (RS256 → PS256 → ES256) without any schema change: verification and
/// re-signing of in-flight versions always use the algorithm the version was
/// created with, while <c>VaultOptions.SigningAlgorithm</c> governs what the
/// NEXT created/rotated version uses. FAPI-leaning deployments need PS256 or
/// ES256 (the profile's JWS baseline) — RS256 remains the default for
/// backward compatibility.
/// </summary>
public static class SigningAlgorithms
{
    public const string RsaSha256 = "RS256";
    public const string RsaPssSha256 = "PS256";
    public const string EcdsaSha256 = "ES256";

    /// <summary>Algorithms a new signing-key version may be created with.</summary>
    public static readonly IReadOnlySet<string> Supported = new HashSet<string>(
        [RsaSha256, RsaPssSha256, EcdsaSha256], StringComparer.Ordinal);

    /// <summary>
    /// Reads the <c>alg</c> member of a stored signing JWK. Legacy RSA rows
    /// already embedded <c>alg</c>; anything missing it is treated as RS256
    /// (the value every pre-A6 key was created with).
    /// </summary>
    public static string FromJwk(string? publicJwk)
    {
        if (string.IsNullOrWhiteSpace(publicJwk))
        {
            return RsaSha256;
        }

        try
        {
            using var document = JsonDocument.Parse(publicJwk);
            return document.RootElement.TryGetProperty(
                "alg", out var alg)
                && alg.ValueKind == JsonValueKind.String
                && Supported.Contains(alg.GetString()!)
                ? alg.GetString()!
                : RsaSha256;
        }
        catch (JsonException)
        {
            return RsaSha256;
        }
    }

    /// <summary>True when the JWK describes an elliptic-curve key.</summary>
    public static bool IsEc(string? publicJwk)
    {
        if (string.IsNullOrWhiteSpace(publicJwk)) return false;
        try
        {
            using var document = JsonDocument.Parse(publicJwk);
            return document.RootElement.TryGetProperty("kty", out var kty)
                && kty.ValueKind == JsonValueKind.String
                && kty.GetString() == "EC";
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
