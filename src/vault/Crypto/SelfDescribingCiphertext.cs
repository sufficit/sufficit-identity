using System.Globalization;
using System.Security.Cryptography;
using Microsoft.AspNetCore.WebUtilities;

namespace Sufficit.Identity.Vault.Crypto;

/// <summary>
/// Self-describing ciphertext format (Vault Transit / age inspired):
/// <code>
/// v1.&lt;keyName&gt;:&lt;keyVersion&gt;.&lt;base64url(nonce‖ct‖tag)&gt;.&lt;base64url(aadHash)&gt;
/// </code>
/// The key name and version are embedded, so decryption picks the right key
/// version for free — no side table needed. The AAD hash (first 8 bytes of
/// HMAC-SHA256 over the AAD, keyed by the DEK) lets us fail-fast on AAD
/// mismatch / field-swap without exposing the AAD itself (sops MAC pattern).
/// When there is no AAD, the hash segment is empty.
/// </summary>
internal static class SelfDescribingCiphertext
{
    public const string Scheme = "v1";
    // Marker prefix for the pass-through (no-crypto) variant.
    public const string PassThroughPrefix = "pt1.";

    /// <summary>
    /// Formats a complete ciphertext string from its components.
    /// </summary>
    public static string Format(
        string keyName,
        int keyVersion,
        byte[] packedCiphertext, // nonce ‖ ct ‖ tag from EnvelopeCrypto
        byte[]? aadHash) // null when no AAD
    {
        var blob = WebEncoders.Base64UrlEncode(packedCiphertext);
        var hash = aadHash is null ? "" : WebEncoders.Base64UrlEncode(aadHash);
        return $"{Scheme}.{keyName}:{keyVersion}.{blob}.{hash}";
    }

    /// <summary>
    /// Parses a ciphertext string into its components.
    /// </summary>
    public static ParsedCiphertext Parse(string ciphertext)
    {
        var rest = ciphertext;
        string scheme;
        var dot = rest.IndexOf('.');
        if (dot < 0)
        {
            throw new FormatException("Ciphertext has no scheme separator.");
        }
        scheme = rest[..dot];
        rest = rest[(dot + 1)..];

        if (scheme != Scheme)
        {
            throw new FormatException($"Unsupported ciphertext scheme '{scheme}'.");
        }

        // keyName:version.blob.hash
        dot = rest.IndexOf('.');
        if (dot < 0)
        {
            throw new FormatException("Ciphertext has no key/blob separator.");
        }
        var keyPart = rest[..dot];
        rest = rest[(dot + 1)..];

        var colon = keyPart.IndexOf(':');
        if (colon < 0)
        {
            throw new FormatException("Ciphertext key part has no version separator.");
        }
        var keyName = keyPart[..colon];
        var keyVersion = int.Parse(keyPart[(colon + 1)..], CultureInfo.InvariantCulture);

        // blob.hash
        dot = rest.IndexOf('.');
        byte[] packed;
        byte[]? aadHash;
        if (dot < 0)
        {
            // No hash segment (no AAD).
            packed = WebEncoders.Base64UrlDecode(rest);
            aadHash = null;
        }
        else
        {
            packed = WebEncoders.Base64UrlDecode(rest[..dot]);
            var hashSegment = rest[(dot + 1)..];
            aadHash = string.IsNullOrEmpty(hashSegment) ? null : WebEncoders.Base64UrlDecode(hashSegment);
        }

        return new ParsedCiphertext(keyName, keyVersion, packed, aadHash);
    }

    /// <summary>
    /// Computes the AAD hash: first 8 bytes of HMAC-SHA256 over the
    /// canonicalized AAD, keyed by the DEK. This binds the ciphertext to its
    /// owner/scope and detects field-swap tampering.
    /// </summary>
    public static byte[] ComputeAadHash(IReadOnlyDictionary<string, string>? aad, byte[] dek)
    {
        if (aad is null || aad.Count == 0) return Array.Empty<byte>();

        // Canonicalize AAD: sorted keys, key=value joined by '&'.
        var pairs = aad
            .OrderBy(kv => kv.Key, StringComparer.Ordinal)
            .Select(kv => $"{kv.Key}={kv.Value}");
        var canonical = string.Join('&', pairs);
        var canonicalBytes = System.Text.Encoding.UTF8.GetBytes(canonical);

        using var hmac = new HMACSHA256(dek);
        var fullHash = hmac.ComputeHash(canonicalBytes);
        var truncated = new byte[8];
        Buffer.BlockCopy(fullHash, 0, truncated, 0, 8);
        return truncated;
    }

    /// <summary>
    /// Canonicalizes AAD to bytes for the GCM AAD input (separate from the
    /// hash — GCM binds the actual AAD bytes to the tag).
    /// </summary>
    public static byte[] CanonicalizeAad(IReadOnlyDictionary<string, string>? aad)
    {
        if (aad is null || aad.Count == 0) return Array.Empty<byte>();
        var pairs = aad
            .OrderBy(kv => kv.Key, StringComparer.Ordinal)
            .Select(kv => $"{kv.Key}={kv.Value}");
        return System.Text.Encoding.UTF8.GetBytes(string.Join('&', pairs));
    }
}

internal sealed record ParsedCiphertext(
    string KeyName,
    int KeyVersion,
    byte[] PackedCiphertext,
    byte[]? AadHash);
