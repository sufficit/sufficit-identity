using System.Security.Cryptography;

namespace Sufficit.Identity.Tests.Infrastructure;

/// <summary>
/// Minimal RFC 7636 (PKCE) helper: generates a random <c>code_verifier</c>
/// and its matching S256 <c>code_challenge</c>, so integration tests can
/// drive the authorization_code grant the way a real public client would.
/// </summary>
internal static class Pkce
{
    public static (string Verifier, string Challenge) CreatePair()
    {
        // 96 random bytes -> 128 base64url characters, within RFC 7636's
        // 43-128 character allowed range for code_verifier.
        var bytes = RandomNumberGenerator.GetBytes(96);
        var verifier = Base64UrlEncode(bytes);

        var challenge = Base64UrlEncode(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(verifier)));

        return (verifier, challenge);
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
