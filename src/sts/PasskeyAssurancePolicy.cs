using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Sufficit.Identity.Application.Accounts;

namespace Sufficit.Identity.STS;

/// <summary>
/// Reads the WebAuthn authenticator-data flags out of a serialized credential
/// so the server states what the ceremony proved instead of assuming it.
/// </summary>
/// <remarks>
/// The flags come from the same <c>authenticatorData</c> the assertion's
/// signature covers, so a forged flag cannot survive the ceremony: ASP.NET
/// Identity verifies that signature. Reading it up front only decides whether
/// to refuse early; the claims derived from it are applied after the ceremony
/// succeeded, which is when the bytes are known to be authentic.
/// </remarks>
internal sealed class PasskeyAssurancePolicy(AccountPasskeyOptions options)
    : IPasskeyAssurancePolicy
{
    // WebAuthn Level 3, 6.1: rpIdHash (32 bytes), then the flags byte.
    private const int FlagsOffset = 32;
    private const byte UserPresentFlag = 0x01;
    private const byte UserVerifiedFlag = 0x04;

    public string UserVerificationRequirement { get; } =
        options.RequireUserVerification ? "required" : "preferred";

    public bool RequireUserVerification { get; } = options.RequireUserVerification;

    public PasskeyAssertionEvidence? Read(string credentialJson)
    {
        if (string.IsNullOrWhiteSpace(credentialJson))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(credentialJson);
            if (!document.RootElement.TryGetProperty("response", out var response)
                || !response.TryGetProperty("authenticatorData", out var encoded)
                || encoded.ValueKind != JsonValueKind.String)
            {
                return null;
            }

            var bytes = Base64UrlTextEncoder.Decode(encoded.GetString()!);
            if (bytes.Length <= FlagsOffset)
            {
                return null;
            }

            var flags = bytes[FlagsOffset];
            return new PasskeyAssertionEvidence(
                UserPresent: (flags & UserPresentFlag) != 0,
                UserVerified: (flags & UserVerifiedFlag) != 0);
        }
        catch (Exception exception)
            when (exception is JsonException or FormatException)
        {
            return null;
        }
    }

    public IReadOnlyCollection<string> AuthenticationMethods(
        PasskeyAssertionEvidence evidence) =>
        // "hwk" and "passkey" are possession; "mfa" says a second, different
        // factor was presented, and only user verification is that factor.
        evidence.UserVerified
            ? ["passkey", "hwk", "mfa"]
            : ["passkey", "hwk"];
}
