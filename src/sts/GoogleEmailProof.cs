using System.Text.Json;

namespace Sufficit.Identity.STS;

/// <summary>
/// Google is authoritative for Gmail and verified Workspace addresses, but
/// email_verified alone can describe historical ownership of a third-party
/// mailbox. See https://developers.google.com/identity/sign-in/web/backend-auth.
/// </summary>
internal static class GoogleEmailProof
{
    public static string FromProfile(JsonElement profile)
    {
        var verified = profile.TryGetProperty("email_verified", out var proof)
            && proof.ValueKind == JsonValueKind.True;
        var email = profile.TryGetProperty("email", out var address)
            && address.ValueKind == JsonValueKind.String ? address.GetString() : null;
        var hosted = profile.TryGetProperty("hd", out var domain)
            && domain.ValueKind == JsonValueKind.String
            && !string.IsNullOrWhiteSpace(domain.GetString());
        return verified && !string.IsNullOrWhiteSpace(email)
            && (email.EndsWith("@gmail.com", StringComparison.OrdinalIgnoreCase) || hosted)
                ? "true" : "false";
    }
}
