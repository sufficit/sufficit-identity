using System.Text.Json;

namespace Sufficit.Identity.Core.Services;

/// <summary>
/// A confidential client that authenticates as a system user.
///
/// Software that runs on servers authenticates with <c>client_credentials</c>:
/// a secret it already holds, no rotating refresh token to persist on every
/// node. Without a binding that token has no user behind it, so anything the
/// software is allowed to do had to be granted to the CLIENT, a second
/// authority model next to users. With the binding, the client is only how
/// the software proves who it is; the token names the system user, and what
/// it may do comes from that user like for everyone else.
///
/// The binding lives in the client's own properties, written by an operator
/// who can manage both the client and system users. Only a system user can be
/// bound: an account that can sign in interactively is refused when the token
/// is issued, so a client secret never becomes a way into a person's account.
/// </summary>
public static class SystemUserClientBinding
{
    public const string PropertyName = "identity:client:system-user";

    public static string? Read(IReadOnlyDictionary<string, JsonElement> properties) =>
        properties.TryGetValue(PropertyName, out var value)
            && value.ValueKind == JsonValueKind.String
            && !string.IsNullOrWhiteSpace(value.GetString())
            ? value.GetString()!.Trim()
            : null;
}
