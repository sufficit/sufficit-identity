using System.Collections.Immutable;
using System.Text.Json;

namespace Sufficit.Identity.STS;

/// <summary>
/// Entitlements granted to a client registration.
/// </summary>
/// <remarks>
/// A <c>client_credentials</c> token does not go through any claims source:
/// the handler assembles a raw identity with <c>sub</c>, name, scopes and
/// resources. That left a machine account with no way to receive a grant
/// other than a role — and a role is a category, not an instance. An agent
/// that needs to access context <c>X</c> needs to say WHICH context, and
/// that is a value.
/// <para>
/// The grant lives in the client's own <c>identity:client:entitlements</c>
/// property, the same convention as <c>identity:client:roles</c>: the
/// database says who has what, and revoking is an UPDATE, with no
/// deployment.
/// </para>
/// <para>
/// The claim type is fixed here on purpose. Letting the operator choose the
/// type would let them write <c>role</c> or <c>scope</c> and escalate on
/// their own — that is exactly the hole scope entitlements had to close with
/// a list of forbidden types. Here there is no choice.
/// </para>
/// </remarks>
public static class ClientEntitlements
{
    /// <summary>Client property that holds the grant.</summary>
    public const string PropertyName = "identity:client:entitlements";

    /// <summary>
    /// Container standardized by RFC 9068 §2.2.3.1, with SCIM semantics
    /// (RFC 7643 §4.1.2).
    /// </summary>
    public const string ClaimType = "entitlements";

    /// <summary>
    /// Short name already consumed by our own services (sufficit-ai and
    /// sufficit-provisioning). Emitted in parallel during the transition: it
    /// is not in the IANA registry and RFC 7519 §4.3 asks for
    /// collision-resistant names, but cutting it before the consumers
    /// migrate would break things to gain elegance.
    /// </summary>
    public const string LegacyClaimType = "directive";

    /// <summary>Defensive limit: a token is not a place for free-form text.</summary>
    private const int MaximumLength = 256;

    /// <summary>
    /// Reads the property and returns only the usable values.
    /// </summary>
    /// <remarks>
    /// Accepts a list and a single string, like the role reader: whoever
    /// writes it by hand tends to write the string, and silently refusing it
    /// would leave the client with no capability at all without saying why.
    /// </remarks>
    public static IReadOnlyCollection<string> Read(
        IReadOnlyDictionary<string, JsonElement> properties)
    {
        ArgumentNullException.ThrowIfNull(properties);

        if (!properties.TryGetValue(PropertyName, out var declared))
        {
            return [];
        }

        var values = ImmutableArray.CreateBuilder<string>();

        switch (declared.ValueKind)
        {
            case JsonValueKind.String:
                Collect(declared.GetString(), values);
                break;

            case JsonValueKind.Array:
                foreach (var element in declared.EnumerateArray())
                {
                    if (element.ValueKind == JsonValueKind.String)
                    {
                        Collect(element.GetString(), values);
                    }
                }

                break;
        }

        return values.Distinct(StringComparer.Ordinal).ToArray();
    }

    /// <summary>
    /// An entitlement needs to survive transport without changing meaning.
    /// </summary>
    /// <remarks>
    /// Whitespace is rejected because consumers treat lists as space
    /// separated; a value with a space would become two on the other side.
    /// Control characters are rejected because they cross logs and headers.
    /// </remarks>
    public static bool IsUsable(string? value) =>
        !string.IsNullOrWhiteSpace(value)
        && value.Length <= MaximumLength
        && value.Trim().Length == value.Length
        && !value.Any(character => char.IsWhiteSpace(character)
            || char.IsControl(character));

    private static void Collect(string? value, ImmutableArray<string>.Builder values)
    {
        if (IsUsable(value))
        {
            values.Add(value!);
        }
    }
}
