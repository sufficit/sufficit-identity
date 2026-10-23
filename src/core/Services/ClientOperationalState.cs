using System.Text.Json;

namespace Sufficit.Identity.Core.Services;

/// <summary>Why and since when a client stopped being served.</summary>
public sealed record ClientDisablement(DateTimeOffset AtUtc, string By, string? Reason);

/// <summary>
/// A client's operational state (plan E1), kept in the application's own
/// property bag: no row means the client is active, so every existing client
/// keeps working. The manifest provisioner preserves keys it does not manage,
/// so re-applying a manifest never re-enables a disabled client.
/// </summary>
public static class ClientOperationalState
{
    public const string PropertyName = "sufficit:disabled";
    public const string Active = "active";
    public const string Disabled = "disabled";
    public const int MaxReasonLength = 500;

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public static ClientDisablement? Read(IReadOnlyDictionary<string, JsonElement> properties) =>
        properties.TryGetValue(PropertyName, out var value) ? Parse(value) : null;

    /// <summary>Reads the raw <c>properties</c> column; a malformed blob reads as active.</summary>
    public static ClientDisablement? Read(string? propertiesJson)
    {
        if (string.IsNullOrWhiteSpace(propertiesJson) || !propertiesJson.Contains(PropertyName, StringComparison.Ordinal))
            return null;
        try
        {
            using var document = JsonDocument.Parse(propertiesJson);
            return document.RootElement.ValueKind == JsonValueKind.Object
                && document.RootElement.TryGetProperty(PropertyName, out var value)
                    ? Parse(value)
                    : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public static JsonElement Write(ClientDisablement disablement) =>
        JsonSerializer.SerializeToElement(disablement, Json);

    private static ClientDisablement? Parse(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object) return null;
        try
        {
            return value.Deserialize<ClientDisablement>(Json);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}

/// <summary>
/// The set of disabled clients, held in memory on every replica: the check on
/// each request is a set lookup, never a query. Each replica re-reads it on a
/// short interval and immediately when another replica announces a change.
/// </summary>
public interface IDisabledClientRegistry
{
    bool IsDisabled(string? clientId);

    /// <summary>Re-reads the set here and tells the other replicas to do the same.</summary>
    Task PublishChangeAsync(CancellationToken cancellationToken = default);
}
