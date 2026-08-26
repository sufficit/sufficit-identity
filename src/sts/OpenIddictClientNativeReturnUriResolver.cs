using System.Text.Json;
using OpenIddict.Abstractions;
using Sufficit.Identity.Application.Accounts;

namespace Sufficit.Identity.STS;

/// <summary>
/// Resolves native callbacks from the OpenIddict client record, where they are
/// stored as the <c>native_return_uris</c> extension metadata (RFC 7591,
/// section 2).
/// </summary>
public sealed class OpenIddictClientNativeReturnUriResolver(
    IOpenIddictApplicationManager applications) : IClientNativeReturnUriResolver
{
    public async Task<IReadOnlyList<string>> ListAsync(
        string? clientId,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(clientId))
        {
            return [];
        }

        var application = await applications.FindByClientIdAsync(
            clientId,
            cancellationToken);
        if (application is null)
        {
            return [];
        }

        var properties = await applications.GetPropertiesAsync(
            application,
            cancellationToken);
        return Read(properties);
    }

    public async Task<string?> ResolveAsync(
        string? clientId,
        string? candidate,
        CancellationToken cancellationToken = default)
    {
        var registered = await ListAsync(clientId, cancellationToken);
        if (registered.Count == 0)
        {
            return null;
        }

        return string.IsNullOrWhiteSpace(candidate)
            ? registered[0]
            : NativeReturnUriPolicy.Match(registered, candidate);
    }

    /// <summary>
    /// Reads the registered callbacks out of a client property bag. Entries
    /// that no longer satisfy the current policy are dropped rather than
    /// returned, so tightening the rules retroactively disables a stale
    /// registration instead of trusting it.
    /// </summary>
    public static IReadOnlyList<string> Read(
        IReadOnlyDictionary<string, JsonElement>? properties)
    {
        if (properties is null
            || !properties.TryGetValue(
                NativeReturnUriPolicy.PropertyKey,
                out var value)
            || value.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        return value.EnumerateArray()
            .Where(element => element.ValueKind == JsonValueKind.String)
            .Select(element => element.GetString())
            .Where(uri => NativeReturnUriPolicy.TryValidateRegistration(
                uri,
                out _,
                out _,
                out _))
            .Select(uri => uri!.Trim())
            .Distinct(StringComparer.Ordinal)
            .Take(NativeReturnUriPolicy.MaximumRegistrations)
            .ToArray();
    }
}
