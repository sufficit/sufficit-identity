using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;

namespace Sufficit.Identity.Management.Authorization;

/// <summary>
/// The roles a client's registration declares.
///
/// Deliberately narrow interface: the resolver needs ONE question, and
/// depending on the entire <c>IOpenIddictApplicationManager</c> for it would
/// force every test to fake some forty operations it doesn't use — a double
/// that lies about what it exercises.
/// </summary>
public interface IServicePrincipalRoleSource
{
    ValueTask<IReadOnlyCollection<string>> RolesAsync(
        string clientId,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Reads the roles from the client's property in the database — the same
/// <c>identity:client:*</c> convention that dynamic registration already uses
/// for origin, user-agent and registration date.
/// </summary>
public sealed class OpenIddictServicePrincipalRoleSource(
    IOpenIddictApplicationManager applications,
    IOptions<ManagementOptions> options) : IServicePrincipalRoleSource
{
    public async ValueTask<IReadOnlyCollection<string>> RolesAsync(
        string clientId,
        CancellationToken cancellationToken = default)
    {
        var application = await applications.FindByClientIdAsync(clientId, cancellationToken);
        if (application is null)
        {
            return [];
        }

        var properties = await applications.GetPropertiesAsync(application, cancellationToken);
        return properties.TryGetValue(
            options.Value.Authorization.ClientRolesPropertyName, out var declared)
            ? Parse(declared)
            : [];
    }

    /// <summary>
    /// The property is persisted as <see cref="JsonElement"/>. Accepts both a
    /// list and a single string: whoever writes it by hand usually writes the
    /// string, and rejecting that would be a silent rejection — the client
    /// would end up with no capabilities at all, and nothing would say why.
    /// </summary>
    private static IReadOnlyCollection<string> Parse(JsonElement declared)
    {
        var roles = ImmutableArray.CreateBuilder<string>();

        switch (declared.ValueKind)
        {
            case JsonValueKind.Array:
                foreach (var item in declared.EnumerateArray())
                {
                    var value = item.ValueKind == JsonValueKind.String ? item.GetString() : null;
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        roles.Add(value.Trim());
                    }
                }
                break;

            case JsonValueKind.String:
                foreach (var value in (declared.GetString() ?? string.Empty)
                    .Split([' ', ','], StringSplitOptions.RemoveEmptyEntries))
                {
                    roles.Add(value.Trim());
                }
                break;
        }

        return roles.ToImmutable();
    }
}
