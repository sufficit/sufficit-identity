using OpenIddict.Abstractions;
using Sufficit.Identity.Application.Accounts;

namespace Sufficit.Identity.STS;

/// <summary>
/// Resolves the device close fallback URL from the OpenIddict client record,
/// where it is stored as the <c>device_close_fallback_url</c> extension
/// metadata (RFC 7591, section 2) — per client, in the database.
/// </summary>
public sealed class OpenIddictDeviceCloseFallbackResolver(
    IOpenIddictApplicationManager applications) : IClientDeviceCloseFallbackResolver
{
    public async Task<string?> ResolveAsync(
        string? clientId,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(clientId))
        {
            return null;
        }

        var application = await applications.FindByClientIdAsync(
            clientId,
            cancellationToken);
        if (application is null)
        {
            return null;
        }

        return DeviceCloseFallbackPolicy.Read(
            await applications.GetPropertiesAsync(application, cancellationToken));
    }
}
