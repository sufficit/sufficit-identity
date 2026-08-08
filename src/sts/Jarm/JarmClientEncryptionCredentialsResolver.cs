using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;

namespace Sufficit.Identity.STS.Jarm;

internal interface IJarmClientEncryptionCredentialsResolver
{
    ValueTask<EncryptingCredentials?> ResolveAsync(
        string clientId,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Resolves JARM encryption solely from the recipient client's public JWKS.
/// The authorization server never uses a server-global private key as the
/// recipient key for every client.
/// </summary>
internal sealed class JarmClientEncryptionCredentialsResolver(
    IOpenIddictApplicationManager applications,
    SufficitIdentityOptions options)
    : IJarmClientEncryptionCredentialsResolver
{
    public async ValueTask<EncryptingCredentials?> ResolveAsync(
        string clientId,
        CancellationToken cancellationToken = default)
    {
        var application = await applications.FindByClientIdAsync(
            clientId,
            cancellationToken);
        if (application is null)
        {
            return null;
        }

        var keySet = await applications.GetJsonWebKeySetAsync(
            application,
            cancellationToken);
        var key = keySet?.Keys.FirstOrDefault(candidate =>
            string.Equals(candidate.Kty, "RSA", StringComparison.Ordinal)
            && (string.Equals(candidate.Use, "enc", StringComparison.Ordinal)
                || candidate.KeyOps.Contains("encrypt", StringComparer.Ordinal)
                || candidate.KeyOps.Contains("wrapKey", StringComparer.Ordinal)));
        if (key is null)
        {
            return null;
        }

        var publicKey = JsonWebKey.Create(JsonSerializer.Serialize(key));
        var encryption = options.Jarm.Encryption;
        return new EncryptingCredentials(
            publicKey,
            encryption.KeyManagementAlgorithm,
            encryption.ContentEncryptionAlgorithm);
    }
}
