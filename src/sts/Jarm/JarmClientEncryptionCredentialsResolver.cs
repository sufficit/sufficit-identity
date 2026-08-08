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

        // Accept an encryption-eligible key of either family. A key qualifies
        // when it is not restricted to signing: use=enc, or key_ops naming an
        // encryption/key-wrap operation. RSA and EC are both valid recipient
        // key types (a FAPI client may register either), so the resolver must
        // not hard-restrict to RSA — doing so would reject a correctly
        // configured EC client and silently fail the JARM response.
        static bool IsEncryptionEligible(Microsoft.IdentityModel.Tokens.JsonWebKey candidate) =>
            string.Equals(candidate.Use, "enc", StringComparison.Ordinal)
            || candidate.KeyOps.Contains("encrypt", StringComparer.Ordinal)
            || candidate.KeyOps.Contains("wrapKey", StringComparer.Ordinal)
            || candidate.KeyOps.Contains("deriveKey", StringComparer.Ordinal);

        var key = keySet?.Keys.FirstOrDefault(candidate =>
            (string.Equals(candidate.Kty, "RSA", StringComparison.Ordinal)
                || string.Equals(candidate.Kty, "EC", StringComparison.Ordinal))
            && IsEncryptionEligible(candidate));
        if (key is null)
        {
            return null;
        }

        var publicKey = JsonWebKey.Create(JsonSerializer.Serialize(key));
        var encryption = options.Jarm.Encryption;

        // Choose the key-management (JWE alg) algorithm by recipient key type:
        // RSA keys use RSA-OAEP-256, EC keys use ECDH-ES key agreement.
        var keyManagementAlgorithm =
            string.Equals(key.Kty, "EC", StringComparison.Ordinal)
                ? encryption.EcKeyManagementAlgorithm
                : encryption.KeyManagementAlgorithm;

        return new EncryptingCredentials(
            publicKey,
            keyManagementAlgorithm,
            encryption.ContentEncryptionAlgorithm);
    }
}
