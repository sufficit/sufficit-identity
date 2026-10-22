using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Core.Data;

namespace Sufficit.Identity.Vault;

/// <summary>Outcome of decrypting one kind of vault-protected value. Ids only, never values.</summary>
public sealed record VaultVerificationResult(string Kind, int Decrypted, IReadOnlyList<string> Failed);

/// <summary>
/// Proves that the vault-protected data in a database decrypts with the key
/// authority this process holds — the question a restored backup has to answer
/// (plan C1). Every value is decrypted and discarded; only counts and the ids
/// of failures come out.
/// </summary>
public static class VaultRestoreVerification
{
    public static async Task<VaultVerificationResult> VerifyNamedSecretsAsync(
        AppDbContext database, IKeyVault vault, CancellationToken cancellationToken = default)
    {
        var decrypted = 0;
        var failed = new List<string>();
        foreach (var secret in await database.VaultSecrets.AsNoTracking().ToListAsync(cancellationToken))
        {
            try
            {
                await vault.DecryptAsync(secret.Ciphertext, VaultBackedSecretStore.ReadAad(secret), cancellationToken);
                decrypted++;
            }
            catch (Exception) when (!cancellationToken.IsCancellationRequested)
            {
                failed.Add(secret.Id.ToString());
            }
        }
        return new("named-secrets", decrypted, failed);
    }
}
