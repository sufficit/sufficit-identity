using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.Vault;

public sealed class VaultProductionPostureContributor(VaultOptions options)
    : IProductionPostureContributor
{
    public IEnumerable<ProductionPostureFinding> Evaluate()
    {
        if (!options.Enabled)
        {
            yield return new(
                "vault-plaintext-compatibility",
                "The internal vault is disabled and IKeyVault resolves to reversible pt1 compatibility storage.",
                "Migrate pt1 values, set Sufficit:Vault:Enabled=true and require encryption in production.");
        }
        else if (string.Equals(options.KeySource, "dataprotection", StringComparison.OrdinalIgnoreCase))
        {
            // V11 (evaluation 2026-09-12): advisory by the maintainer's decision.
            yield return new(
                "vault-kek-in-data-protection",
                "The vault key-encryption key is protected by the Data Protection key ring, which is stored in the same database as the wrapped data keys, so a copy of that database carries both.",
                "Set Sufficit:Vault:KeySource=certificate with a dedicated CertificatePath readable only by the service account.",
                Severity: ProductionPostureSeverity.Advisory);
        }
    }
}
