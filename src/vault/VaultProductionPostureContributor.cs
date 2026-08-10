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
    }
}
