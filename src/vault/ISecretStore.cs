namespace Sufficit.Identity.Vault;

/// <summary>
/// Configuration-time secret boundary. Consumers ask for a logical name and
/// do not need to know whether the value came from an environment variable,
/// configuration provider, or a future named-secret backend.
/// </summary>
public interface ISecretStore
{
    Task<string?> GetSecretAsync(
        string name,
        CancellationToken cancellationToken = default);
}
