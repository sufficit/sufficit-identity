namespace Sufficit.Identity.Management.Provisioning;

internal sealed class MissingClientSecretResolver : IClientSecretResolver
{
    public ValueTask<string> ResolveAsync(
        string reference,
        CancellationToken cancellationToken = default) =>
        throw new ClientSecretResolverUnavailableException();
}
