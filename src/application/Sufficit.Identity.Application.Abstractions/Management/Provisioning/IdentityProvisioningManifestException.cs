namespace Sufficit.Identity.Management.Provisioning;

public sealed class IdentityProvisioningManifestException : Exception
{
    public IdentityProvisioningManifestException(IReadOnlyList<string> errors)
        : base($"The identity provisioning manifest is invalid: {string.Join(" ", errors)}")
    {
        Errors = errors;
    }

    public IReadOnlyList<string> Errors { get; }
}
