using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

/// <summary>
/// Publishes the deployment's legacy-grant decision to the client-definition
/// validator, which lives in the abstractions and cannot read STS options.
/// </summary>
internal sealed class LegacyGrantAvailability(LegacyGrantsOptions options)
    : ILegacyGrantAvailability
{
    public bool PasswordGrantEnabled { get; } = options.Password;
}
