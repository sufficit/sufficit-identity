using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

/// <summary>
/// The single place that turns an authentication assurance level into the
/// <c>acr</c> value placed in tokens and sessions.
/// </summary>
/// <remarks>
/// Sign-in flows describe what happened (password, second factor, passkey) as an
/// assurance level; this boundary decides how that level is spelled on the wire.
/// Keeping the spelling in one place is what lets a deployment change its public
/// vocabulary without every sign-in path carrying its own literal.
/// </remarks>
public interface IAuthenticationContextClassMapper
{
    string Map(CaepAssuranceLevel level);
}

internal sealed class ConfigurableAuthenticationContextClassMapper(
    AuthenticationContextOptions options) : IAuthenticationContextClassMapper
{
    private readonly string _prefix = (options.AcrPrefix ?? string.Empty).Trim();

    public string Map(CaepAssuranceLevel level) => _prefix + level switch
    {
        CaepAssuranceLevel.Loa2 => "loa2",
        // A phishing-resistant factor is the strongest level this server
        // distinguishes; it shares the top acr value with Loa3.
        CaepAssuranceLevel.Loa3 or CaepAssuranceLevel.PhishingResistant => "loa3",
        _ => "loa1",
    };
}
