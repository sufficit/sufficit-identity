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

    /// <summary>
    /// The assurance level an <c>acr</c> value asks for, or
    /// <see langword="null"/> when this server does not recognise it.
    /// </summary>
    /// <remarks>
    /// The inverse of <see cref="Map"/>, and deliberately partial: a relying
    /// party may ask for a vocabulary this deployment does not speak, and
    /// <c>acr_values</c> is a voluntary request (OIDC Core 3.1.2.1). An
    /// unrecognised value is ignored rather than refused.
    /// </remarks>
    CaepAssuranceLevel? Parse(string acr);
}

internal sealed class ConfigurableAuthenticationContextClassMapper(
    AuthenticationContextOptions options) : IAuthenticationContextClassMapper
{
    private readonly string _prefix = (options.AcrPrefix ?? string.Empty).Trim();

    public CaepAssuranceLevel? Parse(string acr)
    {
        if (string.IsNullOrWhiteSpace(acr))
        {
            return null;
        }

        var value = acr.Trim();
        if (_prefix.Length > 0)
        {
            if (!value.StartsWith(_prefix, StringComparison.Ordinal))
            {
                return null;
            }

            value = value[_prefix.Length..];
        }

        // Loa3 is the level this server can be asked for; PhishingResistant
        // shares its spelling and is not separately requestable.
        return value switch
        {
            "loa1" => CaepAssuranceLevel.Loa1,
            "loa2" => CaepAssuranceLevel.Loa2,
            "loa3" => CaepAssuranceLevel.Loa3,
            _ => null,
        };
    }

    public string Map(CaepAssuranceLevel level) => _prefix + level switch
    {
        CaepAssuranceLevel.Loa2 => "loa2",
        // A phishing-resistant factor is the strongest level this server
        // distinguishes; it shares the top acr value with Loa3.
        CaepAssuranceLevel.Loa3 or CaepAssuranceLevel.PhishingResistant => "loa3",
        _ => "loa1",
    };
}
