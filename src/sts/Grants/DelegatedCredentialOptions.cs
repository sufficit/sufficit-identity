namespace Sufficit.Identity.STS.Grants;

/// <summary>
/// Delegated device credentials: a trusted first-party client, holding a
/// fresh user access token, exchanges it (RFC 8693) for a refresh token that
/// belongs to ANOTHER registered client — the delegate — and is bound to a
/// DPoP key (RFC 9449) the delegate device generated and never shares.
/// Bound from <c>Sufficit:Identity:TokenExchange:DelegatedCredentials</c>.
/// </summary>
/// <remarks>
/// <para>The intended use is a headless runtime (a remote workspace, a build
/// agent, a kiosk) that cannot run an interactive sign-in of its own: the
/// user's already-signed-in application vouches for it, and the resulting
/// credential is useless to whoever transports it, because every refresh and
/// every access token requires a proof signed with the device's private
/// key.</para>
/// <para>All limits are initial values meant to be tuned by configuration
/// after operating the feature; none is fixed in code. Disabled by
/// default: with <see cref="Enabled"/> false the token-exchange grant keeps
/// refusing <c>requested_token_type=refresh_token</c>, exactly as before the
/// feature existed.</para>
/// </remarks>
public sealed class DelegatedCredentialOptions
{
    /// <summary>Master switch. Default <see langword="false"/>.</summary>
    public bool Enabled { get; init; }

    /// <summary>
    /// Clients allowed to delegate (the token-exchange caller). Empty means
    /// nobody can delegate, even with <see cref="Enabled"/> set: an allow-list
    /// that defaults to "everyone with the token-exchange permission" would
    /// turn a mis-provisioned permission into a credential factory.
    /// </summary>
    public HashSet<string> DelegatorClientIds { get; init; } = new(StringComparer.Ordinal);

    /// <summary>
    /// The client the credential is issued to. The request selects this mode
    /// by naming it in <c>audience</c>. It must be registered, may not be a
    /// delegator itself, and needs the <c>refresh_token</c> grant permission.
    /// </summary>
    public string DelegateClientId { get; init; } = string.Empty;

    /// <summary>
    /// Scope the subject token must carry. It is a consent marker for the
    /// delegation itself and is never copied into the delegated credential.
    /// </summary>
    public string RequiredScope { get; init; } = string.Empty;

    /// <summary>
    /// How old the user's sign-in (<c>auth_time</c> of the subject token) may
    /// be. A subject token without <c>auth_time</c> is refused. Default 12.
    /// </summary>
    public int MaxAuthAgeHours { get; init; } = 12;

    /// <summary>
    /// Absolute lifetime of a delegated credential. Refreshing it never
    /// extends this deadline; only a new delegation does. Default 30.
    /// </summary>
    public int CredentialLifetimeDays { get; init; } = 30;

    /// <summary>
    /// Active delegated credentials per user. A new delegation beyond this
    /// number is refused, except when it replaces the credential of the same
    /// device label. Default 10.
    /// </summary>
    public int MaxActivePerUser { get; init; } = 10;

    /// <summary>
    /// Sends the user an email for every credential issued (when the account
    /// has a confirmed address). The issuance is audited either way.
    /// Default <see langword="true"/>.
    /// </summary>
    public bool NotifyOnIssue { get; init; } = true;

    internal const int MaxAuthAgeHoursCeiling = 24 * 7;
    internal const int CredentialLifetimeDaysCeiling = 365;
    internal const int MaxActivePerUserCeiling = 1000;

    /// <summary>
    /// Configuration errors that must refuse startup while the feature is
    /// enabled. Empty when disabled: an inert section never blocks a deploy.
    /// </summary>
    /// <param name="identity">The STS options, when known: a delegated
    /// credential is bound to a DPoP key, so without DPoP every refresh of it
    /// would fail.</param>
    public IEnumerable<string> Validate(SufficitIdentityOptions? identity = null)
    {
        if (!Enabled)
        {
            yield break;
        }

        const string prefix = "Sufficit:Identity:TokenExchange:DelegatedCredentials:";
        if (identity is not null && !identity.Dpop.Enabled)
        {
            yield return prefix + "Enabled requires Sufficit:Identity:Dpop:Enabled=true.";
        }

        if (string.IsNullOrWhiteSpace(DelegateClientId))
        {
            yield return prefix + "DelegateClientId is required when the feature is enabled.";
        }
        else if (DelegatorClientIds.Contains(DelegateClientId))
        {
            yield return prefix + "DelegateClientId cannot also be a delegator.";
        }

        if (string.IsNullOrWhiteSpace(RequiredScope))
        {
            yield return prefix + "RequiredScope is required when the feature is enabled.";
        }

        if (MaxAuthAgeHours is < 1 or > MaxAuthAgeHoursCeiling)
        {
            yield return prefix + "MaxAuthAgeHours must be between 1 and "
                + MaxAuthAgeHoursCeiling + ".";
        }

        if (CredentialLifetimeDays is < 1 or > CredentialLifetimeDaysCeiling)
        {
            yield return prefix + "CredentialLifetimeDays must be between 1 and "
                + CredentialLifetimeDaysCeiling + ".";
        }

        if (MaxActivePerUser is < 1 or > MaxActivePerUserCeiling)
        {
            yield return prefix + "MaxActivePerUser must be between 1 and "
                + MaxActivePerUserCeiling + ".";
        }
    }
}
