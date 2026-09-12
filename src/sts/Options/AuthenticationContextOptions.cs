namespace Sufficit.Identity.STS;

/// <summary>
/// Vocabulary of the <c>acr</c> (authentication context class reference) values
/// this server emits (<c>Sufficit:Identity:AuthenticationContext</c>).
/// </summary>
/// <remarks>
/// <c>acr</c> is read by relying parties the operator does not control, so its
/// values are a deployment's public contract, not a constant of the software. The
/// emitted value is <see cref="AcrPrefix"/> followed by <c>loa1</c>, <c>loa2</c> or
/// <c>loa3</c>.
/// </remarks>
public sealed class AuthenticationContextOptions
{
    /// <summary>
    /// Prefix of every emitted <c>acr</c> value. Default <c>urn:identity:acr:</c>.
    /// A deployment whose relying parties already check another vocabulary sets
    /// the prefix they expect.
    /// </summary>
    public string AcrPrefix { get; init; } = "urn:identity:acr:";
}
