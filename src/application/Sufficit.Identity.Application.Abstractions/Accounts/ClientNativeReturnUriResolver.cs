namespace Sufficit.Identity.Application.Accounts;

/// <summary>
/// Reads the native callbacks a client registered with this deployment.
/// </summary>
/// <remarks>
/// The registry is the only place a concrete callback exists. Nothing in the
/// server carries a built-in list, so a deployment adds an application by
/// registering it — through the management API, a provisioning manifest or
/// dynamic client registration — and never by changing this code.
/// </remarks>
public interface IClientNativeReturnUriResolver
{
    /// <summary>
    /// Callbacks registered for <paramref name="clientId"/>, in registration
    /// order. Empty when the client is unknown or registered none.
    /// </summary>
    Task<IReadOnlyList<string>> ListAsync(
        string? clientId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Resolves what a request asked for against what the client registered.
    /// A blank candidate resolves to the first registered callback, so a
    /// client that registered exactly one target may omit the parameter;
    /// anything else must match a registration exactly or the result is
    /// <c>null</c>.
    /// </summary>
    Task<string?> ResolveAsync(
        string? clientId,
        string? candidate,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Turns a callback validated against a client registration into an opaque,
/// expiring ticket, and back.
/// </summary>
/// <remarks>
/// The completion page is reached after a redirect that no longer carries the
/// device transaction, so it cannot re-check a raw <c>return_uri</c> against
/// the client record. Handing it a ticket the server minted keeps the decision
/// on the server: the page renders a link only for a value this deployment
/// already accepted, and a tampered query string resolves to nothing.
/// </remarks>
public interface INativeReturnUriTicketService
{
    /// <summary>Protects an already-validated callback for the browser round trip.</summary>
    string Protect(string returnUri);

    /// <summary>
    /// Recovers the callback from a ticket, or <c>null</c> when the ticket is
    /// missing, tampered with or expired.
    /// </summary>
    string? Unprotect(string? ticket);
}
