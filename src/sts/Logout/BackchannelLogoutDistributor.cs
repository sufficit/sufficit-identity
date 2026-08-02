using System.Collections.Immutable;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS.Logout;

/// <summary>
/// Enumerates the relying parties (RPs / OpenIddict applications) that have an
/// active session for a given user and POSTs each of them a signed
/// <c>logout_token</c> at their registered <c>backchannel_logout_uri</c>, per
/// OIDC Back-Channel Logout 1.0.
/// </summary>
/// <remarks>
/// <b>Fan-out strategy.</b> The plan called for a queued fan-out (RabbitMQ) with
/// retry/audit. Implementing a full queue CONSUMER here (not just the publisher
/// pattern <c>RabbitMqEmailPublisher</c> already uses) is a separate component.
/// This implementation performs direct HTTP POSTs with bounded retry and a
/// caller-supplied timeout. The interface <see cref="IBackchannelLogoutDispatcher"/>
/// is shaped so a queue-backed implementation can drop in later without
/// touching the controller. Portable: depends only on OpenIddict's public
/// manager interfaces (<c>IOpenIddictAuthorizationManager</c>/
/// <c>IOpenIddictApplicationManager</c>) and <c>HttpClient</c>, not on
/// OpenIddict internals.
/// </remarks>
public interface IBackchannelLogoutDispatcher
{
    /// <summary>
    /// Distributes a back-channel logout to every RP with an active
    /// authorization for <paramref name="subject"/>. Returns after every
    /// delivery succeeds, fails, or the supplied cancellation token expires.
    /// Per-RP failures are logged and swallowed.
    /// </summary>
    Task DistributeAsync(string subject, string? sessionId, CancellationToken cancellationToken);
}

internal sealed class BackchannelLogoutDistributor : IBackchannelLogoutDispatcher
{
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly LogoutTokenGenerator _tokenGenerator;
    private readonly HttpClient _httpClient;
    private readonly ILogger<BackchannelLogoutDistributor> _logger;

    public BackchannelLogoutDistributor(
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictApplicationManager applicationManager,
        LogoutTokenGenerator tokenGenerator,
        HttpClient httpClient,
        ILogger<BackchannelLogoutDistributor> logger)
    {
        _authorizationManager = authorizationManager;
        _applicationManager = applicationManager;
        _tokenGenerator = tokenGenerator;
        _httpClient = httpClient;
        _logger = logger;
    }

    public async Task DistributeAsync(string subject, string? sessionId, CancellationToken cancellationToken)
    {
        // Find every VALID permanent authorization for this subject — each one
        // represents an RP the user previously consented to (and whose session
        // we should therefore terminate). OpenIddict's FindAsync is async-
        // enumerable; materialize so we can fan out after.
        var clientIds = new HashSet<string>(StringComparer.Ordinal);
        await foreach (var authorization in _authorizationManager.FindAsync(
            subject: subject,
            client: null,
            status: Statuses.Valid,
            type: AuthorizationTypes.Permanent,
            scopes: ImmutableArray<string>.Empty,
            cancellationToken: cancellationToken))
        {
            var applicationId = await _authorizationManager.GetApplicationIdAsync(authorization);
            if (applicationId is null) continue;

            var application = await _applicationManager.FindByIdAsync(applicationId, cancellationToken);
            if (application is null) continue;

            var clientId = (string?)await _applicationManager.GetClientIdAsync(application);
            if (clientId is not null)
            {
                clientIds.Add(clientId);
            }
        }

        if (clientIds.Count == 0)
        {
            _logger.LogDebug(
                "Back-channel logout: no active authorizations for subject {Subject}; nothing to distribute.",
                subject);
            return;
        }

        // Fan out in parallel but keep all work inside this request scope.
        // This avoids using scoped OpenIddict managers after their service
        // provider has been disposed (the previous fire-and-forget approach
        // could lose every notification immediately after redirect).
        await Task.WhenAll(clientIds.Select(clientId =>
            DispatchToClientAsync(clientId, subject, sessionId, cancellationToken)));
    }

    private async Task DispatchToClientAsync(
        string clientId,
        string subject,
        string? sessionId,
        CancellationToken cancellationToken)
    {
        try
        {
            var application = await _applicationManager.FindByClientIdAsync(
                clientId, cancellationToken);
            if (application is null) return;

            // backchannel_logout_uri is per-client registration metadata (set on
            // the application via its settings JSON). OpenIddict stores extra
            // settings under GetSettingsAsync(); the well-known key is the same
            // one configured at client registration time.
            var settings = await _applicationManager.GetSettingsAsync(
                application, cancellationToken);
            var backchannelLogoutUri = GetBackchannelLogoutUri(settings);
            if (string.IsNullOrWhiteSpace(backchannelLogoutUri))
            {
                // Not an error: most clients won't register a backchannel URI.
                _logger.LogDebug(
                    "Back-channel logout: client {ClientId} has no backchannel_logout_uri; skipping.",
                    clientId);
                return;
            }

            var sessionRequired = settings.TryGetValue(
                    "backchannel_logout_session_required", out var rawSessionRequired) &&
                bool.TryParse(rawSessionRequired, out var parsedSessionRequired) &&
                parsedSessionRequired;
            if (sessionRequired && string.IsNullOrWhiteSpace(sessionId))
            {
                _logger.LogWarning(
                    "Back-channel logout skipped for client {ClientId}: the RP requires sid, " +
                    "but this OP session does not expose one.",
                    clientId);
                return;
            }

            // OIDC Back-Channel Logout 1.0 defines aud exactly as it does for
            // ID Tokens: the RP's client_id, never the HTTP origin of its
            // backchannel_logout_uri.
            var token = _tokenGenerator.Generate(subject, sessionId, clientId);

            await PostWithRetryAsync(
                backchannelLogoutUri!, token, clientId, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            _logger.LogWarning(
                "Back-channel logout to client {ClientId} exceeded the delivery deadline.",
                clientId);
        }
        catch (Exception ex)
        {
            // Never let a single RP's failure surface — log and move on. The
            // user's logout already succeeded; a missed back-channel logout
            // means that RP's local session lives a bit longer (bounded by the
            // RP's own session timeout). The OP session has already ended, but
            // this delivery outcome must remain observable because SignOut does
            // not revoke a relying party's local browser session by itself.
            _logger.LogWarning(ex,
                "Back-channel logout to client {ClientId} failed; the user's logout at the STS is unaffected.",
                clientId);
        }
    }

    private static string? GetBackchannelLogoutUri(
        System.Collections.Immutable.ImmutableDictionary<string, string> settings)
    {
        // OpenIddict exposes extra application properties via the JSON settings
        // dictionary (IOpenIddictApplicationManager.GetSettingsAsync). The
        // backchannel_logout_uri is a standard OIDC client registration metadata
        // field; reading it from settings keeps this portable across OpenIddict
        // versions (no reliance on a typed property on the application object).
        if (settings.TryGetValue("backchannel_logout_uri", out var value) &&
            Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
            uri.Fragment.Length == 0 &&
            (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp))
        {
            return uri.AbsoluteUri;
        }
        return null;
    }

    private async Task PostWithRetryAsync(
        string uri,
        string token,
        string clientId,
        CancellationToken cancellationToken)
    {
        const int maxAttempts = 3;
        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            try
            {
                using var content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["logout_token"] = token,
                });
                // OIDC Back-Channel Logout 1.0 §2.6: the request is an HTTP POST
                // application/x-www-form-urlencoded with a single logout_token
                // parameter. The RP validates signature, iss, aud, and the
                // events member, then terminates the local session.
                using var response = await _httpClient.PostAsync(uri, content, cancellationToken);
                if (response.IsSuccessStatusCode)
                {
                    _logger.LogInformation(
                        "Back-channel logout delivered to client {ClientId} at {Uri} (attempt {Attempt}).",
                        clientId, uri, attempt);
                    return;
                }

                // 4xx = the RP rejected the token/our request; retrying won't help.
                if ((int)response.StatusCode >= 400 && (int)response.StatusCode < 500)
                {
                    _logger.LogWarning(
                        "Back-channel logout to client {ClientId} at {Uri} returned {Status} (non-retriable); giving up.",
                        clientId, uri, (int)response.StatusCode);
                    return;
                }

                _logger.LogWarning(
                    "Back-channel logout to client {ClientId} at {Uri} returned {Status} (attempt {Attempt}/{Max}); will retry.",
                    clientId, uri, (int)response.StatusCode, attempt, maxAttempts);
            }
            catch (Exception ex) when (attempt < maxAttempts)
            {
                _logger.LogWarning(ex,
                    "Back-channel logout to client {ClientId} at {Uri} threw (attempt {Attempt}/{Max}); will retry.",
                    clientId, uri, attempt, maxAttempts);
            }

            // Exponential backoff between attempts (bounded — this runs on a
            // background thread, not blocking the user).
            if (attempt < maxAttempts)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(250 * attempt), cancellationToken);
            }
        }
    }
}

/// <summary>
/// No-op <see cref="IBackchannelLogoutDispatcher"/> used when
/// <c>BackchannelLogoutOptions.Enabled</c> is false. Lets the
/// <c>AuthorizationController</c> take the dispatcher as a hard dependency
/// (no nullable injection) while keeping logout a pure local sign-out when the
/// feature is off.
/// </summary>
internal sealed class NullBackchannelLogoutDispatcher : IBackchannelLogoutDispatcher
{
    public Task DistributeAsync(string subject, string? sessionId, CancellationToken cancellationToken)
        => Task.CompletedTask;
}
