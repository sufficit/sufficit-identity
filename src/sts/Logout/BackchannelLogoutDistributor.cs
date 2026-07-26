using System.Collections.Immutable;
using System.Net.Http.Headers;
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
/// This first cut does direct HTTP POSTs with a bounded retry, fire-and-forget
/// relative to the user's logout response (the RP-initiated logout redirect is
/// NOT blocked on RP fan-out). The interface <see cref="IBackchannelLogoutDispatcher"/>
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
    /// authorization for <paramref name="subject"/>. Non-blocking: returns
    /// once distribution has been SCHEDULED (each POST runs on a background
    /// task with its own retry). Never throws — failures are logged and
    /// swallowed so a misbehaving RP cannot break the user's logout.
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

        // Fan out to each distinct client. Fire-and-forget per RP: a slow/down
        // RP must not delay the others or the user's logout redirect. The
        // cancellation token from the request is intentionally NOT forwarded
        // to the background tasks (the request that triggered the logout will
        // have completed by the time these run).
        foreach (var clientId in clientIds)
        {
            _ = Task.Run(() => DispatchToClientAsync(clientId, subject, sessionId), CancellationToken.None);
        }
    }

    private async Task DispatchToClientAsync(string clientId, string subject, string? sessionId)
    {
        try
        {
            var application = await _applicationManager.FindByClientIdAsync(clientId);
            if (application is null) return;

            // backchannel_logout_uri is per-client registration metadata (set on
            // the application via its settings JSON). OpenIddict stores extra
            // settings under GetSettingsAsync(); the well-known key is the same
            // one configured at client registration time.
            var backchannelLogoutUri = await GetBackchannelLogoutUriAsync(application);
            if (string.IsNullOrWhiteSpace(backchannelLogoutUri))
            {
                // Not an error: most clients won't register a backchannel URI.
                _logger.LogDebug(
                    "Back-channel logout: client {ClientId} has no backchannel_logout_uri; skipping.",
                    clientId);
                return;
            }

            // aud = the RP's origin (scheme + host [+ port]) so the RP can
            // validate the token is addressed to it.
            var audience = new Uri(backchannelLogoutUri, UriKind.Absolute).GetLeftPart(UriPartial.Authority);
            var token = _tokenGenerator.Generate(subject, sessionId, audience);

            await PostWithRetryAsync(backchannelLogoutUri!, token, clientId);
        }
        catch (Exception ex)
        {
            // Never let a single RP's failure surface — log and move on. The
            // user's logout already succeeded; a missed back-channel logout
            // means that RP's local session lives a bit longer (bounded by the
            // RP's own session timeout), which is a graceful degradation, not a
            // security boundary breach (the STS-side authorization is revoked
            // by SignOut regardless).
            _logger.LogWarning(ex,
                "Back-channel logout to client {ClientId} failed; the user's logout at the STS is unaffected.",
                clientId);
        }
    }

    private async Task<string?> GetBackchannelLogoutUriAsync(object application)
    {
        // OpenIddict exposes extra application properties via the JSON settings
        // dictionary (IOpenIddictApplicationManager.GetSettingsAsync). The
        // backchannel_logout_uri is a standard OIDC client registration metadata
        // field; reading it from settings keeps this portable across OpenIddict
        // versions (no reliance on a typed property on the application object).
        var settings = await _applicationManager.GetSettingsAsync(application);
        if (settings is null) return null;
        if (settings.TryGetValue("backchannel_logout_uri", out var value) && !string.IsNullOrWhiteSpace(value))
        {
            return value;
        }
        return null;
    }

    private async Task PostWithRetryAsync(string uri, string token, string clientId)
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
                using var response = await _httpClient.PostAsync(uri, content, CancellationToken.None);
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
            await Task.Delay(TimeSpan.FromSeconds(Math.Pow(2, attempt)), CancellationToken.None);
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
