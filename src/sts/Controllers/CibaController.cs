using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using Sufficit.Identity.Core.Entities;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS.Controllers;

/// <summary>
/// CIBA (Client-Initiated Backchannel Authentication, RFC 9126 — item 3.5).
/// Implements the initiation (<c>/bc-authorize</c>) and completion
/// (<c>/connect/ciba/complete</c>) halves. The polling half
/// (<c>grant_type=urn:openid:params:grant-type:ciba</c>) lives in
/// <see cref="AuthorizationController.ExchangeForCibaAsync"/>.
/// </summary>
/// <remarks>
/// OpenIddict 7.6 has no CIBA primitives. The pending <c>auth_req_id</c> state
/// lives in <see cref="Ciba.ICibaPendingRequestStore"/> (in-memory by default;
/// swappable for Redis/DB in a multi-replica deployment). The poll loop and
/// completion reuse the device-flow shape (pending → approve → issue), but the
/// principal handoff is via the store rather than OpenIddict's SignIn binding
/// (which is device_code-specific). Portable: the store interface isolates the
/// OpenIddict-free core from the host.
/// </remarks>
public class CibaController : Controller
{
    /// <summary>RFC 9126 §2.1 — the CIBA grant-type URI.</summary>
    public const string CibaGrantType = "urn:openid:params:grant-type:ciba";

    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly Ciba.ICibaPendingRequestStore _pendingStore;
    private readonly Ciba.CibaAccessTokenGenerator _accessTokenGenerator;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IAntiforgery _antiforgery;
    private readonly CibaOptions _options;

    public CibaController(
        IOpenIddictApplicationManager applicationManager,
        Ciba.ICibaPendingRequestStore pendingStore,
        Ciba.CibaAccessTokenGenerator accessTokenGenerator,
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IConfiguration configuration,
        IAntiforgery antiforgery)
    {
        _applicationManager = applicationManager;
        _pendingStore = pendingStore;
        _accessTokenGenerator = accessTokenGenerator;
        _signInManager = signInManager;
        _userManager = userManager;
        _antiforgery = antiforgery;
        var root = configuration.GetSection("Sufficit:Identity")
            .Get<SufficitIdentityOptions>() ?? new SufficitIdentityOptions();
        _options = root.Ciba;
    }

    // -----------------------------------------------------------------------
    // POST /bc-authorize — RFC 9126 §2.2 initiation endpoint.
    // -----------------------------------------------------------------------
    [HttpPost("~/bc-authorize")]
    [IgnoreAntiforgeryToken]
    [Produces("application/json")]
    public async Task<IActionResult> Initiate()
    {
        // /bc-authorize is NOT a registered OpenIddict endpoint (CIBA is not
        // supported by OpenIddict 7.6), so GetOpenIddictServerRequest() returns
        // null here. Read the form parameters directly instead.
        var form = await Request.ReadFormAsync();
        var clientId = form["client_id"].ToString();
        var clientSecret = form["client_secret"].ToString();
        var loginHint = form["login_hint"].ToString();
        var bindingMessage = form["binding_message"].ToString();
        var scope = form["scope"].ToString();

        if (string.IsNullOrEmpty(clientId))
        {
            return BadRequest(new { error = "invalid_request", error_description = "client_id is required." });
        }

        // Authenticate the client. For confidential clients, validate the
        // secret against the OpenIddict application store. (OpenIddict's own
        // client-auth pipeline only runs on its registered endpoints, so CIBA
        // initiation does this here.)
        var application = await _applicationManager.FindByClientIdAsync(clientId);
        if (application is null)
        {
            return Unauthorized(new { error = "invalid_client" });
        }
        var clientType = (string?)await _applicationManager.GetClientTypeAsync(application);
        if (string.Equals(clientType, OpenIddictConstants.ClientTypes.Confidential, StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrEmpty(clientSecret)
                || !await _applicationManager.ValidateClientSecretAsync(application, clientSecret))
            {
                return Unauthorized(new { error = "invalid_client" });
            }
        }

        // Resolve the target user from login_hint (email-or-username).
        ApplicationUser? user = null;
        if (!string.IsNullOrWhiteSpace(loginHint))
        {
            user = await _userManager.FindByNameAsync(loginHint)
                ?? await _userManager.FindByEmailAsync(loginHint);
        }
        if (user is null)
        {
            return NotFound(new
            {
                error = "unknown_user",
                error_description = "The user could not be identified from the provided hints."
            });
        }

        IReadOnlyCollection<string> scopes = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        var pending = _pendingStore.Create(
            clientId,
            await _userManager.GetUserIdAsync(user),
            scopes,
            string.IsNullOrWhiteSpace(bindingMessage) ? null : bindingMessage,
            TimeSpan.FromSeconds(_options.ExpiresInSeconds));

        return Ok(new
        {
            auth_req_id = pending.AuthReqId,
            expires_in = _options.ExpiresInSeconds,
            interval = _options.PollIntervalSeconds,
        });
    }

    // -----------------------------------------------------------------------
    // POST ~/connect/ciba/complete — the out-of-band completion channel.
    // The end user (authenticated via the STS cookie) approves or denies the
    // CIBA request on a separate authentication device. Approve sets the
    // approved subject in the store so the next poll issues the token; deny
    // removes the entry so the next poll gets access_denied.
    // -----------------------------------------------------------------------
    [HttpPost("~/connect/ciba/complete")]
    public async Task<IActionResult> Complete()
    {
        try
        {
            await _antiforgery.ValidateRequestAsync(HttpContext);
        }
        catch (AntiforgeryValidationException ex)
        {
            return BadRequest(new { error = "invalid_request", error_description = ex.Message });
        }

        var authReqId = Request.Form["auth_req_id"].ToString();
        var approved = string.Equals(Request.Form["approved"].ToString(), "true", StringComparison.OrdinalIgnoreCase);

        if (_pendingStore.Find(authReqId) is null)
        {
            return NotFound(new { error = "expired_token", error_description = "The auth_req_id is unknown or expired." });
        }

        if (!approved)
        {
            _pendingStore.Deny(authReqId);
            return Ok(new { status = "denied" });
        }

        // Approved: authenticate the confirming user, then mark the pending
        // request approved with their subject. Same cookie contract as
        // DeviceController.Verify.
        var result = await HttpContext.AuthenticateAsync();
        if (result is not { Succeeded: true })
        {
            return Challenge(new AuthenticationProperties
            {
                RedirectUri = Request.PathBase + Request.Path + QueryString.Create(Request.Form)
            });
        }

        var user = await _userManager.GetUserAsync(result.Principal) ??
            throw new InvalidOperationException("The user details cannot be retrieved.");
        if (!await _signInManager.CanSignInAsync(user))
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The user is not allowed to sign in."
                }));
        }

        _pendingStore.Approve(authReqId, await _userManager.GetUserIdAsync(user));
        return Ok(new { status = "approved" });
    }

    // -----------------------------------------------------------------------
    // POST ~/connect/ciba/token — the CIBA poll endpoint (RFC 9126 §3).
    // -----------------------------------------------------------------------
    // RFC 9126 §3 specifies the token endpoint as the poll target. However,
    // OpenIddict 7.6 has no CIBA grant-type registration, so a
    // grant_type=urn:openid:params:grant-type:ciba posted to /connect/token is
    // rejected with unsupported_grant_type before the controller runs. This
    // dedicated endpoint (/connect/ciba/token) implements the same poll
    // contract so CIBA works on OpenIddict 7.6 today. When migrating off
    // OpenIddict (or when a future OpenIddict version adds CIBA), this logic
    // moves to the standard token endpoint unchanged — the response shape and
    // error codes are RFC-compliant either way.
    [HttpPost("~/connect/ciba/token")]
    [IgnoreAntiforgeryToken]
    [Produces("application/json")]
    public async Task<IActionResult> Poll()
    {
        var authReqId = Request.Form["auth_req_id"].ToString();
        var grantType = Request.Form["grant_type"].ToString();
        if (!string.Equals(grantType, CibaGrantType, StringComparison.Ordinal))
        {
            return BadRequest(new { error = Errors.UnsupportedGrantType });
        }

        var pending = _pendingStore.Find(authReqId);
        if (pending is null)
        {
            // Unknown or expired (the store evicts expired entries on read).
            return BadRequest(new { error = Errors.ExpiredToken, error_description = "The auth_req_id is unknown or expired." });
        }

        // Approved? Issue the token. Checked BEFORE slow_down so an approved
        // request that the client polls a touch early still completes.
        if (pending.ApprovedSubject is { } subject)
        {
            var user = await _userManager.FindByIdAsync(subject);
            if (user is null || !await _signInManager.CanSignInAsync(user))
            {
                _pendingStore.Deny(authReqId);
                return BadRequest(new { error = Errors.InvalidGrant });
            }

            // Emit the access token MANUALLY (Limitation 2). SignIn would throw
            // ("A sign-in response cannot be returned from this endpoint")
            // because /connect/ciba/token is not a registered OpenIddict
            // endpoint. CibaAccessTokenGenerator builds a self-contained JWT
            // signed with the STS key, validatable against the STS JWKS. This
            // is NOT an OpenIddict reference token (no introspection/revocation)
            // — documented limitation; deferred until a client needs it.
            var scopes = pending.Scopes.ToList();
            var extraClaims = new List<System.Security.Claims.Claim>
            {
                new(Claims.Email, (await _userManager.GetEmailAsync(user)) ?? string.Empty),
                new(Claims.Name, (await _userManager.GetUserNameAsync(user)) ?? string.Empty),
                new(Claims.PreferredUsername, (await _userManager.GetUserNameAsync(user)) ?? string.Empty),
            };
            foreach (var role in await _userManager.GetRolesAsync(user))
            {
                extraClaims.Add(new System.Security.Claims.Claim(Claims.Role, role));
            }

            var accessToken = _accessTokenGenerator.Generate(
                subject: subject,
                audience: pending.ClientId,
                scopes: scopes,
                clientId: pending.ClientId,
                extraClaims: extraClaims);

            _pendingStore.Deny(authReqId); // one-shot: remove so it can't be replayed

            // RFC 9126 §3.2 / RFC 6749 §5.1 successful token response.
            return Ok(new
            {
                access_token = accessToken,
                token_type = "Bearer",
                expires_in = 3600,
                scope = string.Join(' ', scopes),
            });
        }

        // Slow-down enforcement (RFC 9126 §3): reject polls faster than the
        // configured interval.
        if (!_pendingStore.TryRecordPoll(authReqId, TimeSpan.FromSeconds(_options.PollIntervalSeconds)))
        {
            return BadRequest(new { error = Errors.SlowDown, error_description = "The client is polling too fast." });
        }

        // Still pending — the canonical polling response.
        return BadRequest(new { error = Errors.AuthorizationPending, error_description = "The authorization request is still pending approval." });
    }
}
