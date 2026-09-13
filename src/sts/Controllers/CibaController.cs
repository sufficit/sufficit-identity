using System.Collections.Immutable;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using Sufficit.Identity.Core.Entities;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS.Controllers;

/// <summary>
/// CIBA (OpenID Connect Client-Initiated Backchannel Authentication Core 1.0).
/// Implements the initiation (<c>/bc-authorize</c>) and completion
/// (<c>/connect/ciba/complete</c>) halves. The polling half is the standard
/// token endpoint with <c>grant_type=urn:openid:params:grant-type:ciba</c>,
/// served by <see cref="Grants.CibaGrantHandler"/>.
/// </summary>
/// <remarks>
/// The pending <c>auth_req_id</c> state lives in
/// <see cref="Ciba.ICibaPendingRequestStore"/>, registered as
/// <c>RollingCibaPendingRequestStore</c> over a database primary, so it is
/// shared across replicas and survives a restart. The initiation endpoint is
/// not a token endpoint, so it still authenticates the client itself through
/// <see cref="Ciba.ICibaClientPolicy"/> (client secret only).
/// </remarks>
public class CibaController : Controller
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly Ciba.ICibaPendingRequestStore _pendingStore;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IAntiforgery _antiforgery;
    private readonly CibaOptions _options;
    private readonly Ciba.ICibaClientPolicy _clientPolicy;
    private readonly IAccountLookupPolicy _accountLookup;

    public CibaController(
        IOpenIddictApplicationManager applicationManager,
        Ciba.ICibaPendingRequestStore pendingStore,
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IConfiguration configuration,
        IAntiforgery antiforgery,
        Ciba.ICibaClientPolicy clientPolicy,
        IAccountLookupPolicy accountLookup)
    {
        _applicationManager = applicationManager;
        _pendingStore = pendingStore;
        _signInManager = signInManager;
        _userManager = userManager;
        _antiforgery = antiforgery;
        _clientPolicy = clientPolicy;
        _accountLookup = accountLookup;
        var root = configuration.GetSection("Sufficit:Identity")
            .Get<SufficitIdentityOptions>() ?? new SufficitIdentityOptions();
        _options = root.Ciba;
    }

    public override void OnActionExecuting(ActionExecutingContext context)
    {
        if (!_options.Enabled)
        {
            context.Result = NotFound();
            return;
        }

        base.OnActionExecuting(context);
    }

    // -----------------------------------------------------------------------
    // POST /bc-authorize — CIBA Core 1.0 initiation endpoint.
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
        // CIBA Core 1.0: binding_message is human-readable; cap it
        // to prevent abuse/log-injection. 180 chars covers any reasonable
        // display without being a transport for arbitrary content.
        if (bindingMessage.Length > 180)
        {
            return BadRequest(new { error = "invalid_binding_message", error_description = "binding_message must not exceed 180 characters." });
        }
        var scope = form["scope"].ToString();

        if (string.IsNullOrEmpty(clientId))
        {
            return BadRequest(new { error = "invalid_request", error_description = "client_id is required." });
        }

        // This custom endpoint does not enter OpenIddict's token-endpoint
        // client-authentication pipeline, so initiation and polling share one
        // explicit client/entitlement policy.
        var clientAuthorization = await _clientPolicy.AuthorizeAsync(
            clientId,
            clientSecret,
            "initiate",
            HttpContext.RequestAborted);
        if (!clientAuthorization.Allowed)
        {
            return Unauthorized(new { error = clientAuthorization.ErrorCode });
        }
        var application = clientAuthorization.Application!;

        // Resolve the target user from login_hint (email-or-username).
        // M3 fix (eval M3): do NOT return unknown_user — that is a user-existence
        // oracle. Instead, create a pending request that will NEVER be approved
        // (subject=null). The poll returns authorization_pending until expiry,
        // then expired_token — indistinguishable from a real request whose user
        // hasn't approved yet. This mirrors the password grant's anti-enumeration.
        ApplicationUser? user = null;
        if (!string.IsNullOrWhiteSpace(loginHint))
        {
            user = await _userManager.FindByNameAsync(loginHint)
                ?? await _accountLookup.FindUniqueByEmailAsync(
                    loginHint,
                    HttpContext.RequestAborted);
        }

        IReadOnlyCollection<string> scopes = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        foreach (var requestedScope in scopes)
        {
            if (!await _applicationManager.HasPermissionAsync(
                    application,
                    OpenIddictConstants.Permissions.Prefixes.Scope + requestedScope))
            {
                return BadRequest(new
                {
                    error = Errors.InvalidScope,
                    error_description = $"The scope '{requestedScope}' is not allowed for this client."
                });
            }
        }

        var pending = _pendingStore.Create(
            clientId,
            user is null ? string.Empty : await _userManager.GetUserIdAsync(user),
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
    // GET ~/connect/ciba/complete — authenticated approval review. The
    // binding_message is rendered before a user can approve the transaction.
    // -----------------------------------------------------------------------
    [HttpGet("~/connect/ciba/complete")]
    public async Task<IActionResult> Review([FromQuery(Name = "auth_req_id")] string authReqId)
    {
        var pendingRequest = _pendingStore.Find(authReqId);
        if (pendingRequest is null)
        {
            return NotFound("The authentication request is unknown or expired.");
        }

        var result = await HttpContext.AuthenticateAsync();
        if (result is not { Succeeded: true, Principal: not null })
        {
            return Challenge(new AuthenticationProperties
            {
                RedirectUri = Request.PathBase + Request.Path + Request.QueryString,
            });
        }
        var user = await _userManager.GetUserAsync(result.Principal);
        var userId = user is null ? null : await _userManager.GetUserIdAsync(user);
        if (string.IsNullOrWhiteSpace(userId)
            || !string.Equals(userId, pendingRequest.Subject, StringComparison.Ordinal))
        {
            return Forbid();
        }

        var tokens = _antiforgery.GetAndStoreTokens(HttpContext);
        Response.Headers.CacheControl = "no-store";
        Response.Headers.Pragma = "no-cache";
        var encoder = HtmlEncoder.Default;
        var bindingMessage = string.IsNullOrWhiteSpace(pendingRequest.BindingMessage)
            ? "No transaction message was supplied. Confirm the requesting application before continuing."
            : pendingRequest.BindingMessage;
        var html = new StringBuilder("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
            .Append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
            .Append("<title>Confirm sign-in request</title></head><body><main>")
            .Append("<h1>Confirm sign-in request</h1><p>Application: <strong>")
            .Append(encoder.Encode(pendingRequest.ClientId))
            .Append("</strong></p><p>Verification message: <strong>")
            .Append(encoder.Encode(bindingMessage))
            .Append("</strong></p><form method=\"post\" action=\"")
            .Append(encoder.Encode(Request.PathBase + Request.Path))
            .Append("\"><input type=\"hidden\" name=\"")
            .Append(encoder.Encode(tokens.FormFieldName))
            .Append("\" value=\"")
            .Append(encoder.Encode(tokens.RequestToken ?? string.Empty))
            .Append("\"><input type=\"hidden\" name=\"auth_req_id\" value=\"")
            .Append(encoder.Encode(authReqId))
            .Append("\"><button type=\"submit\" name=\"approved\" value=\"true\">Approve</button>")
            .Append("<button type=\"submit\" name=\"approved\" value=\"false\">Deny</button>")
            .Append("</form></main></body></html>");
        return Content(html.ToString(), "text/html; charset=utf-8");
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

        var pendingRequest = _pendingStore.Find(authReqId);
        if (pendingRequest is null)
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

        // M3 fix (eval M3): subject-binding check — the approving user MUST be
        // the same user the client asked to authenticate (pending.Subject).
        // Without this, a different user could approve and the client would
        // receive a token for the wrong identity.
        var approverId = await _userManager.GetUserIdAsync(user);
        // A CIBA request without a resolvable login_hint has no subject to
        // bind to. Do not silently turn it into "whoever is logged in";
        // requiring a resolvable subject preserves the anti-enumeration
        // response from initiation without weakening approval binding.
        if (string.IsNullOrEmpty(pendingRequest.Subject)
            || !string.Equals(pendingRequest.Subject, approverId, StringComparison.Ordinal))
        {
            _pendingStore.Deny(authReqId);
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.AccessDenied,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The approving user does not match the requested user."
                }));
        }

        _pendingStore.Approve(authReqId, approverId);
        return Ok(new { status = "approved" });
    }
}
