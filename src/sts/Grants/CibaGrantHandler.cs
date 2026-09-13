using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS.Grants;

/// <summary>
/// OpenID Connect CIBA Core 1.0 poll mode, token-endpoint half (§10.1):
/// redeems an approved <c>auth_req_id</c> at <c>/connect/token</c> with
/// <c>grant_type=urn:openid:params:grant-type:ciba</c>.
/// </summary>
/// <remarks>
/// The token endpoint authenticates the client (client_secret_basic,
/// client_secret_post, private_key_jwt, mTLS) and checks the grant-type
/// permission before this handler runs, and the dispatcher's DPoP preamble
/// applies as for every other grant. The handler adds the CIBA client
/// eligibility policy, binds the <c>auth_req_id</c> to the client that
/// initiated it, and consumes an approval atomically so only one poll redeems
/// it. <c>offline_access</c> is dropped: CIBA tokens carry no refresh token,
/// as before this grant moved to the token endpoint.
/// </remarks>
public sealed class CibaGrantHandler(
    SufficitIdentityOptions options,
    Ciba.ICibaPendingRequestStore pendingStore,
    Ciba.ICibaClientPolicy clientPolicy) : ITokenGrantHandler
{
    /// <summary>CIBA Core 1.0 §4 — the CIBA grant-type URI.</summary>
    public const string GrantType = "urn:openid:params:grant-type:ciba";

    public const string AuthReqIdParameter = "auth_req_id";

    public IReadOnlyCollection<string> HandledGrantTypes { get; } = [GrantType];

    public async Task<IActionResult> HandleAsync(TokenGrantContext context)
    {
        var (httpContext, request, proof, ops) =
            (context.HttpContext, context.Request, context.Proof, context.Operations);
        var ciba = options.Ciba;

        if (!ciba.Enabled)
        {
            return TokenGrantDispatcher.ForbidError(Errors.UnsupportedGrantType, null);
        }

        var clientId = request.ClientId;
        var clientAuthorization = await clientPolicy.AuthorizeAuthenticatedClientAsync(
            clientId,
            "poll",
            httpContext.RequestAborted);
        if (!clientAuthorization.Allowed)
        {
            return TokenGrantDispatcher.ForbidError(
                clientAuthorization.ErrorCode ?? Errors.UnauthorizedClient, null);
        }

        var authReqId = (string?)request[AuthReqIdParameter];
        if (string.IsNullOrWhiteSpace(authReqId))
        {
            return TokenGrantDispatcher.ForbidError(Errors.InvalidRequest,
                "The auth_req_id parameter is required.");
        }

        if (pendingStore.Find(authReqId) is not { } pending)
        {
            return Expired();
        }

        // auth_req_id is issued to exactly one client. invalid_grant does not
        // disclose whether the identifier belongs to another client.
        if (!string.Equals(pending.ClientId, clientId, StringComparison.Ordinal))
        {
            return TokenGrantDispatcher.ForbidError(Errors.InvalidGrant,
                "The auth_req_id is invalid for this client.");
        }

        // Consuming atomically closes the window where two concurrent polls
        // both observe the approval and receive two token sets.
        if (pendingStore.TryConsumeApproved(authReqId, out var consumed))
        {
            var user = await ops.UserManager.FindByIdAsync(consumed.ApprovedSubject!);
            if (user is null || !await ops.SignInManager.CanSignInAsync(user))
            {
                return TokenGrantDispatcher.ForbidError(Errors.InvalidGrant,
                    "The user is no longer allowed to sign in.");
            }

            var grantedScopes = consumed.Scopes
                .Where(scope => !string.Equals(scope, Scopes.OfflineAccess, StringComparison.Ordinal))
                .Distinct(StringComparer.Ordinal)
                .ToArray();
            var entitlementResult = await ops.ProvisionScopeEntitlementsAsync(
                user,
                grantedScopes,
                httpContext.RequestAborted);
            if (!entitlementResult.Succeeded)
            {
                return TokenGrantDispatcher.ForbidError(
                    "temporarily_unavailable",
                    "The requested product access could not be activated. Please retry.");
            }

            var identity = await ops.BuildIdentityAsync(user);
            identity.SetScopes(grantedScopes);
            identity.SetResources(await ops.ResolveResourcesAsync(identity, request: null));
            GrantOperations.ApplyDpopBinding(identity, proof);
            identity.SetDestinations(ops.GetDestinations);

            return new SignInResult(
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                new ClaimsPrincipal(identity));
        }

        // Another concurrent poll consumed the approval: same terminal error
        // as an unknown auth_req_id.
        if (pendingStore.Find(authReqId) is null)
        {
            return Expired();
        }

        if (!pendingStore.TryRecordPoll(authReqId, TimeSpan.FromSeconds(ciba.PollIntervalSeconds)))
        {
            return TokenGrantDispatcher.ForbidError(Errors.SlowDown,
                "The client is polling too fast.");
        }

        return TokenGrantDispatcher.ForbidError(Errors.AuthorizationPending,
            "The authorization request is still pending approval.");
    }

    private static ForbidResult Expired() =>
        TokenGrantDispatcher.ForbidError(Errors.ExpiredToken,
            "The auth_req_id is unknown or expired.");
}
