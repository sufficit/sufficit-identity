using System.Security.Claims;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;

namespace Sufficit.Identity.STS;

/// <summary>
///     Emits the authorization grant only as <c>entitlements</c>, whichever
///     name it is stored or derived under.
/// </summary>
/// <remarks>
///     <para>
///         The grant used to travel under both <c>directive</c> and
///         <c>entitlements</c> while consumers moved to the standard name
///         (RFC 9068 §2.2.3.1). Every consumer reads <c>entitlements</c> since
///         2026-10-22, so a value still found under the old name is renamed, not
///         copied: the old name no longer leaves this server.
///     </para>
///     <para>
///         <b>Why here, and not where destinations are assigned.</b> By this
///         point OpenIddict has already built the per-token principals, so a
///         claim is present only if it survived the claim-to-scope gate; the
///         rename inherits that decision instead of re-deriving it.
///     </para>
/// </remarks>
internal sealed class NormalizeEntitlementClaimName
    : IOpenIddictServerHandler<ProcessSignInContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
            .UseSingletonHandler<NormalizeEntitlementClaimName>()
            .SetOrder(PrepareUserCodePrincipal.Descriptor.Order + 550)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ProcessSignInContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        Project(context.AccessTokenPrincipal);
        Project(context.IdentityTokenPrincipal);

        // The id_token is already covered by IdentityTokenPrincipal above; the
        // issued principal only needs the same treatment when it is the access
        // token, which mirrors how DPoP confirmation is attached.
        if (context.IssuedTokenType is OpenIddictConstants.TokenTypeIdentifiers.AccessToken)
        {
            Project(context.IssuedTokenPrincipal);
        }

        return ValueTask.CompletedTask;
    }

    private static void Project(ClaimsPrincipal? principal)
    {
        if (principal?.Identity is not ClaimsIdentity identity)
        {
            return;
        }

        Copy(identity, from: ClientEntitlements.LegacyClaimType, to: ClientEntitlements.ClaimType);
        foreach (var legacy in identity.FindAll(ClientEntitlements.LegacyClaimType).ToArray())
        {
            identity.RemoveClaim(legacy);
        }
    }

    /// <summary>
    ///     Mirrors every value of <paramref name="from"/> onto
    ///     <paramref name="to"/>, skipping values the target already carries.
    /// </summary>
    /// <remarks>
    ///     De-duplicated: a value stored under both names must not appear twice.
    /// </remarks>
    private static void Copy(ClaimsIdentity identity, string from, string to)
    {
        var sources = identity.FindAll(from).ToArray();
        if (sources.Length == 0)
        {
            return;
        }

        var present = identity.FindAll(to)
            .Select(claim => claim.Value)
            .ToHashSet(StringComparer.Ordinal);

        foreach (var source in sources)
        {
            if (!present.Add(source.Value))
            {
                continue;
            }

            identity.AddClaim(new Claim(to, source.Value, source.ValueType, source.Issuer));
        }
    }
}
