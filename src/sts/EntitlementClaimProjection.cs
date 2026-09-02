using System.Security.Claims;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;

namespace Sufficit.Identity.STS;

/// <summary>
///     Emits the authorization grant under both claim names, whichever one it is
///     stored as.
/// </summary>
/// <remarks>
///     <para>
///         The persisted claim type travels straight into the token: there is no
///         translation layer between storage and wire. That coupling made
///         renaming the stored type a breaking change for every consumer at
///         once — the data migration was the dangerous operation, and it had to
///         be scheduled against the slowest application to adopt the new name.
///     </para>
///     <para>
///         This handler breaks that coupling. Whatever the grant is stored as,
///         both <c>directive</c> and <c>entitlements</c> reach the token, so a
///         consumer may read either one and the storage rename becomes an
///         internal detail nobody observes.
///     </para>
///     <para>
///         <b>Why here, and not where destinations are assigned.</b> By this
///         point OpenIddict has already built the per-token principals, so a
///         claim is present only if it survived the claim-to-scope gate. Copying
///         it inside those principals therefore inherits that decision exactly:
///         a grant withheld for want of the mapped scope has nothing to copy,
///         and cannot leak under the second name. Adding the twin earlier, next
///         to the source claim, would require re-deriving the gate — and a
///         second implementation of a security decision is a second thing to get
///         wrong.
///     </para>
/// </remarks>
internal sealed class ProjectEntitlementClaimUnderBothNames
    : IOpenIddictServerHandler<ProcessSignInContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
            .UseSingletonHandler<ProjectEntitlementClaimUnderBothNames>()
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
        Copy(identity, from: ClientEntitlements.ClaimType, to: ClientEntitlements.LegacyClaimType);
    }

    /// <summary>
    ///     Mirrors every value of <paramref name="from"/> onto
    ///     <paramref name="to"/>, skipping values the target already carries.
    /// </summary>
    /// <remarks>
    ///     The de-duplication matters because the client-credentials path
    ///     already stamps both names itself. Without it, a machine token would
    ///     carry each grant twice and every consumer counting values would be
    ///     wrong.
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
