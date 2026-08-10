using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace Sufficit.Identity.STS.Tokens;

internal sealed record AccessTokenFormatDecision(
    AccessTokenStorageMode Format,
    bool HasConflict = false);

internal sealed class AccessTokenFormatPolicy(TokenLifetimeOptions options)
{
    public AccessTokenFormatDecision Resolve(
        string? clientId,
        IEnumerable<string> resources)
    {
        var resourceFormats = resources
            .Distinct(StringComparer.Ordinal)
            .Where(options.AccessTokenFormatsByResource.ContainsKey)
            .Select(resource => options.AccessTokenFormatsByResource[resource])
            .Distinct()
            .ToArray();
        if (resourceFormats.Length > 1)
        {
            return new(default, HasConflict: true);
        }
        if (resourceFormats.Length == 1)
        {
            return new(resourceFormats[0]);
        }
        if (!string.IsNullOrWhiteSpace(clientId)
            && options.AccessTokenFormatsByClient.TryGetValue(
                clientId,
                out var clientFormat))
        {
            return new(clientFormat);
        }
        return new(options.UseReferenceAccessTokens
            ? AccessTokenStorageMode.Reference
            : AccessTokenStorageMode.Jwt);
    }
}

internal sealed class ApplyAccessTokenFormat(
    AccessTokenFormatPolicy policy)
    : IOpenIddictServerHandler<OpenIddictServerEvents.GenerateTokenContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<
                OpenIddictServerEvents.GenerateTokenContext>()
            .UseSingletonHandler<ApplyAccessTokenFormat>()
            .SetOrder(int.MinValue + 100_000)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(
        OpenIddictServerEvents.GenerateTokenContext context)
    {
        // Personal tokens and other explicit low-level callers deliberately
        // set IsReferenceToken themselves and do not carry a protocol request.
        if (context.Request is null
            || !string.Equals(
                context.TokenType,
                OpenIddictConstants.TokenTypeIdentifiers.AccessToken,
                StringComparison.Ordinal))
        {
            return ValueTask.CompletedTask;
        }

        var decision = policy.Resolve(
            context.ClientId,
            context.Principal?.GetResources() ?? []);
        if (decision.HasConflict)
        {
            context.Reject(
                error: OpenIddictConstants.Errors.InvalidTarget,
                description:
                    "The requested resources require conflicting access-token formats.");
            return ValueTask.CompletedTask;
        }

        context.IsReferenceToken =
            decision.Format == AccessTokenStorageMode.Reference;
        return ValueTask.CompletedTask;
    }
}

internal sealed class PrepareSelfContainedAccessToken
    : IOpenIddictServerHandler<OpenIddictServerEvents.GenerateTokenContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<
                OpenIddictServerEvents.GenerateTokenContext>()
            .UseSingletonHandler<PrepareSelfContainedAccessToken>()
            .SetOrder(
                OpenIddictServerHandlers.Protection.GenerateIdentityModelToken
                    .Descriptor.Order - 2)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(
        OpenIddictServerEvents.GenerateTokenContext context)
    {
        if (context.Request is not null
            && !context.IsReferenceToken
            && string.Equals(
                context.TokenType,
                OpenIddictConstants.TokenTypeIdentifiers.AccessToken,
                StringComparison.Ordinal))
        {
            // A Jwt rule means a signed self-contained JWS that resource
            // servers can validate from public signing metadata. Keeping the
            // server-only encryption credential would produce a JWE and defeat
            // that migration contract.
            context.EncryptionCredentials = null;
            if (context.SecurityTokenDescriptor is not null)
            {
                context.SecurityTokenDescriptor.EncryptingCredentials = null;
            }
        }
        return ValueTask.CompletedTask;
    }
}
