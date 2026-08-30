using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using OpenIddict.Server;
using OpenIddict.Validation.AspNetCore;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.STS.Security;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Sufficit.Identity.STS.Controllers;

public sealed partial class PersonalTokensController
{
    private async Task<object?> FindOwnedTokenAsync(
        string id,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(id))
        {
            return null;
        }

        var token = await _tokenManager.FindByIdAsync(id, cancellationToken);
        if (token is null
            || !string.Equals(
                await _tokenManager.GetSubjectAsync(token, cancellationToken),
                RequireSubject(),
                StringComparison.Ordinal)
            || !await _tokenManager.HasTypeAsync(
                token,
                TokenTypeIdentifiers.AccessToken,
                cancellationToken)
            || string.IsNullOrWhiteSpace(
                await _tokenManager.GetReferenceIdAsync(token, cancellationToken)))
        {
            return null;
        }

        return token;
    }

    private async Task<PersonalTokenSummary> ToSummaryAsync(
        object token,
        CancellationToken cancellationToken)
    {
        var properties = await _tokenManager.GetPropertiesAsync(token, cancellationToken);
        var subject = await _tokenManager.GetSubjectAsync(token, cancellationToken);
        return new PersonalTokenSummary(
            Key: await _tokenManager.GetIdAsync(token, cancellationToken)
                ?? throw new InvalidOperationException("The token identifier is missing."),
            Type: await _tokenManager.GetTypeAsync(token, cancellationToken)
                ?? TokenTypeIdentifiers.AccessToken,
            SubjectId: Guid.TryParse(subject, out var subjectId) ? subjectId : null,
            ClientId: GetStringProperty(properties, ClientIdProperty)
                ?? PersonalTokenClientId,
            Creation: await _tokenManager.GetCreationDateAsync(token, cancellationToken)
                ?? DateTimeOffset.MinValue,
            Expiration: await _tokenManager.GetExpirationDateAsync(token, cancellationToken),
            Consumed: await _tokenManager.GetRedemptionDateAsync(token, cancellationToken),
            Description: GetStringProperty(properties, DescriptionProperty),
            SessionId: null,
            Status: await _tokenManager.GetStatusAsync(token, cancellationToken)
                ?? "unknown");
    }

    /// <summary>
    /// Ensures the token metadata bag is durable on every supported relational
    /// provider. OpenIddict's descriptor update is still the canonical path,
    /// but the MariaDB provider can leave <c>properties</c> null when the
    /// generated reference token is updated in the same request. Re-reading
    /// and writing the mapped entity here keeps client/description metadata
    /// available to subsequent requests without storing secrets in the bag.
    /// </summary>
    private async Task PersistPropertiesAsync(
        object token,
        IReadOnlyDictionary<string, JsonElement> properties,
        CancellationToken cancellationToken)
    {
        var id = await _tokenManager.GetIdAsync(token, cancellationToken)
            ?? throw new InvalidOperationException("The token identifier is missing.");
        var entity = await _database.Set<OpenIddictEntityFrameworkCoreToken>()
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken)
            ?? throw new InvalidOperationException("The generated token entry cannot be found.");

        var serialized = properties.Count == 0
            ? null
            : JsonSerializer.Serialize(properties);
        if (string.Equals(entity.Properties, serialized, StringComparison.Ordinal))
        {
            return;
        }

        entity.Properties = serialized;
        await _database.SaveChangesAsync(cancellationToken);
    }

    private Task<Application.Security.PrivilegedTokenMint> GenerateAsync(
        ClaimsPrincipal principal,
        bool createEntry,
        bool referenceToken,
        bool persistPayload) =>
        // A3 (eval 2026-08-14): the dispatch contract lives in the shared
        // minting service — this controller keeps only the personal-token
        // policy (issuance decision, scope attenuation, lifetime bounds).
        _minting.MintPrincipalAsync(
            principal,
            createEntry,
            referenceToken,
            persistPayload);

    private async Task<ClaimsPrincipal?> ValidateAsync(
        string token,
        bool disableLifetimeValidation,
        bool treatPayloadAsReferenceToken = false)
    {
        var transaction = await _factory.CreateTransactionAsync();
        var context = new ValidateTokenContext(transaction)
        {
            Token = token,
            DisableAudienceValidation = true,
            DisableLifetimeValidation = disableLifetimeValidation,
            DisablePresenterValidation = true,
            DisableProofOfPossessionValidation = true,
            IsReferenceToken = treatPayloadAsReferenceToken,
        };
        context.ValidTokenTypes.Add(TokenTypeIdentifiers.AccessToken);

        await _dispatcher.DispatchAsync(context);
        return context.IsRejected ? null : context.Principal;
    }

    private string RequireSubject() =>
        User.FindFirstValue(Claims.Subject)
        ?? throw new InvalidOperationException("The authenticated token has no subject claim.");

    private bool IsAdministrator() => User
        .FindAll(Claims.Role)
        .SelectMany(claim => ParseClaimValues(claim.Value))
        .Any(value => string.Equals(
            value,
            "administrator",
            StringComparison.OrdinalIgnoreCase));

    private IEnumerable<string> GetPersonalTokenDestinations(Claim claim)
    {
        if (claim.Type is Claims.Name or Claims.PreferredUsername)
        {
            if (claim.Subject!.HasScope(Scopes.Profile))
                yield return Destinations.AccessToken;
            yield break;
        }

        if (claim.Type == Claims.Email)
        {
            if (claim.Subject!.HasScope(Scopes.Email))
                yield return Destinations.AccessToken;
            yield break;
        }

        if (claim.Type == Claims.Role)
        {
            if (claim.Subject!.HasScope(Scopes.Roles))
            {
                yield return Destinations.AccessToken;
            }

            yield break;
        }

        foreach (var destination in _applicationClaimPolicy.GetDestinations(
            claim, includeIdentityToken: false))
            yield return destination;
    }

    private static IEnumerable<string> ParseClaimValues(string value)
    {
        if (!value.TrimStart().StartsWith("[", StringComparison.Ordinal))
        {
            yield return value;
            yield break;
        }

        string[]? values;
        try
        {
            values = JsonSerializer.Deserialize<string[]>(value);
        }
        catch (JsonException)
        {
            yield break;
        }

        foreach (var item in values ?? [])
        {
            if (!string.IsNullOrWhiteSpace(item))
            {
                yield return item;
            }
        }
    }

    private string ResolveIssuer()
    {
        return _publicOrigin.Resolve(Request) + "/";
    }

    private string? ResolveCallerClientId() =>
        User.GetClaim(Claims.AuthorizedParty)
        ?? User.GetClaim(Claims.ClientId)
        ?? User.GetPresenters().SingleOrDefault();

    private DateTimeOffset? ResolveAuthenticationTime()
    {
        var value = User.GetClaim("auth_time");
        return long.TryParse(value, out var unixSeconds)
            ? DateTimeOffset.FromUnixTimeSeconds(unixSeconds)
            : null;
    }

    private static bool IsValidExpiration(
        DateTimeOffset expiration,
        DateTimeOffset now,
        bool isAdministrator) =>
        expiration > now
        && expiration <= now.Add(
            isAdministrator ? MaximumLifetime : MaximumUserLifetime);

    private static string? NormalizeDescription(string? description)
    {
        var normalized = description?.Trim();
        return string.IsNullOrWhiteSpace(normalized) ? null : normalized;
    }

    private static void SetStringProperty(
        OpenIddictTokenDescriptor descriptor,
        string name,
        string? value)
    {
        if (value is null)
        {
            descriptor.Properties.Remove(name);
        }
        else
        {
            descriptor.Properties[name] = JsonSerializer.SerializeToElement(value);
        }
    }

    private static string? GetStringProperty(
        IReadOnlyDictionary<string, JsonElement> properties,
        string name) =>
        properties.TryGetValue(name, out var value)
        && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static async Task<List<string>> ToListAsync(
        IAsyncEnumerable<string> values,
        CancellationToken cancellationToken)
    {
        var result = new List<string>();
        await foreach (var value in values.WithCancellation(cancellationToken))
        {
            result.Add(value);
        }

        return result;
    }
}
