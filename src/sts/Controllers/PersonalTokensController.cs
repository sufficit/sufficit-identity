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
using Sufficit.Identity.STS.Security;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Sufficit.Identity.STS.Controllers;

/// <summary>
/// Self-service API for the reference access tokens owned by the authenticated
/// user. This replaces the legacy Endpoints bridge and never exposes an OAuth
/// client secret to the browser.
/// </summary>
[ApiController]
[Route("api/account/tokens")]
[Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
public sealed class PersonalTokensController : ControllerBase
{
    private const string LegacyAddressClaimType = "urn:sufficit:claim:address";
    private const string DescriptionProperty = "urn:sufficit:token:description";
    private const string ClientIdProperty = "urn:sufficit:token:client_id";
    private const string ReplacesTokenIdProperty = "urn:sufficit:token:replaces_id";
    private const string PersonalTokenClientId = "SufficitAPIUserAccess";
    private const string LegacyReferenceTokenType = "legacy_reference_token";
    private static readonly TimeSpan DefaultLifetime = TimeSpan.FromDays(30);
    private static readonly TimeSpan MaximumUserLifetime = TimeSpan.FromDays(365);
    // L1 fix (eval): was 3650 days (10 years) — far too long for a reference
    // token. Capped at 1 year to match MaximumUserLifetime; an admin who needs
    // longer can rotate. Long-lived credentials are revocable, but a shorter
    // ceiling bounds the blast radius of a stolen token.
    private static readonly TimeSpan MaximumLifetime = TimeSpan.FromDays(365);

    private static readonly HashSet<string> ProtocolClaims = new(StringComparer.Ordinal)
    {
        Claims.Audience,
        Claims.AuthorizedParty,
        Claims.ClientId,
        "exp",
        Claims.IssuedAt,
        Claims.Issuer,
        Claims.JwtId,
        Claims.NotBefore,
        Claims.Scope,
        Claims.TokenType,
        Claims.Private.AuthorizationId,
        Claims.Private.CreationDate,
        Claims.Private.ExpirationDate,
        Claims.Private.Issuer,
        Claims.Private.Presenter,
        Claims.Private.Resource,
        Claims.Private.Scope,
        Claims.Private.TokenId,
        Claims.Private.TokenType,
    };

    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly Application.Security.IPrivilegedTokenMintingService _minting;
    private readonly IOpenIddictTokenManager _tokenManager;
    // Validation-only dependencies: minting moved to the shared service, but
    // re-validating a stored payload on expiration updates still dispatches
    // a ValidateTokenContext directly.
    private readonly IOpenIddictServerDispatcher _dispatcher;
    private readonly IOpenIddictServerFactory _factory;
    private readonly AppDbContext _database;
    private readonly SufficitIdentityOptions _options;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IApplicationClaimDestinationPolicy _applicationClaimPolicy;
    private readonly IPublicOriginResolver _publicOrigin;
    private readonly IPersonalTokenIssuancePolicy _issuancePolicy;

    public PersonalTokensController(
        IOpenIddictScopeManager scopeManager,
        Application.Security.IPrivilegedTokenMintingService minting,
        IOpenIddictTokenManager tokenManager,
        IOpenIddictServerDispatcher dispatcher,
        IOpenIddictServerFactory factory,
        AppDbContext database,
        SufficitIdentityOptions options,
        UserManager<ApplicationUser> userManager,
        IApplicationClaimDestinationPolicy applicationClaimPolicy,
        IPublicOriginResolver publicOrigin,
        IPersonalTokenIssuancePolicy issuancePolicy)
    {
        _scopeManager = scopeManager;
        _minting = minting;
        _tokenManager = tokenManager;
        _dispatcher = dispatcher;
        _factory = factory;
        _database = database;
        _options = options;
        _userManager = userManager;
        _applicationClaimPolicy = applicationClaimPolicy;
        _publicOrigin = publicOrigin;
        _issuancePolicy = issuancePolicy;
    }

    [HttpGet]
    [ProducesResponseType<IReadOnlyList<PersonalTokenSummary>>(StatusCodes.Status200OK)]
    public async Task<ActionResult<IReadOnlyList<PersonalTokenSummary>>> List(
        CancellationToken cancellationToken)
    {
        var subject = RequireSubject();
        var tokens = new List<PersonalTokenSummary>();
        var candidates = new List<object>();
        var replacedLegacyTokenIds = new HashSet<string>(StringComparer.Ordinal);

        await foreach (var token in _tokenManager.FindBySubjectAsync(subject, cancellationToken))
        {
            var type = await _tokenManager.GetTypeAsync(token, cancellationToken);
            if ((!string.Equals(
                        type,
                        TokenTypeIdentifiers.AccessToken,
                        StringComparison.Ordinal)
                    && !string.Equals(
                        type,
                        LegacyReferenceTokenType,
                        StringComparison.Ordinal))
                || string.IsNullOrWhiteSpace(
                    await _tokenManager.GetReferenceIdAsync(token, cancellationToken)))
            {
                continue;
            }

            candidates.Add(token);
            if (string.Equals(type, TokenTypeIdentifiers.AccessToken, StringComparison.Ordinal))
            {
                var properties = await _tokenManager.GetPropertiesAsync(token, cancellationToken);
                var replacedId = GetStringProperty(properties, ReplacesTokenIdProperty);
                if (!string.IsNullOrWhiteSpace(replacedId))
                {
                    replacedLegacyTokenIds.Add(replacedId);
                }
            }
        }

        foreach (var token in candidates)
        {
            if (string.Equals(
                    await _tokenManager.GetTypeAsync(token, cancellationToken),
                    LegacyReferenceTokenType,
                    StringComparison.Ordinal)
                && replacedLegacyTokenIds.Contains(
                    await _tokenManager.GetIdAsync(token, cancellationToken) ?? string.Empty))
            {
                // Regenerated tombstones remain in the database for audit and
                // identifier continuity, but no longer clutter the active UI.
                continue;
            }

            tokens.Add(await ToSummaryAsync(token, cancellationToken));
        }

        return Ok(tokens
            .OrderByDescending(token => token.Creation)
            .ToArray());
    }

    [HttpPost]
    [ProducesResponseType<PersonalTokenCreated>(StatusCodes.Status201Created)]
    public async Task<ActionResult<PersonalTokenCreated>> Create(
        [FromBody] CreatePersonalTokenRequest request,
        CancellationToken cancellationToken)
    {
        var subject = RequireSubject();
        var now = DateTimeOffset.UtcNow;
        var expiration = request.Expiration ?? now.Add(DefaultLifetime);
        if (!IsValidExpiration(expiration, now, IsAdministrator()))
        {
            return BadRequest(new
            {
                error = "Token expiration must be in the future and within the permitted lifetime.",
            });
        }
        if (request.Description?.Trim().Length > 250)
        {
            return BadRequest(new { error = "Token description cannot exceed 250 characters." });
        }

        var replacesTokenId = request.ReplacesTokenId?.Trim();
        if (!string.IsNullOrWhiteSpace(replacesTokenId))
        {
            var replacedToken = await _tokenManager.FindByIdAsync(
                replacesTokenId,
                cancellationToken);
            if (replacedToken is null
                || !string.Equals(
                    await _tokenManager.GetSubjectAsync(replacedToken, cancellationToken),
                    subject,
                    StringComparison.Ordinal)
                || !string.Equals(
                    await _tokenManager.GetTypeAsync(replacedToken, cancellationToken),
                    LegacyReferenceTokenType,
                    StringComparison.Ordinal)
                || string.IsNullOrWhiteSpace(
                    await _tokenManager.GetReferenceIdAsync(replacedToken, cancellationToken)))
            {
                return NotFound();
            }
        }

        var user = await _userManager.FindByIdAsync(subject);
        if (user is null)
        {
            return Unauthorized();
        }

        var identity = new ClaimsIdentity(
            authenticationType: "PersonalAccessToken",
            nameType: Claims.Name,
            roleType: Claims.Role);

        // A personal token is a new authorization snapshot, not a clone of the
        // management token used to create it. Rebuild it from ASP.NET Identity
        // so roles/claims added after login are included and revoked values are
        // not kept alive until the caller's current access token expires.
        var roles = await _userManager.GetRolesAsync(user);
        var persistedClaims = await _userManager.GetClaimsAsync(user);

        identity.SetClaim(Claims.Subject, subject);
        identity.SetClaim(Claims.ClientId, PersonalTokenClientId);
        identity.SetClaim(Claims.Name, user.UserName ?? user.Email ?? subject);
        identity.SetClaim(Claims.PreferredUsername, user.UserName ?? user.Email ?? subject);
        if (!string.IsNullOrWhiteSpace(user.Email))
        {
            identity.SetClaim(Claims.Email, user.Email);
        }
        identity.SetClaims(Claims.Role, [.. roles]);

        foreach (var claim in persistedClaims)
        {
            if (ProtocolClaims.Contains(claim.Type)
                || claim.Type.StartsWith(Claims.Prefixes.Private, StringComparison.Ordinal)
                || claim.Type is Claims.Subject
                    or Claims.ClientId
                    or Claims.Name
                    or Claims.PreferredUsername
                    or Claims.Email
                    or Claims.Role)
            {
                continue;
            }

            var projected = claim.Type == Claims.Address
                ? new Claim(
                    LegacyAddressClaimType,
                    claim.Value,
                    ClaimValueTypes.String,
                    claim.Issuer)
                : claim;

            if (!identity.HasClaim(projected.Type, projected.Value))
            {
                identity.AddClaim(new Claim(
                    projected.Type,
                    projected.Value,
                    projected.ValueType,
                    projected.Issuer));
            }
        }

        identity.SetCreationDate(now);
        identity.SetExpirationDate(expiration);
        // Preserve any application-specific claim scopes configured by the
        // host without baking a domain vocabulary into the generic STS.
        var allowedApplicationScopes = _options.ClaimScopeMap.ClaimToScope
            .Values
            .Where(scope => !string.IsNullOrWhiteSpace(scope))
            .Append(Scopes.Roles)
            .Append(Scopes.Profile)
            .Append(Scopes.Email)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        var requestedApplicationScopes = request.Scopes?
            .Where(scope => !string.IsNullOrWhiteSpace(scope))
            .Select(scope => scope.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (requestedApplicationScopes?.Any(scope =>
                !allowedApplicationScopes.Contains(scope, StringComparer.Ordinal)) == true)
        {
            return BadRequest(new
            {
                error = "invalid_scope",
                error_description = "A requested personal-token scope is not allowed by the issuance policy.",
            });
        }
        var issuanceDecision = _issuancePolicy.Evaluate(new PersonalTokenIssuanceContext(
            subject,
            ResolveCallerClientId(),
            User.GetScopes().ToArray(),
            requestedApplicationScopes ?? [],
            allowedApplicationScopes,
            ResolveAuthenticationTime(),
            now,
            expiration,
            !string.IsNullOrWhiteSpace(User.GetClaim(Dpop.DpopProofValidator.ConfirmationClaimType)),
            MfaEvidence.HasMfaEvidence(User)));
        if (issuanceDecision.ShouldReject)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                error = issuanceDecision.ErrorCode,
                error_description = "The personal token exceeds the caller's delegated authority.",
            });
        }
        var applicationScopes = issuanceDecision.EffectiveScopes;
        identity.SetScopes(applicationScopes);
        var resources = await ToListAsync(
            _scopeManager.ListResourcesAsync(identity.GetScopes(), cancellationToken),
            cancellationToken);
        identity.SetResources(resources);

        // GenerateTokenContext is intentionally lower-level than the regular
        // token endpoint pipeline. Materialize the public RFC claims as well
        // as OpenIddict's private metadata so introspection can identify the
        // resource server as an audience and return its authorized claims.
        identity.SetClaim(Claims.Scope, string.Join(' ', applicationScopes));
        identity.SetClaims(Claims.Audience, [.. resources]);
        identity.SetDestinations(GetPersonalTokenDestinations);
        identity.SetClaim(Claims.Private.Issuer, ResolveIssuer());

        var principal = new ClaimsPrincipal(identity);
        var context = await GenerateAsync(
            principal,
            createEntry: true,
            referenceToken: true,
            persistPayload: true);

        var id = context.TokenId;
        if (string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(context.Token))
        {
            throw new InvalidOperationException("OpenIddict did not create the personal access token.");
        }

        var token = await _tokenManager.FindByIdAsync(id, cancellationToken)
            ?? throw new InvalidOperationException("The generated token entry cannot be found.");
        var descriptor = new OpenIddictTokenDescriptor();
        await _tokenManager.PopulateAsync(descriptor, token, cancellationToken);
        SetStringProperty(descriptor, ClientIdProperty, PersonalTokenClientId);
        SetStringProperty(descriptor, DescriptionProperty, NormalizeDescription(request.Description));
        SetStringProperty(descriptor, ReplacesTokenIdProperty, replacesTokenId);
        await _tokenManager.UpdateAsync(token, descriptor, cancellationToken);
        await PersistPropertiesAsync(token, descriptor.Properties, cancellationToken);

        var summary = await ToSummaryAsync(
            await _tokenManager.FindByIdAsync(id, cancellationToken) ?? token,
            cancellationToken);
        return CreatedAtAction(nameof(List), new PersonalTokenCreated(
            context.Token,
            "Bearer",
            summary));
    }

    [HttpPatch("{id}")]
    [ProducesResponseType<PersonalTokenSummary>(StatusCodes.Status200OK)]
    public async Task<ActionResult<PersonalTokenSummary>> Update(
        string id,
        [FromBody] UpdatePersonalTokenRequest request,
        CancellationToken cancellationToken)
    {
        if (!request.UpdateDescription && !request.UpdateExpiration)
        {
            return BadRequest(new { error = "No token field was selected for update." });
        }
        if (request.UpdateDescription && request.Description?.Trim().Length > 250)
        {
            return BadRequest(new { error = "Token description cannot exceed 250 characters." });
        }
        var isAdministrator = IsAdministrator();
        var requestedExpiration = request.Expiration;
        if (request.UpdateExpiration && requestedExpiration is null)
        {
            if (!isAdministrator)
            {
                return BadRequest(new { error = "Expiration is required for non-administrator users." });
            }

            requestedExpiration = DateTimeOffset.UtcNow.Add(MaximumLifetime);
        }
        if (request.UpdateExpiration
            && requestedExpiration is { } expiration
            && !IsValidExpiration(expiration, DateTimeOffset.UtcNow, isAdministrator))
        {
            return BadRequest(new
            {
                error = "Token expiration must be in the future and within the permitted lifetime.",
            });
        }

        var token = await FindOwnedTokenAsync(id, cancellationToken);
        if (token is null)
        {
            return NotFound();
        }

        var descriptor = new OpenIddictTokenDescriptor();
        await _tokenManager.PopulateAsync(descriptor, token, cancellationToken);

        if (request.UpdateDescription)
        {
            SetStringProperty(
                descriptor,
                DescriptionProperty,
                NormalizeDescription(request.Description));
        }

        if (request.UpdateExpiration)
        {
            descriptor.ExpirationDate = requestedExpiration;
            if (!string.IsNullOrWhiteSpace(descriptor.Payload))
            {
                var principal = await ValidateAsync(
                    descriptor.Payload,
                    disableLifetimeValidation: true,
                    treatPayloadAsReferenceToken: true);
                if (principal is null)
                {
                    throw new InvalidOperationException("The stored token payload cannot be validated.");
                }

                principal.SetExpirationDate(requestedExpiration);
                principal.SetClaim(Claims.Private.Issuer, ResolveIssuer());
                var generated = await GenerateAsync(
                    principal,
                    createEntry: false,
                    referenceToken: false,
                    persistPayload: false);
                descriptor.Payload = generated.Token;
            }
        }

        await _tokenManager.UpdateAsync(token, descriptor, cancellationToken);
        await PersistPropertiesAsync(token, descriptor.Properties, cancellationToken);
        return Ok(await ToSummaryAsync(
            await _tokenManager.FindByIdAsync(id, cancellationToken) ?? token,
            cancellationToken));
    }

    [HttpDelete("{id}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Revoke(string id, CancellationToken cancellationToken)
    {
        var token = await FindOwnedTokenAsync(id, cancellationToken);
        if (token is null)
        {
            return NotFound();
        }

        if (!await _tokenManager.TryRevokeAsync(token, cancellationToken))
        {
            return Conflict(new { error = "The token could not be revoked." });
        }

        return NoContent();
    }

    [HttpPost("introspect")]
    [ProducesResponseType<PersonalTokenIntrospectionResponse>(StatusCodes.Status200OK)]
    public async Task<ActionResult<PersonalTokenIntrospectionResponse>> Introspect(
        [FromBody] IntrospectPersonalTokenRequest request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.Token))
        {
            return Ok(PersonalTokenIntrospectionResponse.Inactive);
        }

        var tokenById = await _tokenManager.FindByIdAsync(request.Token, cancellationToken);
        var token = tokenById
            ?? await _tokenManager.FindByReferenceIdAsync(request.Token, cancellationToken);
        if (token is null
            || !string.Equals(
                await _tokenManager.GetSubjectAsync(token, cancellationToken),
                RequireSubject(),
                StringComparison.Ordinal)
            || !await _tokenManager.HasTypeAsync(
                token,
                TokenTypeIdentifiers.AccessToken,
                cancellationToken))
        {
            return Ok(PersonalTokenIntrospectionResponse.Inactive);
        }

        var descriptor = new OpenIddictTokenDescriptor();
        await _tokenManager.PopulateAsync(descriptor, token, cancellationToken);
        if (string.IsNullOrWhiteSpace(descriptor.Payload)
            || !string.Equals(descriptor.Status, Statuses.Valid, StringComparison.Ordinal))
        {
            return Ok(PersonalTokenIntrospectionResponse.Inactive);
        }

        var principal = await ValidateAsync(
            tokenById is null ? request.Token : descriptor.Payload,
            disableLifetimeValidation: false,
            treatPayloadAsReferenceToken: tokenById is not null);
        if (principal is null)
        {
            return Ok(PersonalTokenIntrospectionResponse.Inactive);
        }

        var properties = await _tokenManager.GetPropertiesAsync(token, cancellationToken);
        return Ok(new PersonalTokenIntrospectionResponse(
            Active: true,
            Scope: string.Join(' ', principal.GetScopes()),
            ClientId: GetStringProperty(properties, ClientIdProperty)
                ?? principal.GetClaim(Claims.ClientId),
            Username: principal.GetClaim(Claims.PreferredUsername)
                ?? principal.GetClaim(Claims.Name),
            TokenType: "Bearer",
            Expiration: descriptor.ExpirationDate?.ToUnixTimeSeconds(),
            IssuedAt: descriptor.CreationDate?.ToUnixTimeSeconds(),
            NotBefore: null,
            Subject: descriptor.Subject,
            Audiences: principal.GetAudiences().ToArray(),
            Issuer: principal.GetClaim(Claims.Issuer)
                ?? principal.GetClaim(Claims.Private.Issuer),
            JwtId: principal.GetClaim(Claims.JwtId)));
    }

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

public sealed record CreatePersonalTokenRequest(
    string? Description,
    DateTimeOffset? Expiration,
    string? ReplacesTokenId = null,
    IReadOnlyCollection<string>? Scopes = null);

public sealed record UpdatePersonalTokenRequest(
    bool UpdateDescription,
    string? Description,
    bool UpdateExpiration,
    DateTimeOffset? Expiration);

public sealed record IntrospectPersonalTokenRequest(string Token);

public sealed record PersonalTokenSummary(
    string Key,
    string Type,
    Guid? SubjectId,
    string ClientId,
    DateTimeOffset Creation,
    DateTimeOffset? Expiration,
    DateTimeOffset? Consumed,
    string? Description,
    Guid? SessionId,
    string Status);

public sealed record PersonalTokenCreated(
    string AccessToken,
    string TokenType,
    PersonalTokenSummary Token);

public sealed record PersonalTokenIntrospectionResponse(
    [property: JsonPropertyName("active")] bool Active,
    [property: JsonPropertyName("scope")] string? Scope,
    [property: JsonPropertyName("client_id")] string? ClientId,
    [property: JsonPropertyName("username")] string? Username,
    [property: JsonPropertyName("token_type")] string? TokenType,
    [property: JsonPropertyName("exp")] long? Expiration,
    [property: JsonPropertyName("iat")] long? IssuedAt,
    [property: JsonPropertyName("nbf")] long? NotBefore,
    [property: JsonPropertyName("sub")] string? Subject,
    [property: JsonPropertyName("aud")] string[] Audiences,
    [property: JsonPropertyName("iss")] string? Issuer,
    [property: JsonPropertyName("jti")] string? JwtId)
{
    public static PersonalTokenIntrospectionResponse Inactive { get; } = new(
        false, null, null, null, null, null, null, null, null, [], null, null);
}
