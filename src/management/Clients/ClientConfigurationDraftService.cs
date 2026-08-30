using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using System.Security.Cryptography;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Clients;

internal sealed class ClientConfigurationDraftService(
    AppDbContext database,
    IDataProtectionProvider dataProtection,
    IOpenIddictApplicationManager applications,
    IOpenIddictScopeManager scopes,
    IClientManagementService clients,
    IManagementAuthorizationEvaluator authorization,
    IOptions<ManagementOptions> managementOptions,
    IIdentityRuntimeCapabilityCatalog runtimeCapabilities,
    TimeProvider timeProvider,
    ILogger<ClientConfigurationDraftService> logger)
    : IClientConfigurationDraftService
{
    private const string ActiveStatus = "active";
    private const string CompletedStatus = "completed";
    private static readonly TimeSpan DraftLifetime = TimeSpan.FromDays(14);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly IDataProtector rootProtector = dataProtection.CreateProtector(
        "Sufficit.Identity.Management.ClientDrafts.v1");

    private static readonly ManagementClientProfile[] Profiles =
    [
        new(
            ManagementClientProfiles.Web,
            "Aplicação web / BFF",
            "Login interativo processado por um servidor capaz de proteger uma credencial.",
            "browser",
            "Authorization Code + PKCE, renovação e consentimento explícito.",
            RequiresRedirectUris: true,
            CreatesCredential: true),
        new(
            ManagementClientProfiles.Spa,
            "SPA pública",
            "Aplicação executada no navegador, sem segredo incorporado ao código.",
            "code",
            "Authorization Code + PKCE, sem client secret.",
            RequiresRedirectUris: true,
            CreatesCredential: false),
        new(
            ManagementClientProfiles.Native,
            "Aplicativo móvel ou desktop",
            "Cliente público instalado no dispositivo do usuário.",
            "device",
            "Authorization Code + PKCE com redirect de loopback seguro.",
            RequiresRedirectUris: true,
            CreatesCredential: false),
        new(
            ManagementClientProfiles.Service,
            "Serviço para serviço",
            "Integração sem usuário para jobs, APIs internas e automações.",
            "server",
            "Client Credentials com uma credencial exibida uma única vez.",
            RequiresRedirectUris: false,
            CreatesCredential: true),
        new(
            ManagementClientProfiles.Device,
            "Dispositivo ou CLI",
            "Equipamento ou terminal com entrada limitada que autoriza em outro navegador.",
            "terminal",
            "Device Authorization com renovação opcional.",
            RequiresRedirectUris: false,
            CreatesCredential: false),
        new(
            ManagementClientProfiles.Advanced,
            "Configuração avançada",
            "Comece com padrões seguros e ajuste conscientemente cada fluxo.",
            "settings",
            "Controle explícito com as mesmas proteções do configurador.",
            RequiresRedirectUris: true,
            CreatesCredential: false),
    ];

    public async Task<IReadOnlyList<ManagementClientProfile>> GetProfilesAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        await DemandCreateAsync(context, cancellationToken);
        var capabilities = runtimeCapabilities.Current;
        return Profiles
            .Select(profile => WithAvailability(profile, capabilities))
            .ToArray();
    }

    public async Task<IReadOnlyList<ManagementClientAvailableScope>> GetAvailableScopesAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        await DemandCreateAsync(context, cancellationToken);
        var result = new List<ManagementClientAvailableScope>
        {
            new("openid", "Identidade OpenID", "Identifica o usuário no protocolo OpenID Connect.", [], true),
            new("profile", "Perfil básico", "Nome e atributos básicos do perfil.", [], true),
            new("email", "E-mail", "Endereço de e-mail e seu estado de confirmação.", [], true),
            new("phone", "Telefone", "Número de telefone e seu estado de confirmação.", [], true),
            new("address", "Endereço", "Dados de endereço padronizados pelo OpenID Connect.", [], true),
            new("roles", "Papéis", "Papéis genéricos emitidos para o usuário.", [], true),
            new("offline_access", "Acesso contínuo", "Permite solicitar refresh tokens.", [], true),
        };
        var reserved = managementOptions.Value.ReservedApiScopes;
        await foreach (var scope in scopes.ListAsync(cancellationToken: cancellationToken))
        {
            var name = await scopes.GetNameAsync(scope, cancellationToken);
            if (string.IsNullOrWhiteSpace(name)
                || reserved.Contains(name, StringComparer.Ordinal)
                || result.Any(item => string.Equals(item.Name, name, StringComparison.Ordinal)))
            {
                continue;
            }
            result.Add(new ManagementClientAvailableScope(
                name,
                await scopes.GetDisplayNameAsync(scope, cancellationToken) ?? name,
                await scopes.GetDescriptionAsync(scope, cancellationToken),
                await scopes.GetResourcesAsync(scope, cancellationToken),
                IsProtocolScope: false));
        }

        return result
            .OrderByDescending(item => item.IsProtocolScope)
            .ThenBy(item => item.DisplayName, StringComparer.CurrentCultureIgnoreCase)
            .ToArray();
    }

    public async Task<IReadOnlyList<ManagementClientDraftSummary>> ListAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        await DemandCreateAsync(context, cancellationToken);
        await DeleteExpiredAsync(context.OperatorSubject, cancellationToken);

        var rows = await database.ManagementClientDrafts
            .AsNoTracking()
            .Where(row => row.OwnerSubject == context.OperatorSubject
                && row.Status == ActiveStatus)
            .OrderByDescending(row => row.UpdatedAtUtc)
            .ToArrayAsync(cancellationToken);

        var result = new List<ManagementClientDraftSummary>(rows.Length);
        foreach (var row in rows)
        {
            var values = Unprotect(row);
            var validation = await ValidateAsync(values, cancellationToken);
            result.Add(new ManagementClientDraftSummary(
                row.Id,
                row.Profile,
                FindProfile(row.Profile).DisplayName,
                row.CurrentStep,
                NullIfWhiteSpace(values.ClientId),
                NullIfWhiteSpace(values.DisplayName),
                validation.IsReady,
                AsUtcOffset(row.UpdatedAtUtc),
                AsUtcOffset(row.ExpiresAtUtc)));
        }

        return result;
    }

    public async Task<ManagementClientDraftDetail> CreateAsync(
        string profile,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        await DemandCreateAsync(context, cancellationToken);
        var definition = FindProfile(profile);
        EnsureProfileAvailable(definition, runtimeCapabilities.Current);
        var now = timeProvider.GetUtcNow();
        var row = new ManagementClientDraftRecord
        {
            Id = Guid.NewGuid(),
            OwnerSubject = context.OperatorSubject,
            Profile = definition.Id,
            CurrentStep = ManagementClientDraftSteps.Identity,
            Status = ActiveStatus,
            Version = NewVersion(),
            CreatedAtUtc = now.UtcDateTime,
            UpdatedAtUtc = now.UtcDateTime,
            ExpiresAtUtc = now.Add(DraftLifetime).UtcDateTime,
        };
        var values = DefaultsFor(definition.Id);
        row.ProtectedPayload = Protect(row, values);
        database.ManagementClientDrafts.Add(row);
        await database.SaveChangesAsync(cancellationToken);
        return await ToDetailAsync(row, values, cancellationToken);
    }

    public async Task<ManagementClientDraftDetail> GetAsync(
        Guid id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        await DemandCreateAsync(context, cancellationToken);
        var row = await FindOwnedAsync(id, context, tracking: false, cancellationToken);
        return await ToDetailAsync(row, Unprotect(row), cancellationToken);
    }

    public async Task<ManagementClientDraftDetail> SaveAsync(
        SaveManagementClientDraftCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        ArgumentNullException.ThrowIfNull(command.Values);
        await DemandCreateAsync(context, cancellationToken);
        var row = await FindOwnedAsync(command.Id, context, tracking: true, cancellationToken);
        EnsureActive(row);

        if (!string.Equals(row.Version, command.Version, StringComparison.Ordinal))
        {
            throw new ManagementConflictException(
                "client_draft_changed",
                "Este rascunho foi alterado em outra sessão. Recarregue antes de continuar.");
        }

        var step = NormalizeStep(command.CurrentStep);
        NormalizeValues(command.Values);
        var now = timeProvider.GetUtcNow();
        row.CurrentStep = step;
        row.ProtectedPayload = Protect(row, command.Values);
        row.Version = NewVersion();
        row.UpdatedAtUtc = now.UtcDateTime;
        row.ExpiresAtUtc = now.Add(DraftLifetime).UtcDateTime;
        await database.SaveChangesAsync(cancellationToken);
        return await ToDetailAsync(row, command.Values, cancellationToken);
    }

    public async Task<CompleteManagementClientDraftResult> CompleteAsync(
        Guid id,
        string version,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        await DemandCreateAsync(context, cancellationToken);
        var row = await FindOwnedAsync(id, context, tracking: true, cancellationToken);

        if (row.Status == CompletedStatus && row.CreatedClientId is not null)
        {
            return new CompleteManagementClientDraftResult(
                await clients.GetByClientIdAsync(
                    row.CreatedClientId,
                    context,
                    cancellationToken),
                OneTimeSecret: null);
        }

        EnsureActive(row);
        if (!string.Equals(row.Version, version, StringComparison.Ordinal))
        {
            throw new ManagementConflictException(
                "client_draft_changed",
                "Este rascunho foi alterado em outra sessão. Recarregue antes de criar a aplicação.");
        }

        var values = Unprotect(row);
        NormalizeValues(values);
        var validation = await ValidateAsync(values, cancellationToken);
        var error = validation.Errors.FirstOrDefault();
        if (error is not null)
        {
            throw new ManagementValidationException(error.Code, error.Message, error.Field);
        }

        var oneTimeSecret = string.Equals(
            values.ClientType,
            OpenIddictConstants.ClientTypes.Confidential,
            StringComparison.Ordinal)
                ? WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32))
                : null;

        var grantTypes = new List<string>();
        if (values.AuthorizationCode)
        {
            grantTypes.Add("authorization_code");
        }
        if (values.RefreshToken)
        {
            grantTypes.Add("refresh_token");
        }
        if (values.ClientCredentials)
        {
            grantTypes.Add("client_credentials");
        }
        if (values.DeviceCode)
        {
            grantTypes.Add("urn:ietf:params:oauth:grant-type:device_code");
        }

        var client = await clients.CreateAsync(
            new CreateManagementClientCommand(
                values.ClientId,
                oneTimeSecret,
                values.DisplayName,
                values.ConsentType,
                values.RequirePar,
                grantTypes,
                values.Scopes,
                values.RedirectUris,
                values.PostLogoutRedirectUris,
                values.FrontchannelLogoutUri,
                values.FrontchannelLogoutSessionRequired,
                values.BackchannelLogoutUri,
                values.BackchannelLogoutSessionRequired,
                null,
                values.AccessTokenLifetimeMinutes,
                values.IdentityTokenLifetimeMinutes,
                values.RefreshTokenLifetimeDays),
            context,
            cancellationToken);

        row.Status = CompletedStatus;
        row.CreatedClientId = client.ClientId;
        row.CurrentStep = ManagementClientDraftSteps.Review;
        row.Version = NewVersion();
        row.UpdatedAtUtc = timeProvider.GetUtcNow().UtcDateTime;
        row.ProtectedPayload = Protect(row, values);
        await database.SaveChangesAsync(cancellationToken);

        return new CompleteManagementClientDraftResult(client, oneTimeSecret);
    }

    public async Task AbandonAsync(
        Guid id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        await DemandCreateAsync(context, cancellationToken);
        var row = await FindOwnedAsync(id, context, tracking: true, cancellationToken);
        EnsureActive(row);
        database.ManagementClientDrafts.Remove(row);
        await database.SaveChangesAsync(cancellationToken);
    }

    private async Task<ManagementClientDraftDetail> ToDetailAsync(
        ManagementClientDraftRecord row,
        ManagementClientDraftValues values,
        CancellationToken cancellationToken) =>
        new(
            row.Id,
            row.Profile,
            row.CurrentStep,
            values,
            await ValidateAsync(values, cancellationToken),
            row.Version,
            AsUtcOffset(row.UpdatedAtUtc),
            AsUtcOffset(row.ExpiresAtUtc));

    private async Task<ClientDraftValidation> ValidateAsync(
        ManagementClientDraftValues values,
        CancellationToken cancellationToken)
    {
        var issues = new List<ClientValidationIssue>();
        AddRequired(issues, values.DisplayName, "display_name_required",
            ManagementClientDraftSteps.Identity, "displayName",
            "Informe um nome que permita reconhecer a aplicação.");
        AddRequired(issues, values.ClientId, "client_id_required",
            ManagementClientDraftSteps.Identity, "clientId",
            "Informe um client ID estável para a integração.");

        var clientId = values.ClientId.Trim();
        if (clientId.Length > IdentityDatabaseSchema.OpenIddictClientIdLength)
        {
            AddError(issues, "client_id_too_long", ManagementClientDraftSteps.Identity,
                "clientId", $"Use no máximo {IdentityDatabaseSchema.OpenIddictClientIdLength} caracteres.");
        }
        else if (clientId.Length > 0 && clientId.Any(char.IsWhiteSpace))
        {
            issues.Add(new ClientValidationIssue(
                "client_id_whitespace",
                ManagementClientDraftSteps.Identity,
                "clientId",
                ClientValidationSeverity.Warning,
                "Espaços no client ID dificultam integrações e diagnóstico.",
                "Prefira letras, números, ponto, hífen, sublinhado ou dois-pontos."));
        }

        if (clientId.Length > 0 && await applications.FindByClientIdAsync(
                clientId,
                cancellationToken) is not null)
        {
            AddError(issues, "client_already_exists", ManagementClientDraftSteps.Identity,
                "clientId", "Este client ID já pertence a outra aplicação.");
        }

        var grants = GrantCount(values);
        if (grants == 0)
        {
            AddError(issues, "grant_required", ManagementClientDraftSteps.Protocol,
                "grantTypes", "Escolha como a aplicação irá obter tokens.");
        }
        if (values.ClientCredentials &&
            string.Equals(values.ClientType, "public", StringComparison.Ordinal))
        {
            AddError(issues, "confidential_client_required", ManagementClientDraftSteps.Protocol,
                "clientType", "Client Credentials exige uma aplicação confidencial.");
        }
        if (values.AuthorizationCode && values.RedirectUris.Count == 0)
        {
            AddError(issues, "redirect_uri_required", ManagementClientDraftSteps.Uris,
                "redirectUris", "O login interativo exige pelo menos uma Redirect URI.");
        }
        if (values.Scopes.Contains("offline_access", StringComparer.Ordinal) && !values.RefreshToken)
        {
            AddError(issues, "offline_access_requires_refresh_token",
                ManagementClientDraftSteps.Permissions, "scopes",
                "offline_access exige que Refresh Token esteja habilitado.");
        }

        ValidateOptionalLifetime(issues, values.AccessTokenLifetimeMinutes,
            TokenLifetimeLimits.MinimumAccessTokenLifetimeMinutes,
            TokenLifetimeLimits.MaximumAccessTokenLifetimeMinutes,
            "accessTokenLifetimeMinutes", "Access token deve ficar entre 1 minuto e 7 dias.");
        ValidateOptionalLifetime(issues, values.IdentityTokenLifetimeMinutes,
            TokenLifetimeLimits.MinimumIdentityTokenLifetimeMinutes,
            TokenLifetimeLimits.MaximumIdentityTokenLifetimeMinutes,
            "identityTokenLifetimeMinutes", "ID token deve ficar entre 1 e 120 minutos.");
        ValidateOptionalLifetime(issues, values.RefreshTokenLifetimeDays,
            TokenLifetimeLimits.MinimumRefreshTokenLifetimeDays,
            TokenLifetimeLimits.MaximumRefreshTokenLifetimeDays,
            "refreshTokenLifetimeDays", "Refresh token deve ficar entre 1 e 365 dias.");

        if (values.ClientCredentials && !values.AuthorizationCode && !values.DeviceCode)
        {
            foreach (var scope in values.Scopes.Where(IsUserIdentityScope))
            {
                AddError(issues, "identity_scope_without_user",
                    ManagementClientDraftSteps.Permissions, "scopes",
                    $"O scope '{scope}' representa um usuário e não se aplica a serviço para serviço.");
            }
        }

        ValidateUris(issues, values.RedirectUris, "redirectUris");
        ValidateUris(issues, values.PostLogoutRedirectUris, "postLogoutRedirectUris");
        ValidateOptionalUri(issues, values.FrontchannelLogoutUri, "frontchannelLogoutUri");
        ValidateOptionalUri(issues, values.BackchannelLogoutUri, "backchannelLogoutUri");
        if (TryAbsoluteUri(values.FrontchannelLogoutUri, out var frontchannelUri)
            && !values.RedirectUris
                .Select(value => TryAbsoluteUri(value, out var redirectUri) ? redirectUri : null)
                .Any(redirectUri => redirectUri is not null && SameOrigin(redirectUri, frontchannelUri)))
        {
            AddError(issues, "frontchannel_logout_origin_mismatch",
                ManagementClientDraftSteps.Uris, "frontchannelLogoutUri",
                "A URI de front-channel deve usar o mesmo protocolo, host e porta de uma Redirect URI.");
        }
        if (values.FrontchannelLogoutSessionRequired &&
            string.IsNullOrWhiteSpace(values.FrontchannelLogoutUri))
        {
            AddError(issues, "frontchannel_logout_uri_required", ManagementClientDraftSteps.Uris,
                "frontchannelLogoutUri", "Informe a URI antes de exigir logout por sessão.");
        }
        if (values.BackchannelLogoutSessionRequired &&
            string.IsNullOrWhiteSpace(values.BackchannelLogoutUri))
        {
            AddError(issues, "backchannel_logout_uri_required", ManagementClientDraftSteps.Uris,
                "backchannelLogoutUri", "Informe a URI antes de exigir logout por sessão.");
        }

        return new ClientDraftValidation(
            issues.All(issue => issue.Severity is not ClientValidationSeverity.Error),
            issues);
    }

    private static void ValidateUris(
        ICollection<ClientValidationIssue> issues,
        IReadOnlyList<string> values,
        string field)
    {
        foreach (var value in values)
        {
            ValidateOptionalUri(issues, value, field);
        }

        var duplicates = values
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .GroupBy(value => value.Trim(), StringComparer.Ordinal)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key);
        foreach (var duplicate in duplicates)
        {
            AddError(issues, "redirect_uri_duplicate", ManagementClientDraftSteps.Uris,
                field, $"A URI '{duplicate}' aparece mais de uma vez.");
        }
    }

    private static void ValidateOptionalUri(
        ICollection<ClientValidationIssue> issues,
        string? value,
        string field)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }
        if (!Uri.TryCreate(value.Trim(), UriKind.Absolute, out var uri))
        {
            AddError(issues, "redirect_uri_invalid", ManagementClientDraftSteps.Uris,
                field, $"'{value}' não é uma URI absoluta válida.");
            return;
        }
        if (!string.IsNullOrEmpty(uri.Fragment))
        {
            AddError(issues, "redirect_uri_fragment", ManagementClientDraftSteps.Uris,
                field, "Redirect URIs não podem conter fragmento (#...).");
        }
        var loopback = uri.IsLoopback || string.Equals(
            uri.Host,
            "localhost",
            StringComparison.OrdinalIgnoreCase);
        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            && !loopback)
        {
            AddError(issues, "redirect_uri_https_required", ManagementClientDraftSteps.Uris,
                field, "Use HTTPS. HTTP é aceito somente em loopback local.");
        }
    }

    private static bool TryAbsoluteUri(string? value, out Uri uri)
    {
        if (!string.IsNullOrWhiteSpace(value)
            && Uri.TryCreate(value.Trim(), UriKind.Absolute, out var parsed))
        {
            uri = parsed;
            return true;
        }

        uri = null!;
        return false;
    }

    private static void ValidateOptionalLifetime(
        ICollection<ClientValidationIssue> issues,
        int? value,
        int minimum,
        int maximum,
        string field,
        string message)
    {
        if (value is not null && (value < minimum || value > maximum))
        {
            AddError(issues, $"{field}_invalid", ManagementClientDraftSteps.Protocol,
                field, message);
        }
    }

    private static bool SameOrigin(Uri left, Uri right) =>
        string.Equals(left.Scheme, right.Scheme, StringComparison.OrdinalIgnoreCase)
        && string.Equals(left.Host, right.Host, StringComparison.OrdinalIgnoreCase)
        && left.Port == right.Port;

    private async Task<ManagementClientDraftRecord> FindOwnedAsync(
        Guid id,
        ManagementRequestContext context,
        bool tracking,
        CancellationToken cancellationToken)
    {
        var query = tracking
            ? database.ManagementClientDrafts.AsQueryable()
            : database.ManagementClientDrafts.AsNoTracking();
        var row = await query.FirstOrDefaultAsync(candidate =>
            candidate.Id == id && candidate.OwnerSubject == context.OperatorSubject,
            cancellationToken);
        if (row is null)
        {
            throw new ManagementNotFoundException(
                "client_draft_not_found",
                "O rascunho não existe ou não pertence a este operador.");
        }
        if (row.ExpiresAtUtc <= timeProvider.GetUtcNow().UtcDateTime)
        {
            if (tracking)
            {
                database.ManagementClientDrafts.Remove(row);
                await database.SaveChangesAsync(cancellationToken);
            }
            throw new ManagementNotFoundException(
                "client_draft_expired",
                "Este rascunho expirou. Inicie uma nova configuração.");
        }
        return row;
    }

    private async Task DeleteExpiredAsync(
        string ownerSubject,
        CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow().UtcDateTime;
        await database.ManagementClientDrafts
            .Where(row => row.OwnerSubject == ownerSubject && row.ExpiresAtUtc <= now)
            .ExecuteDeleteAsync(cancellationToken);
    }

    private async Task DemandCreateAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken)
    {
        var decision = await authorization.EvaluateAsync(
            context.Operator,
            ManagementCapabilities.ClientsCreate,
            new ManagementResource(ManagementResourceTypes.ClientCollection),
            cancellationToken);
        if (!decision.IsAllowed)
        {
            throw new ManagementAccessException(decision);
        }
    }

    private string Protect(
        ManagementClientDraftRecord row,
        ManagementClientDraftValues values) =>
        DraftProtector(row).Protect(JsonSerializer.Serialize(values, JsonOptions));

    private ManagementClientDraftValues Unprotect(ManagementClientDraftRecord row)
    {
        try
        {
            return JsonSerializer.Deserialize<ManagementClientDraftValues>(
                DraftProtector(row).Unprotect(row.ProtectedPayload),
                JsonOptions) ?? new ManagementClientDraftValues();
        }
        catch (Exception exception) when (exception is CryptographicException or JsonException)
        {
            logger.LogError(
                exception,
                "Unable to read OAuth client draft {DraftId} for operator {OperatorSubject}.",
                row.Id,
                row.OwnerSubject);
            throw new ManagementValidationException(
                "client_draft_unreadable",
                "O rascunho não pôde ser lido com segurança. Abandone-o e inicie outro.");
        }
    }

    private IDataProtector DraftProtector(ManagementClientDraftRecord row) =>
        rootProtector.CreateProtector(row.OwnerSubject, row.Id.ToString("N"));

    private static ManagementClientProfile FindProfile(string? profile) =>
        Profiles.FirstOrDefault(item => string.Equals(
            item.Id,
            profile?.Trim(),
            StringComparison.OrdinalIgnoreCase))
        ?? throw new ManagementValidationException(
            "client_profile_invalid",
            "Escolha um perfil de aplicação disponível.",
            "profile");

    private static ManagementClientProfile WithAvailability(
        ManagementClientProfile profile,
        IdentityRuntimeCapabilitySnapshot capabilities)
    {
        var (available, reason) = profile.Id switch
        {
            ManagementClientProfiles.Web or
            ManagementClientProfiles.Spa or
            ManagementClientProfiles.Native or
            ManagementClientProfiles.Advanced =>
                (capabilities.SupportsGrant(
                    ManagementRuntimeCapabilities.AuthorizationCode),
                 "O runtime não habilita Authorization Code."),
            ManagementClientProfiles.Service =>
                (capabilities.SupportsGrant(
                    ManagementRuntimeCapabilities.ClientCredentials),
                 "O runtime não habilita Client Credentials."),
            ManagementClientProfiles.Device =>
                (capabilities.SupportsGrant(
                        ManagementRuntimeCapabilities.DeviceCode) &&
                 capabilities.SupportsFeature(
                     ManagementRuntimeCapabilities.DeviceAuthorization),
                 "O runtime não habilita Device Authorization."),
            _ => (false, "Perfil desconhecido para este runtime."),
        };

        return profile with
        {
            IsAvailable = available,
            UnavailableReason = available ? null : reason,
        };
    }

    private static void EnsureProfileAvailable(
        ManagementClientProfile profile,
        IdentityRuntimeCapabilitySnapshot capabilities)
    {
        var resolved = WithAvailability(profile, capabilities);
        if (!resolved.IsAvailable)
        {
            throw new ManagementValidationException(
                "client_profile_unavailable",
                resolved.UnavailableReason ??
                    "Este perfil não está habilitado no runtime atual.",
                "profile");
        }
    }

    private static ManagementClientDraftValues DefaultsFor(string profile) => profile switch
    {
        ManagementClientProfiles.Web => new()
        {
            ClientType = "confidential",
            AuthorizationCode = true,
            RefreshToken = true,
            RequirePar = true,
            Scopes = ["openid", "profile", "offline_access"],
        },
        ManagementClientProfiles.Spa => new()
        {
            ClientType = "public",
            AuthorizationCode = true,
            RequirePar = true,
            Scopes = ["openid", "profile"],
        },
        ManagementClientProfiles.Native => new()
        {
            ClientType = "public",
            AuthorizationCode = true,
            RefreshToken = true,
            Scopes = ["openid", "profile", "offline_access"],
        },
        ManagementClientProfiles.Service => new()
        {
            ClientType = "confidential",
            ClientCredentials = true,
        },
        ManagementClientProfiles.Device => new()
        {
            ClientType = "public",
            DeviceCode = true,
            RefreshToken = true,
            Scopes = ["openid", "profile", "offline_access"],
        },
        _ => new()
        {
            ClientType = "public",
            AuthorizationCode = true,
            Scopes = ["openid", "profile"],
        },
    };

    private static void NormalizeValues(ManagementClientDraftValues values)
    {
        values.ClientId = values.ClientId.Trim();
        values.DisplayName = values.DisplayName.Trim();
        values.ClientType = string.Equals(values.ClientType, "confidential", StringComparison.OrdinalIgnoreCase)
            ? "confidential"
            : "public";
        values.ConsentType = string.IsNullOrWhiteSpace(values.ConsentType)
            ? "explicit"
            : values.ConsentType.Trim().ToLowerInvariant();
        values.Scopes = NormalizeList(values.Scopes);
        values.RedirectUris = NormalizeList(values.RedirectUris);
        values.PostLogoutRedirectUris = NormalizeList(values.PostLogoutRedirectUris);
        values.FrontchannelLogoutUri = NullIfWhiteSpace(values.FrontchannelLogoutUri);
        values.BackchannelLogoutUri = NullIfWhiteSpace(values.BackchannelLogoutUri);
    }

    private static List<string> NormalizeList(IEnumerable<string>? values) =>
        (values ?? [])
            .Select(value => value?.Trim())
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value!)
            .Distinct(StringComparer.Ordinal)
            .ToList();

    private static string NormalizeStep(string? value) =>
        ManagementClientDraftSteps.All.FirstOrDefault(step => string.Equals(
            step,
            value,
            StringComparison.OrdinalIgnoreCase))
        ?? ManagementClientDraftSteps.Identity;

    private static int GrantCount(ManagementClientDraftValues values) =>
        (values.AuthorizationCode ? 1 : 0)
        + (values.RefreshToken ? 1 : 0)
        + (values.ClientCredentials ? 1 : 0)
        + (values.DeviceCode ? 1 : 0);

    private static bool IsUserIdentityScope(string scope) =>
        scope is "openid" or "profile" or "email" or "phone" or "address" or "roles";

    private static void AddRequired(
        ICollection<ClientValidationIssue> issues,
        string? value,
        string code,
        string step,
        string field,
        string message)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            AddError(issues, code, step, field, message);
        }
    }

    private static void AddError(
        ICollection<ClientValidationIssue> issues,
        string code,
        string step,
        string field,
        string message) =>
        issues.Add(new ClientValidationIssue(
            code,
            step,
            field,
            ClientValidationSeverity.Error,
            message));

    private static void EnsureActive(ManagementClientDraftRecord row)
    {
        if (!string.Equals(row.Status, ActiveStatus, StringComparison.Ordinal))
        {
            throw new ManagementConflictException(
                "client_draft_completed",
                "Este rascunho já foi concluído.");
        }
    }

    private static string NewVersion() => Guid.NewGuid().ToString("N");

    private static string? NullIfWhiteSpace(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static DateTimeOffset AsUtcOffset(DateTime value) =>
        new(DateTime.SpecifyKind(value, DateTimeKind.Utc));
}
