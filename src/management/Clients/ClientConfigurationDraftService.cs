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

internal sealed partial class ClientConfigurationDraftService(
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

}
