using System.Data;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Provisioning;
using System.Globalization;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Clients;

internal sealed partial class ClientManagementService
{
    public async Task<ManagementClientDetail> CreateAsync(
        CreateManagementClientCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        var clientId = command.ClientId?.Trim() ?? string.Empty;
        var resource = new ManagementResource(
            ManagementResourceTypes.Client,
            clientId);
        var decision = await guard.DemandAsync(
            context,
            ManagementCapabilities.ClientsCreate,
            resource,
            cancellationToken,
            auditDenial: true);

        try
        {
            ClientCredentialPolicy.ValidateClientId(clientId);
            var redirectUris = ClientUriPolicy.ValidateRedirectUris(
                command.RedirectUris,
                "redirectUris");
            var postLogoutRedirectUris = ClientUriPolicy.ValidateRedirectUris(
                command.PostLogoutRedirectUris,
                "postLogoutRedirectUris");
            var nativeReturnUris = ClientUriPolicy.ValidateNativeReturnUris(
                command.NativeReturnUris,
                "nativeReturnUris");
            var deviceCloseFallbackUrl = ClientUriPolicy.ValidateDeviceCloseFallback(
                command.DeviceCloseFallbackUrl,
                "deviceCloseFallbackUrl");
            var frontchannelLogoutUri = ClientUriPolicy.ValidateLogoutUri(
                command.FrontchannelLogoutUri,
                "frontchannelLogoutUri");
            var backchannelLogoutUri = ClientUriPolicy.ValidateLogoutUri(
                command.BackchannelLogoutUri,
                "backchannelLogoutUri");
            var jwksUri = ClientJwksPolicy.ValidateJwksUri(command.JwksUri);
            var publicJwks = ClientJwksPolicy.ValidatePublicJwks(command.JwksJson);
            ClientTokenLifetimePolicy.ValidateTokenLifetimes(
                command.AccessTokenLifetimeMinutes,
                command.IdentityTokenLifetimeMinutes,
                command.RefreshTokenLifetimeDays);

            if (command.FrontchannelLogoutSessionRequired &&
                frontchannelLogoutUri is null)
            {
                throw new ManagementValidationException(
                    "frontchannel_logout_uri_required",
                    "frontchannelLogoutUri is required when session-specific front-channel logout is requested.",
                    "frontchannelLogoutUri");
            }

            if (command.BackchannelLogoutSessionRequired &&
                backchannelLogoutUri is null)
            {
                throw new ManagementValidationException(
                    "backchannel_logout_uri_required",
                    "backchannelLogoutUri is required when session-specific back-channel logout is requested.",
                    "backchannelLogoutUri");
            }

            if (frontchannelLogoutUri is not null &&
                !redirectUris.Any(redirect => ClientUriPolicy.SameOrigin(redirect, frontchannelLogoutUri)))
            {
                throw new ManagementValidationException(
                    "frontchannel_logout_origin_mismatch",
                    "frontchannelLogoutUri must use the same scheme, host and port as a redirect URI.",
                    "frontchannelLogoutUri");
            }
            var consentType = ClientPermissionPolicy.NormalizeConsentType(command.ConsentType)
                ?? OpenIddictConstants.ConsentTypes.Explicit;

            if (await applications.FindByClientIdAsync(
                    clientId,
                    cancellationToken) is not null)
            {
                await guard.TryWriteAuditAsync(
                    context,
                    ManagementCapabilities.ClientsCreate,
                    resource,
                    decision,
                    "conflict",
                    "client_already_exists",
                    cancellationToken);
                throw new ManagementConflictException(
                    "client_already_exists",
                    $"Client '{clientId}' already exists.");
            }

            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                ClientSecret = string.IsNullOrEmpty(command.ClientSecret)
                    ? null
                    : command.ClientSecret,
                DisplayName = NullIfWhiteSpace(command.DisplayName),
                ConsentType = consentType,
                ClientType = string.IsNullOrEmpty(command.ClientSecret)
                    && publicJwks is null
                    ? OpenIddictConstants.ClientTypes.Public
                    : OpenIddictConstants.ClientTypes.Confidential,
                JsonWebKeySet = publicJwks,
            };

            var grantTypes = ClientPermissionPolicy.NormalizeGrantTypes(command.GrantTypes);

            // Finding #8: reject insecure grant types (password, implicit) for
            // new client registrations. They are outside the current OAuth 2.1
            // draft baseline, but remain runtime-compatible for existing clients
            // when the explicit legacy feature flag is enabled. The provisioning
            // path already enforces this policy; the management API must not be
            // a weaker parallel path.
            var insecureGrants = grantTypes.Where(g =>
                g == OpenIddictConstants.Permissions.GrantTypes.Password
                || g == OpenIddictConstants.Permissions.GrantTypes.Implicit);
            if (insecureGrants.Any())
            {
                throw new ManagementValidationException(
                    "insecure_grant_type",
                    "Password and implicit grant types are outside the current " +
                    "OAuth 2.1 draft baseline and cannot be assigned to new " +
                    "clients by policy.",
                    "grantTypes");
            }

            foreach (var grantType in grantTypes)
            {
                descriptor.Permissions.Add(grantType);
            }
            ClientPermissionPolicy.AddDerivedProtocolPermissions(descriptor, grantTypes);

            var normalizedScopes = ClientPermissionPolicy.NormalizeScopes(command.Scopes);
            var definitionValidation = clientDefinitionValidator.Validate(
                new ClientDefinitionRequest(
                    ClientDefinitionSource.Management,
                    clientId,
                    string.IsNullOrEmpty(command.ClientSecret)
                        && publicJwks is null
                        ? OpenIddictConstants.ClientTypes.Public
                        : OpenIddictConstants.ClientTypes.Confidential,
                    grantTypes,
                    normalizedScopes,
                    redirectUris,
                    RequirePkce: clientDefinitionValidator
                        .RequiresProofKeyForCodeExchange(grantTypes),
                    HasClientSecret: !string.IsNullOrEmpty(command.ClientSecret)));
            if (!definitionValidation.IsValid)
            {
                var issue = definitionValidation.Issues[0];
                throw new ManagementValidationException(
                    issue.Code,
                    issue.Message,
                    issue.Field);
            }

            // H2/M3 fix (eval): reject API-protection scopes (management, SCIM,
            // custom privileged APIs) at the client-create boundary. Without
            // this, an operator with identity.clients.create could mint a
            // client_credentials client carrying identity.management and
            // defeat the transport policy. Reserved scopes are provisioned via
            // bootstrap, not the runtime CRUD path.
            var requestedScopeNames = normalizedScopes
                .Select(s => s.StartsWith(
                    OpenIddictConstants.Permissions.Prefixes.Scope,
                    StringComparison.Ordinal)
                    ? s[OpenIddictConstants.Permissions.Prefixes.Scope.Length..]
                    : s);
            var forbidden = requestedScopeNames.FirstOrDefault(reservedScopePolicy.IsReserved);
            if (forbidden is not null)
            {
                throw new ManagementValidationException(
                    "scope_reserved",
                    $"O scope '{forbidden}' protege uma superfície administrativa e não pode ser atribuído a um cliente pela API de gerenciamento.",
                    "scopes");
            }

            foreach (var scope in normalizedScopes)
            {
                descriptor.Permissions.Add(scope);
            }

            foreach (var redirectUri in redirectUris)
            {
                descriptor.RedirectUris.Add(redirectUri);
            }

            foreach (var postLogoutRedirectUri in postLogoutRedirectUris)
            {
                descriptor.PostLogoutRedirectUris.Add(postLogoutRedirectUri);
            }

            SetNativeReturnUris(descriptor.Properties, nativeReturnUris);
            SetDeviceCloseFallback(descriptor.Properties, deviceCloseFallbackUrl);

            AddLogoutSettings(
                descriptor.Settings,
                frontchannelLogoutUri,
                command.FrontchannelLogoutSessionRequired,
                backchannelLogoutUri,
                command.BackchannelLogoutSessionRequired);
            if (jwksUri is not null)
            {
                descriptor.Settings["jwks_uri"] = jwksUri.AbsoluteUri;
            }
            ClientTokenLifetimePolicy.ApplyTokenLifetimes(
                descriptor,
                command.AccessTokenLifetimeMinutes,
                command.IdentityTokenLifetimeMinutes,
                command.RefreshTokenLifetimeDays);

            if (clientDefinitionValidator.RequiresProofKeyForCodeExchange(
                    grantTypes))
            {
                descriptor.Requirements.Add(
                    OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange);
            }

            if (command.RequirePar)
            {
                descriptor.Permissions.Add(
                    OpenIddictConstants.Permissions.Endpoints.PushedAuthorization);
                descriptor.Requirements.Add(
                    OpenIddictConstants.Requirements.Features.PushedAuthorizationRequests);
            }

            await using var transaction = await database.Database
                .BeginTransactionAsync(cancellationToken);

            var application = await applications.CreateAsync(
                descriptor,
                cancellationToken);
            var detail = await ToDetailAsync(application, cancellationToken);

            database.ManagementAuditEvents.Add(ManagementAuditEventFactory.Create(
                context,
                ManagementCapabilities.ClientsCreate,
                new ManagementResource(
                    ManagementResourceTypes.Client,
                    detail.ClientId),
                decision,
                "succeeded"));
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            return detail;
        }
        catch (ManagementValidationException exception)
        {
            await guard.TryWriteAuditAsync(
                context,
                ManagementCapabilities.ClientsCreate,
                resource,
                decision,
                "rejected",
                exception.ReasonCode,
                cancellationToken);
            throw;
        }
        catch (ManagementConflictException exception)
        {
            await guard.TryWriteAuditAsync(
                context,
                ManagementCapabilities.ClientsCreate,
                resource,
                decision,
                "rejected",
                exception.ReasonCode,
                cancellationToken);
            throw;
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "OAuth client creation failed. ClientId={ClientId} CorrelationId={CorrelationId}",
                clientId,
                context.CorrelationId);
            throw;
        }
    }

    public async Task<ManagementClientDetail> UpdateAsync(
        UpdateManagementClientCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        var clientId = command.ClientId?.Trim() ?? string.Empty;
        var resource = new ManagementResource(
            ManagementResourceTypes.Client,
            clientId);
        var decision = await guard.DemandAsync(
            context,
            ManagementCapabilities.ClientsUpdate,
            resource,
            cancellationToken,
            auditDenial: true);

        var application = await applications.FindByClientIdAsync(
            clientId,
            cancellationToken);
        if (application is null)
        {
            await guard.TryWriteAuditAsync(
                context,
                ManagementCapabilities.ClientsUpdate,
                resource,
                decision,
                "not-found",
                "client_not_found",
                cancellationToken);
            throw new ManagementNotFoundException(
                "client_not_found",
                $"Client '{clientId}' was not found.");
        }

        try
        {
            if (application is not OpenIddictEntityFrameworkCoreApplication entity)
            {
                throw new InvalidOperationException(
                    "The configured OpenIddict application entity is unsupported.");
            }

            if (string.IsNullOrWhiteSpace(command.ExpectedVersion))
            {
                throw new ManagementValidationException(
                    "client_version_required",
                    "Recarregue a aplicação antes de salvar para confirmar a versão atual.",
                    "expectedVersion");
            }

            if (!string.Equals(
                    command.ExpectedVersion,
                    entity.ConcurrencyToken,
                    StringComparison.Ordinal))
            {
                throw new ManagementConflictException(
                    "client_changed",
                    "O cliente foi alterado por outra operação. Recarregue os dados antes de salvar.");
            }

            var descriptor = new OpenIddictApplicationDescriptor();
            await applications.PopulateAsync(
                descriptor,
                application,
                cancellationToken);

            if (descriptor.Properties.ContainsKey(
                    OpenIddictManifestProvisioner.SchemaVersionProperty))
            {
                throw new ManagementConflictException(
                    "client_manifest_managed",
                    "Este cliente é gerenciado por manifesto declarativo. Altere o manifesto e aplique o provisionamento.");
            }

            var redirectUris = ClientUriPolicy.ValidateRedirectUris(
                command.RedirectUris,
                "redirectUris");
            var postLogoutRedirectUris = ClientUriPolicy.ValidateRedirectUris(
                command.PostLogoutRedirectUris,
                "postLogoutRedirectUris");
            var nativeReturnUris = ClientUriPolicy.ValidateNativeReturnUris(
                command.NativeReturnUris,
                "nativeReturnUris");
            var deviceCloseFallbackUrl = ClientUriPolicy.ValidateDeviceCloseFallback(
                command.DeviceCloseFallbackUrl,
                "deviceCloseFallbackUrl");
            var frontchannelLogoutUri = ClientUriPolicy.ValidateLogoutUri(
                command.FrontchannelLogoutUri,
                "frontchannelLogoutUri");
            var backchannelLogoutUri = ClientUriPolicy.ValidateLogoutUri(
                command.BackchannelLogoutUri,
                "backchannelLogoutUri");
            var jwksUri = ClientJwksPolicy.ValidateJwksUri(command.JwksUri);
            var publicJwks = command.JwksJson is null
                ? null
                : ClientJwksPolicy.ValidatePublicJwks(command.JwksJson);
            ClientTokenLifetimePolicy.ValidateTokenLifetimes(
                command.AccessTokenLifetimeMinutes,
                command.IdentityTokenLifetimeMinutes,
                command.RefreshTokenLifetimeDays);

            ClientUriPolicy.ValidateLogoutConfiguration(
                redirectUris,
                frontchannelLogoutUri,
                command.FrontchannelLogoutSessionRequired,
                backchannelLogoutUri,
                command.BackchannelLogoutSessionRequired);

            var consentType = ClientPermissionPolicy.NormalizeConsentType(command.ConsentType)
                ?? OpenIddictConstants.ConsentTypes.Explicit;
            var grantTypes = ClientPermissionPolicy.NormalizeGrantTypes(command.GrantTypes);
            if (grantTypes.Any(grant =>
                    grant == OpenIddictConstants.Permissions.GrantTypes.Password ||
                    grant == OpenIddictConstants.Permissions.GrantTypes.Implicit))
            {
                throw new ManagementValidationException(
                    "insecure_grant_type",
                    "Password and implicit grant types are outside the current " +
                    "OAuth 2.1 draft baseline and cannot be assigned to new " +
                    "clients by policy.",
                    "grantTypes");
            }

            var normalizedScopes = ClientPermissionPolicy.NormalizeScopes(command.Scopes);
            var clientType = descriptor.ClientType
                ?? OpenIddictConstants.ClientTypes.Public;
            var definitionValidation = clientDefinitionValidator.Validate(
                new ClientDefinitionRequest(
                    ClientDefinitionSource.Management,
                    clientId,
                    clientType,
                    grantTypes,
                    normalizedScopes,
                    redirectUris,
                    RequirePkce: clientDefinitionValidator
                        .RequiresProofKeyForCodeExchange(grantTypes),
                    HasClientSecret: clientType == OpenIddictConstants.ClientTypes.Confidential));
            if (!definitionValidation.IsValid)
            {
                var issue = definitionValidation.Issues[0];
                throw new ManagementValidationException(
                    issue.Code,
                    issue.Message,
                    issue.Field);
            }

            var forbidden = normalizedScopes
                .Select(scope => scope.StartsWith(
                    OpenIddictConstants.Permissions.Prefixes.Scope,
                    StringComparison.Ordinal)
                    ? scope[OpenIddictConstants.Permissions.Prefixes.Scope.Length..]
                    : scope)
                .FirstOrDefault(reservedScopePolicy.IsReserved);
            if (forbidden is not null)
            {
                throw new ManagementValidationException(
                    "scope_reserved",
                    $"O scope '{forbidden}' protege uma superfície administrativa e não pode ser atribuído a um cliente pela API de gerenciamento.",
                    "scopes");
            }

            descriptor.DisplayName = NullIfWhiteSpace(command.DisplayName);
            descriptor.ConsentType = consentType;
            ClientPermissionPolicy.RemoveManagedPermissions(descriptor);
            descriptor.Requirements.Remove(
                OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange);
            descriptor.Requirements.Remove(
                OpenIddictConstants.Requirements.Features.PushedAuthorizationRequests);
            descriptor.RedirectUris.Clear();
            descriptor.PostLogoutRedirectUris.Clear();
            foreach (var grantType in grantTypes)
            {
                descriptor.Permissions.Add(grantType);
            }
            ClientPermissionPolicy.AddDerivedProtocolPermissions(descriptor, grantTypes);
            foreach (var scope in normalizedScopes)
            {
                descriptor.Permissions.Add(scope);
            }
            foreach (var uri in redirectUris)
            {
                descriptor.RedirectUris.Add(uri);
            }
            foreach (var uri in postLogoutRedirectUris)
            {
                descriptor.PostLogoutRedirectUris.Add(uri);
            }

            // Null means the caller did not manage this metadata, so an older
            // API/UI client cannot silently unregister a callback it never
            // knew about; an explicit empty list clears it.
            if (command.NativeReturnUris is not null)
            {
                SetNativeReturnUris(descriptor.Properties, nativeReturnUris);
            }

            // Same null/empty contract as the native callbacks above: null
            // leaves the registration untouched; an explicit empty string
            // clears it.
            if (command.DeviceCloseFallbackUrl is not null)
            {
                SetDeviceCloseFallback(descriptor.Properties, deviceCloseFallbackUrl);
            }

            descriptor.Settings.Remove("frontchannel_logout_uri");
            descriptor.Settings.Remove("frontchannel_logout_session_required");
            descriptor.Settings.Remove("backchannel_logout_uri");
            descriptor.Settings.Remove("backchannel_logout_session_required");
            AddLogoutSettings(
                descriptor.Settings,
                frontchannelLogoutUri,
                command.FrontchannelLogoutSessionRequired,
                backchannelLogoutUri,
                command.BackchannelLogoutSessionRequired);
            // Null means the caller did not manage this metadata (keeps older
            // API/UI clients source-compatible). An explicit empty value
            // removes it; a non-empty value replaces it after validation.
            if (command.JwksUri is not null)
            {
                descriptor.Settings.Remove("jwks_uri");
                if (jwksUri is not null)
                {
                    descriptor.Settings["jwks_uri"] = jwksUri.AbsoluteUri;
                }
            }
            // Null means “not managed by this caller”; an explicit empty
            // value removes the embedded public key set.
            if (command.JwksJson is not null)
            {
                descriptor.JsonWebKeySet =
                    ClientTlsCertificateCredential.MergePrivateKeyJwtKeys(
                        publicJwks,
                        entity.JsonWebKeySet);
            }
            ClientTokenLifetimePolicy.ApplyTokenLifetimes(
                descriptor,
                command.AccessTokenLifetimeMinutes,
                command.IdentityTokenLifetimeMinutes,
                command.RefreshTokenLifetimeDays,
                command.ClearAccessTokenLifetime,
                command.ClearIdentityTokenLifetime,
                command.ClearRefreshTokenLifetime);

            if (clientDefinitionValidator.RequiresProofKeyForCodeExchange(
                    grantTypes))
            {
                descriptor.Requirements.Add(
                    OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange);
            }
            if (command.RequirePar)
            {
                descriptor.Permissions.Add(
                    OpenIddictConstants.Permissions.Endpoints.PushedAuthorization);
                descriptor.Requirements.Add(
                    OpenIddictConstants.Requirements.Features.PushedAuthorizationRequests);
            }

            await using var transaction = await database.Database
                .BeginTransactionAsync(cancellationToken);
            await applications.UpdateAsync(
                application,
                descriptor,
                cancellationToken);
            var detail = await ToDetailAsync(application, cancellationToken);
            database.ManagementAuditEvents.Add(ManagementAuditEventFactory.Create(
                context,
                ManagementCapabilities.ClientsUpdate,
                resource,
                decision,
                "succeeded"));
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return detail;
        }
        catch (ManagementValidationException exception)
        {
            await guard.TryWriteAuditAsync(
                context,
                ManagementCapabilities.ClientsUpdate,
                resource,
                decision,
                "rejected",
                exception.ReasonCode,
                cancellationToken);
            throw;
        }
        catch (ManagementConflictException exception)
        {
            await guard.TryWriteAuditAsync(
                context,
                ManagementCapabilities.ClientsUpdate,
                resource,
                decision,
                "rejected",
                exception.ReasonCode,
                cancellationToken);
            throw;
        }
        catch (DbUpdateConcurrencyException exception)
        {
            logger.LogWarning(
                exception,
                "OAuth client update lost a concurrency race. ClientId={ClientId} CorrelationId={CorrelationId}",
                clientId,
                context.CorrelationId);
            throw new ManagementConflictException(
                "client_changed",
                "O cliente foi alterado por outra operação. Recarregue os dados antes de salvar.");
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "OAuth client update failed. ClientId={ClientId} CorrelationId={CorrelationId}",
                clientId,
                context.CorrelationId);
            throw;
        }
    }

    public async Task DeleteAsync(
        string clientId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);

        var resource = new ManagementResource(
            ManagementResourceTypes.Client,
            clientId);
        var decision = await guard.DemandAsync(
            context,
            ManagementCapabilities.ClientsDelete,
            resource,
            cancellationToken,
            auditDenial: true);

        var application = await applications.FindByClientIdAsync(
            clientId,
            cancellationToken);
        if (application is null)
        {
            await guard.TryWriteAuditAsync(
                context,
                ManagementCapabilities.ClientsDelete,
                resource,
                decision,
                "not-found",
                "client_not_found",
                cancellationToken);
            throw new ManagementNotFoundException(
                "client_not_found",
                $"Client '{clientId}' was not found.");
        }

        try
        {
            await using var transaction = await database.Database
                .BeginTransactionAsync(cancellationToken);

            if (application is not OpenIddictEntityFrameworkCoreApplication entity)
            {
                throw new InvalidOperationException(
                    "The configured OpenIddict application entity is unsupported.");
            }

            var applicationId = entity.Id;
            var canonicalClientId = entity.ClientId ?? clientId;
            // OpenIddict's EF bulk-delete query joins each dependent table
            // back to itself through the application navigation. MariaDB
            // rejects that shape with error 1093, so delete by the mapped
            // shadow foreign keys in dependency order and invalidate the
            // same application cache entry the manager would invalidate.
            await database.Set<OpenIddictEntityFrameworkCoreToken>()
                .Where(token =>
                    EF.Property<string?>(token, "ApplicationId") ==
                    applicationId)
                .ExecuteDeleteAsync(cancellationToken);
            await database.Set<OpenIddictEntityFrameworkCoreAuthorization>()
                .Where(authorization =>
                    EF.Property<string?>(authorization, "ApplicationId") ==
                    applicationId)
                .ExecuteDeleteAsync(cancellationToken);
            await database.OAuthClientCredentials
                .Where(credential => credential.ClientId == canonicalClientId)
                .ExecuteDeleteAsync(cancellationToken);
            var deleted = await database
                .Set<OpenIddictEntityFrameworkCoreApplication>()
                .Where(candidate =>
                    candidate.Id == applicationId
                    && candidate.ConcurrencyToken == entity.ConcurrencyToken)
                .ExecuteDeleteAsync(cancellationToken);
            if (deleted != 1)
            {
                throw new DbUpdateConcurrencyException(
                    $"Client '{clientId}' changed before it could be deleted.");
            }

            await applicationCache.RemoveAsync(entity, cancellationToken);
            database.ManagementAuditEvents.Add(ManagementAuditEventFactory.Create(
                context,
                ManagementCapabilities.ClientsDelete,
                resource,
                decision,
                "succeeded"));
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "OAuth client deletion failed. ClientId={ClientId} CorrelationId={CorrelationId}",
                clientId,
                context.CorrelationId);
            throw;
        }
    }

    public async Task<RotateManagementClientSecretResult> RotateSecretAsync(
        RotateManagementClientSecretCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        var clientId = command.ClientId?.Trim() ?? string.Empty;
        var resource = new ManagementResource(
            ManagementResourceTypes.Client,
            clientId);
        var decision = await guard.DemandAsync(
            context,
            ManagementCapabilities.ClientsUpdate,
            resource,
            cancellationToken,
            auditDenial: true);

        var application = await applications.FindByClientIdAsync(
            clientId,
            cancellationToken);
        if (application is null)
        {
            await guard.TryWriteAuditAsync(
                context,
                ManagementCapabilities.ClientsUpdate,
                resource,
                decision,
                "not-found",
                "client_not_found",
                cancellationToken);
            throw new ManagementNotFoundException(
                "client_not_found",
                $"Client '{clientId}' was not found.");
        }

        try
        {
            if (application is not OpenIddictEntityFrameworkCoreApplication entity)
            {
                throw new InvalidOperationException(
                    "The configured OpenIddict application entity is unsupported.");
            }

            if (string.IsNullOrWhiteSpace(command.ExpectedVersion))
            {
                throw new ManagementValidationException(
                    "client_version_required",
                    "Recarregue a aplicação antes de substituir a credencial.",
                    "expectedVersion");
            }

            if (!string.Equals(
                    command.ExpectedVersion,
                    entity.ConcurrencyToken,
                    StringComparison.Ordinal))
            {
                throw new ManagementConflictException(
                    "client_changed",
                    "O cliente foi alterado por outra operação. Recarregue os dados antes de substituir a credencial.");
            }

            var descriptor = new OpenIddictApplicationDescriptor();
            await applications.PopulateAsync(
                descriptor,
                application,
                cancellationToken);
            if (descriptor.Properties.ContainsKey(
                    OpenIddictManifestProvisioner.SchemaVersionProperty))
            {
                throw new ManagementConflictException(
                    "client_manifest_managed",
                    "Este cliente é gerenciado por manifesto declarativo. Altere a referência do segredo no manifesto e aplique o provisionamento.");
            }

            var generated = command.Generate;
            var oneTimeSecret = generated
                ? WebEncoders.Base64UrlEncode(
                    RandomNumberGenerator.GetBytes(ClientCredentialPolicy.GeneratedClientSecretBytes))
                : ClientCredentialPolicy.ValidateReplacementClientSecret(command.ClientSecret);

            await using var transaction = await database.Database
                .BeginTransactionAsync(cancellationToken);

            // OpenIddict accepts a shared secret only for confidential clients.
            // Mutating the tracked entity here lets the manager validate and
            // persist the type transition together with the newly hashed secret.
            entity.ClientType = OpenIddictConstants.ClientTypes.Confidential;
            await applications.UpdateAsync(
                application,
                oneTimeSecret,
                cancellationToken);

            var detail = await ToDetailAsync(application, cancellationToken);
            database.ManagementAuditEvents.Add(ManagementAuditEventFactory.Create(
                context,
                ManagementCapabilities.ClientsUpdate,
                resource,
                decision,
                "succeeded",
                "client_secret_rotated"));
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            return new RotateManagementClientSecretResult(
                detail,
                oneTimeSecret,
                generated);
        }
        catch (ManagementValidationException exception)
        {
            await guard.TryWriteAuditAsync(
                context,
                ManagementCapabilities.ClientsUpdate,
                resource,
                decision,
                "rejected",
                exception.ReasonCode,
                cancellationToken);
            throw;
        }
        catch (ManagementConflictException exception)
        {
            await guard.TryWriteAuditAsync(
                context,
                ManagementCapabilities.ClientsUpdate,
                resource,
                decision,
                "rejected",
                exception.ReasonCode,
                cancellationToken);
            throw;
        }
        catch (DbUpdateConcurrencyException exception)
        {
            logger.LogWarning(
                exception,
                "OAuth client secret rotation lost a concurrency race. ClientId={ClientId} CorrelationId={CorrelationId}",
                clientId,
                context.CorrelationId);
            throw new ManagementConflictException(
                "client_changed",
                "O cliente foi alterado por outra operação. Recarregue os dados antes de substituir a credencial.");
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "OAuth client secret rotation failed. ClientId={ClientId} CorrelationId={CorrelationId}",
                clientId,
                context.CorrelationId);
            throw;
        }
    }
}
