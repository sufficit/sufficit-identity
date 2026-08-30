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
