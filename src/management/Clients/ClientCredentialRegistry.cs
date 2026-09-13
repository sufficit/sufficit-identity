using System.Data;
using System.Security.Cryptography;
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
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Provisioning;

namespace Sufficit.Identity.Management.Clients;

/// <summary>
/// The credentials a client authenticates with: shared secrets and mTLS
/// client certificates, plus the combined view of both.
/// </summary>
/// <remarks>
/// Split out of <c>ClientManagementService</c>, which was doing four separate
/// jobs — client CRUD, search, this registry, and the certificate registry —
/// in one 3,200-line type. Credential lifecycle is its own concern: it has a
/// different cadence from editing a client (secrets rotate on their own
/// schedule), a different failure mode (locking a client out of its own
/// tokens), and its own invariants, such as refusing to touch a client whose
/// credentials are owned by a declarative manifest.
/// <para>
/// Behavior is unchanged. Authorization and denial auditing go through the
/// shared <see cref="ManagementOperationGuard"/> with
/// <c>auditDenial: true</c>, exactly as this code did when it lived in the
/// service.
/// </para>
/// </remarks>
internal sealed class ClientCredentialRegistry(
    IOpenIddictApplicationManager applications,
    AppDbContext database,
    IClientCredentialSecretHasher credentialSecretHasher,
    IConfiguration configuration,
    ManagementOperationGuard guard,
    ILogger<ClientCredentialRegistry> logger)
{
    public async Task<ManagementClientCredentialsOverview> GetCredentialsAsync(
        string clientId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        clientId = clientId.Trim();

        await guard.DemandAsync(
            context,
            ManagementCapabilities.ClientsRead,
            new ManagementResource(ManagementResourceTypes.Client, clientId),
            cancellationToken,
            auditDenial: true);

        var application = await applications.FindByClientIdAsync(
            clientId,
            cancellationToken);
        if (application is not OpenIddictEntityFrameworkCoreApplication entity)
        {
            throw new ManagementNotFoundException(
                "client_not_found",
                $"Client '{clientId}' was not found.");
        }

        return await BuildCredentialsOverviewAsync(entity, cancellationToken);
    }

    public async Task<CreateManagementClientCredentialResult> CreateCredentialAsync(
        CreateManagementClientCredentialCommand command,
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
        if (application is not OpenIddictEntityFrameworkCoreApplication entity)
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

        // Always persist and query against the canonical client_id returned by
        // the application store. Some legacy MariaDB deployments still use a
        // case-insensitive collation for applications.client_id, while this
        // credential registry is deliberately case-sensitive.
        clientId = entity.ClientId ?? clientId;

        try
        {
            ClientCredentialPolicy.EnsureExpectedClientVersion(command.ExpectedClientVersion, entity);
            await EnsureClientIsManuallyManagedAsync(application, cancellationToken);

            var label = ClientCredentialPolicy.ValidateCredentialLabel(command.Label);
            var generated = command.Generate;
            var oneTimeSecret = generated
                ? WebEncoders.Base64UrlEncode(
                    RandomNumberGenerator.GetBytes(ClientCredentialPolicy.GeneratedClientSecretBytes))
                : ClientCredentialPolicy.ValidateReplacementClientSecret(command.ClientSecret);
            var now = DateTime.UtcNow;
            var notBeforeUtc = command.NotBeforeUtc?.UtcDateTime;
            var expiresAtUtc = command.ExpiresAtUtc?.UtcDateTime;
            ClientCredentialPolicy.ValidateCredentialLifetime(now, notBeforeUtc, expiresAtUtc);

            await using var transaction = await database.Database
                .BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);

            if (await applications.ValidateClientSecretAsync(
                    application,
                    oneTimeSecret,
                    cancellationToken))
            {
                throw new ManagementConflictException(
                    "client_credential_duplicate",
                    "The provided credential is already active for this application.");
            }

            var wasPublic = string.Equals(
                entity.ClientType,
                OpenIddictConstants.ClientTypes.Public,
                StringComparison.Ordinal);
            // Preserve the legacy primary-secret path when no validity window
            // was requested. A dated first credential belongs in the registry:
            // copying it into ClientSecret would bypass expiration/revocation.
            var createdAsPrimary = wasPublic
                && notBeforeUtc is null && expiresAtUtc is null;
            if (createdAsPrimary)
            {
                entity.ClientType = OpenIddictConstants.ClientTypes.Confidential;
                await applications.UpdateAsync(
                    application,
                    oneTimeSecret,
                    cancellationToken);
            }
            else
            {
                var activeCount = await database.OAuthClientCredentials
                    .Where(credential =>
                        credential.ClientId == clientId
                        && credential.Kind == OAuthClientCredentialKinds.SharedSecret
                        && credential.RevokedAtUtc == null
                        && (credential.ExpiresAtUtc == null || credential.ExpiresAtUtc > now))
                    .CountAsync(cancellationToken);
                if (activeCount >= ClientCredentialPolicy.MaximumActiveAdditionalSharedSecrets)
                {
                    throw new ManagementConflictException(
                        "client_credential_limit_reached",
                        $"Each application can keep up to {ClientCredentialPolicy.MaximumActiveAdditionalSharedSecrets} additional active shared credentials.");
                }

                var duplicateLabel = await database.OAuthClientCredentials
                    .AnyAsync(credential =>
                        credential.ClientId == clientId
                        && credential.RevokedAtUtc == null
                        && credential.Label == label,
                        cancellationToken);
                if (duplicateLabel)
                {
                    throw new ManagementConflictException(
                        "client_credential_label_duplicate",
                        "An active credential with that name already exists.");
                }

                var secretHash = credentialSecretHasher.Hash(oneTimeSecret);
                database.OAuthClientCredentials.Add(new OAuthClientCredential
                {
                    Id = Guid.NewGuid(),
                    ClientId = clientId,
                    Kind = OAuthClientCredentialKinds.SharedSecret,
                    Label = label,
                    SecretHash = secretHash,
                    SecretHint = ClientCredentialPolicy.CreateSecretFingerprint(secretHash),
                    CreatedAtUtc = now,
                    NotBeforeUtc = notBeforeUtc,
                    ExpiresAtUtc = expiresAtUtc,
                    ConcurrencyToken = ClientCredentialPolicy.NewConcurrencyToken(),
                });
            }

            database.ManagementAuditEvents.Add(ManagementAuditEventFactory.Create(
                context,
                ManagementCapabilities.ClientsUpdate,
                resource,
                decision,
                "succeeded",
                createdAsPrimary
                    ? "client_primary_credential_created"
                    : "client_credential_created"));
            await database.SaveChangesAsync(cancellationToken);
            if (wasPublic && !createdAsPrimary)
            {
                // Persist the registry entry inside this transaction before
                // the adapter validates the confidential application's credential.
                entity.ClientType = OpenIddictConstants.ClientTypes.Confidential;
                await applications.UpdateAsync(application, cancellationToken);
            }
            var overview = await BuildCredentialsOverviewAsync(
                entity,
                cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            return new CreateManagementClientCredentialResult(
                overview,
                oneTimeSecret,
                generated,
                createdAsPrimary);
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
        catch (DbUpdateException exception)
        {
            logger.LogWarning(
                exception,
                "OAuth client credential creation lost a persistence race. ClientId={ClientId} CorrelationId={CorrelationId}",
                clientId,
                context.CorrelationId);
            throw new ManagementConflictException(
                "client_credential_changed",
                "The credentials were changed by another operation. Reload the data.");
        }
    }

    public async Task<ManagementClientCredentialsOverview> RevokeCredentialAsync(
        RevokeManagementClientCredentialCommand command,
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
        if (application is not OpenIddictEntityFrameworkCoreApplication entity)
        {
            throw new ManagementNotFoundException(
                "client_not_found",
                $"Client '{clientId}' was not found.");
        }

        clientId = entity.ClientId ?? clientId;

        try
        {
            await EnsureClientIsManuallyManagedAsync(application, cancellationToken);
            if (string.IsNullOrWhiteSpace(command.ExpectedCredentialVersion))
            {
                throw new ManagementValidationException(
                    "client_credential_version_required",
                    "Reload the credentials before revoking.",
                    "expectedCredentialVersion");
            }

            var credential = await database.OAuthClientCredentials
                .SingleOrDefaultAsync(candidate =>
                    candidate.Id == command.CredentialId
                    && candidate.ClientId == clientId,
                    cancellationToken);
            if (credential is null)
            {
                throw new ManagementNotFoundException(
                    "client_credential_not_found",
                    "The credential was not found.");
            }
            if (!string.Equals(
                    credential.ConcurrencyToken,
                    command.ExpectedCredentialVersion,
                    StringComparison.Ordinal))
            {
                throw new ManagementConflictException(
                    "client_credential_changed",
                    "The credential was changed by another operation. Reload the data.");
            }
            if (credential.RevokedAtUtc is not null)
            {
                throw new ManagementConflictException(
                    "client_credential_already_revoked",
                    "The credential has already been revoked.");
            }

            var revocationReason = ClientCredentialPolicy.ValidateRevocationReason(command.Reason);
            credential.RevokedAtUtc = DateTime.UtcNow;
            credential.RevocationReason = revocationReason;
            credential.ConcurrencyToken = ClientCredentialPolicy.NewConcurrencyToken();
            database.ManagementAuditEvents.Add(ManagementAuditEventFactory.Create(
                context,
                ManagementCapabilities.ClientsUpdate,
                resource,
                decision,
                "succeeded",
                "client_credential_revoked"));
            await database.SaveChangesAsync(cancellationToken);

            return await BuildCredentialsOverviewAsync(entity, cancellationToken);
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
        catch (ManagementNotFoundException exception)
        {
            await guard.TryWriteAuditAsync(
                context,
                ManagementCapabilities.ClientsUpdate,
                resource,
                decision,
                "not-found",
                exception.ReasonCode,
                cancellationToken);
            throw;
        }
        catch (DbUpdateConcurrencyException exception)
        {
            logger.LogWarning(
                exception,
                "OAuth client credential revocation lost a concurrency race. ClientId={ClientId} CredentialId={CredentialId}",
                clientId,
                command.CredentialId);
            throw new ManagementConflictException(
                "client_credential_changed",
                "The credential was changed by another operation. Reload the data.");
        }
    }

    public async Task<ManagementClientCredentialsOverview>
        RegisterTlsCertificateAsync(
            RegisterManagementClientTlsCertificateCommand command,
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
        if (application is not OpenIddictEntityFrameworkCoreApplication entity)
        {
            throw new ManagementNotFoundException(
                "client_not_found",
                $"Client '{clientId}' was not found.");
        }

        clientId = entity.ClientId ?? clientId;
        try
        {
            ClientCredentialPolicy.EnsureExpectedClientVersion(command.ExpectedClientVersion, entity);
            await EnsureClientIsManuallyManagedAsync(
                application,
                cancellationToken);
            var certificate = ClientTlsCertificateCredential.Create(
                command.CertificatePem,
                command.KeyId,
                command.AuthenticationMethod);

            await using var transaction = await database.Database
                .BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
            var descriptor = new OpenIddictApplicationDescriptor();
            await applications.PopulateAsync(
                descriptor,
                application,
                cancellationToken);
            descriptor.JsonWebKeySet =
                ClientTlsCertificateCredential.AddCertificate(
                    entity.JsonWebKeySet,
                    certificate);
            descriptor.ClientType = OpenIddictConstants.ClientTypes.Confidential;
            await applications.UpdateAsync(
                application,
                descriptor,
                cancellationToken);
            database.ManagementAuditEvents.Add(
                ManagementAuditEventFactory.Create(
                    context,
                    ManagementCapabilities.ClientsUpdate,
                    resource,
                    decision,
                    "succeeded",
                    "client_mtls_certificate_registered"));
            await database.SaveChangesAsync(cancellationToken);
            var overview = await BuildCredentialsOverviewAsync(
                entity,
                cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return overview;
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
    }

    public async Task<ManagementClientCredentialsOverview>
        RevokeTlsCertificateAsync(
            RevokeManagementClientTlsCertificateCommand command,
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
        if (application is not OpenIddictEntityFrameworkCoreApplication entity)
        {
            throw new ManagementNotFoundException(
                "client_not_found",
                $"Client '{clientId}' was not found.");
        }

        clientId = entity.ClientId ?? clientId;
        ClientCredentialPolicy.EnsureExpectedClientVersion(command.ExpectedClientVersion, entity);
        await EnsureClientIsManuallyManagedAsync(application, cancellationToken);
        if (string.IsNullOrWhiteSpace(command.KeyId))
        {
            throw new ManagementValidationException(
                "mtls_certificate_kid_required",
                "Provide the identifier of the certificate to revoke.",
                "keyId");
        }

        await using var transaction = await database.Database
            .BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(
            descriptor,
            application,
            cancellationToken);
        descriptor.JsonWebKeySet =
            ClientTlsCertificateCredential.RemoveCertificate(
                entity.JsonWebKeySet,
                command.KeyId);
        await applications.UpdateAsync(application, descriptor, cancellationToken);
        database.ManagementAuditEvents.Add(ManagementAuditEventFactory.Create(
            context,
            ManagementCapabilities.ClientsUpdate,
            resource,
            decision,
            "succeeded",
            "client_mtls_certificate_revoked"));
        await database.SaveChangesAsync(cancellationToken);
        var overview = await BuildCredentialsOverviewAsync(
            entity,
            cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return overview;
    }

    private async Task<ManagementClientCredentialsOverview>
        BuildCredentialsOverviewAsync(
            OpenIddictEntityFrameworkCoreApplication application,
            CancellationToken cancellationToken)
    {
        var clientId = application.ClientId
            ?? throw new InvalidOperationException(
                "The OpenIddict application has no client_id.");
        var now = DateTime.UtcNow;
        var additional = await database.OAuthClientCredentials
            .AsNoTracking()
            .Where(credential => credential.ClientId == clientId)
            .OrderByDescending(credential => credential.CreatedAtUtc)
            .ToArrayAsync(cancellationToken);

        var hasPrimary = !string.IsNullOrWhiteSpace(application.ClientSecret);
        var hasActiveAdditional = additional.Any(credential =>
            ClientCredentialPolicy.GetCredentialStatus(credential, now) == "active");
        var tlsCertificates = ClientTlsCertificateCredential.Read(
            application.JsonWebKeySet,
            new DateTimeOffset(now, TimeSpan.Zero));
        var mtlsRuntimeEnabled = configuration.GetValue<bool>(
            "Sufficit:Identity:Mtls:Enabled");
        var pkiAuthenticationEnabled = mtlsRuntimeEnabled
            && configuration
                .GetSection(
                    "Sufficit:Identity:Mtls:TrustedCertificateAuthorityPaths")
                .Get<string[]>() is { Length: > 0 };
        var methods = ClientCredentialPolicy.GetAuthenticationMethods(
            hasPrimary || hasActiveAdditional,
            application.JsonWebKeySet,
            tlsCertificates);

        var credentials = new List<ManagementClientCredentialSummary>(
            additional.Length + (hasPrimary ? 1 : 0));
        if (hasPrimary)
        {
            credentials.Add(new ManagementClientCredentialSummary(
                Id: null,
                Label: "Primary credential (compatibility)",
                Kind: OAuthClientCredentialKinds.SharedSecret,
                SecretHint: string.Empty,
                Status: "active",
                IsPrimary: true));
        }

        credentials.AddRange(additional.Select(credential =>
            new ManagementClientCredentialSummary(
                credential.Id,
                credential.Label,
                credential.Kind,
                credential.SecretHint,
                ClientCredentialPolicy.GetCredentialStatus(credential, now),
                IsPrimary: false,
                ClientCredentialPolicy.ToDateTimeOffset(credential.CreatedAtUtc),
                ClientCredentialPolicy.ToDateTimeOffset(credential.NotBeforeUtc),
                ClientCredentialPolicy.ToDateTimeOffset(credential.ExpiresAtUtc),
                ClientCredentialPolicy.ToDateTimeOffset(credential.RevokedAtUtc),
                credential.ConcurrencyToken)));

        return new ManagementClientCredentialsOverview(
            clientId,
            methods,
            credentials,
            ClientCredentialPolicy.MaximumActiveAdditionalSharedSecrets,
            ClientTlsCertificateCredential
                .ExtractPrivateKeyJwtKeys(application.JsonWebKeySet)?.ToString(),
            tlsCertificates,
            mtlsRuntimeEnabled,
            pkiAuthenticationEnabled,
            ClientTlsCertificateCredential.MaximumCertificates,
            application.ConcurrencyToken);
    }

    private async Task EnsureClientIsManuallyManagedAsync(
        object application,
        CancellationToken cancellationToken)
    {
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
                "This client is managed by a declarative manifest. Change its credentials in the manifest and apply provisioning.");
        }
    }
}
